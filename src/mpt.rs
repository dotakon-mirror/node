use crate::dotakon;
use crate::proto;
use anyhow::{Context, Result, anyhow};
use primitive_types::H256;
use sha3::{self, Digest};
use std::collections::BTreeMap;
use std::sync::Mutex;

const KEY_CHARACTERS: [char; 16] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
];

pub trait Sha3Hash {
    fn sha3_hash(&self) -> H256;
}

pub trait Proto: Sized {
    fn encode(&self) -> Result<prost_types::Any>;
    fn decode(proto: &prost_types::Any) -> Result<Self>;
}

fn hash_flat_node(children: &BTreeMap<String, H256>) -> H256 {
    const DOMAIN_SEPARATOR: &str = "dotakon/merkle-proof-v1";
    let encoded_children: Vec<String> = children
        .iter()
        .map(|(label, hash)| format!("[\"{}\",{:#x}]", label, hash))
        .collect();
    let message = format!(
        "{{domain=\"{}\",children=[{}]}}",
        DOMAIN_SEPARATOR,
        encoded_children.join(",")
    );
    let mut hasher = sha3::Sha3_256::new();
    hasher.update(message.as_bytes());
    H256::from_slice(hasher.finalize().as_slice())
}

fn encode_nibble(nibble: u8) -> char {
    KEY_CHARACTERS[(nibble & 0x0F) as usize]
}

fn encode_key<const KL: usize>(key: &[u8; KL]) -> String {
    let mut encoded = String::new();
    encoded.reserve(KL * 2);
    for byte in key {
        encoded.push(encode_nibble(*byte >> 4));
        encoded.push(encode_nibble(*byte & 0x0F));
    }
    encoded
}

fn decode_nibble(nibble: char) -> u8 {
    KEY_CHARACTERS.binary_search(&nibble).unwrap() as u8
}

fn decode_key<const KL: usize>(key: &str) -> [u8; KL] {
    let key = key.as_bytes();
    let mut decoded = [0u8; KL];
    for i in 0..KL {
        decoded[i] += decode_nibble(key[i * 2 + 0] as char) << 4;
        decoded[i] += decode_nibble(key[i * 2 + 1] as char) & 0x0F;
    }
    decoded
}

fn common_prefix<'a>(key1: &'a str, key2: &str) -> &'a str {
    for ((i, ch1), ch2) in key1.char_indices().zip(key2.chars()) {
        if ch1 != ch2 {
            return &key1[0..i];
        }
    }
    key1
}

/// This is a special kind of trie we use to store values in Dotakon's storage. It has the following
/// properties:
///
///   * it's a compressed trie, aka a radix trie;
///   * the key alphabet is lowercase hex characters ([0-9a-f]*), so each node has at most 16
///     children;
///   * all keys have the same length (e.g. 40 hexadecimal characters for account balances), so all
///     terminal nodes are also leaf nodes.
///
/// Each leaf node stores the full history of the corresponding value, indexed by version number (we
/// use block numbers as version numbers). If a version number is missing it means the value didn't
/// change at that version, so it's the same as the previous version.
#[derive(Debug, Clone)]
struct ValueTrie<V> {
    values: BTreeMap<u64, V>,
    children: BTreeMap<String, ValueTrie<V>>,
}

impl<V> ValueTrie<V> {
    fn with_children(children: BTreeMap<String, Self>) -> Self {
        Self {
            values: BTreeMap::new(),
            children,
        }
    }

    /// Looks up a value at the specified version.
    fn get(&self, key: &str, version: u64) -> Option<&V> {
        if key.is_empty() {
            if let Some((_, value)) = self.values.range(..=version).next_back() {
                return Some(value);
            }
        } else if let Some((label, child)) = self.children.range(..=key.to_string()).next_back() {
            if key.len() >= label.len() && key.starts_with(label) {
                return child.get(&key[label.len()..], version);
            }
        }
        None
    }

    /// Inserts or updates a value at the specified version.
    fn put(&mut self, key: &str, value: V, version: u64) {
        if key.is_empty() {
            self.values.insert(version, value);
            return;
        }
        if let Some((label, child)) = self.children.range_mut(..=key.to_string()).next_back() {
            let prefix = common_prefix(key, label);
            if !prefix.is_empty() {
                if prefix.len() < label.len() {
                    let label = label.clone();
                    let child = self.children.remove(label.as_str()).unwrap();
                    let mut child = Self::with_children(BTreeMap::from([(
                        label[prefix.len()..].to_string(),
                        child,
                    )]));
                    child.put(&key[prefix.len()..], value, version);
                    self.children.insert(prefix.to_string(), child);
                } else {
                    child.put(&key[prefix.len()..], value, version);
                }
                return;
            }
        }
        self.children.insert(
            key.to_string(),
            Self {
                values: BTreeMap::from([(version, value)]),
                children: BTreeMap::new(),
            },
        );
    }
}

impl<V> Default for ValueTrie<V> {
    fn default() -> Self {
        Self {
            values: BTreeMap::new(),
            children: BTreeMap::new(),
        }
    }
}

/// A trie we use to store the Merkle hashes of our storage for a given block. We use a separate
/// trie for each block. These hashes are used to construct Merkle proofs for all storage lookups.
#[derive(Debug, Clone)]
struct HashTrie {
    children: BTreeMap<String, HashTrie>,
    hash: H256,
}

impl HashTrie {
    fn hash_node(children: &BTreeMap<String, Self>) -> H256 {
        hash_flat_node(
            &children
                .iter()
                .map(|(label, child)| (label.clone(), child.hash))
                .collect(),
        )
    }

    fn with_children(children: BTreeMap<String, Self>) -> Self {
        let hash = Self::hash_node(&children);
        Self { children, hash }
    }

    fn hash(&self) -> H256 {
        self.hash
    }

    fn lookup(&self, key: &str) -> Vec<BTreeMap<String, H256>> {
        let child_hashes: BTreeMap<String, H256> = self
            .children
            .iter()
            .map(|(label, child)| (label.clone(), child.hash))
            .collect();
        if key.is_empty() {
            vec![]
        } else if let Some((label, child)) = self.children.range(..=key.to_string()).next_back() {
            if key.len() >= label.len() && key.starts_with(label) {
                let suffix = &key[label.len()..];
                let mut path = child.lookup(suffix);
                path.push(child_hashes);
                path
            } else {
                vec![child_hashes]
            }
        } else {
            vec![child_hashes]
        }
    }

    fn put(&mut self, key: &str, hash: H256) -> Result<()> {
        if key.is_empty() {
            if !self.children.is_empty() {
                return Err(anyhow!("invalid MPT insertion for key \"{}\"", key));
            }
            self.hash = hash;
            return Ok(());
        }
        if let Some((label, child)) = self.children.range_mut(..=key.to_string()).next_back() {
            let prefix = common_prefix(key, label);
            if !prefix.is_empty() {
                if prefix.len() < label.len() {
                    let label = label.clone();
                    let child = self.children.remove(label.as_str()).unwrap();
                    let mut child = Self::with_children(BTreeMap::<String, Self>::from([(
                        label[prefix.len()..].to_string(),
                        child,
                    )]));
                    child.put(&key[prefix.len()..], hash)?;
                    self.children.insert(prefix.to_string(), child);
                } else {
                    child.put(&key[prefix.len()..], hash)?;
                }
                self.hash = Self::hash_node(&self.children);
                return Ok(());
            }
        }
        self.children.insert(
            key.to_string(),
            Self {
                children: BTreeMap::new(),
                hash,
            },
        );
        self.hash = Self::hash_node(&self.children);
        Ok(())
    }
}

impl Default for HashTrie {
    fn default() -> Self {
        let children = BTreeMap::<String, HashTrie>::new();
        let hash = Self::hash_node(&children);
        Self { children, hash }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof<V: Sha3Hash, const KL: usize> {
    key: String,
    decoded_key: [u8; KL],
    value: Option<V>,
    path: Vec<BTreeMap<String, H256>>,
    root_hash: H256,
}

impl<V: Sha3Hash, const KL: usize> Proof<V, KL> {
    pub fn new(key: String, value: Option<V>, path: Vec<BTreeMap<String, H256>>) -> Result<Self> {
        if path.is_empty() {
            return Err(anyhow!("the path must not be empty"));
        }
        let root_hash = hash_flat_node(&path[path.len() - 1]);
        let decoded_key = decode_key(key.as_str());
        Ok(Self {
            key,
            decoded_key,
            value,
            path,
            root_hash,
        })
    }

    pub fn key(&self) -> &[u8; KL] {
        &self.decoded_key
    }

    pub fn value(&self) -> &Option<V> {
        &self.value
    }

    pub fn path(&self) -> &[BTreeMap<String, H256>] {
        self.path.as_slice()
    }

    pub fn root_hash(&self) -> H256 {
        self.root_hash
    }

    fn verify_step<'a>(node: &BTreeMap<String, H256>, key: &'a str, hash: H256) -> Result<&'a str> {
        if let Some((label, child_hash)) = node.range(..=key.to_string()).next_back() {
            if key.len() >= label.len() && key.starts_with(label) {
                if *child_hash != hash {
                    return Err(anyhow!("invalid path (hash mismatch)"));
                }
                return Ok(&key[label.len()..]);
            }
        }
        Err(anyhow!("invalid path"))
    }

    pub fn verify(&self, root_hash: H256) -> Result<()> {
        if root_hash != self.root_hash {
            return Err(anyhow!(
                "root hash mismatch: got {:#x}, want {:#x}",
                self.root_hash,
                root_hash
            ));
        }
        let hashes: Vec<H256> = self.path.iter().map(hash_flat_node).collect();
        let mut key = self.key.as_str();
        for i in (1..self.path.len()).rev() {
            key = Self::verify_step(&self.path[i], key, hashes[i - 1])?;
        }
        let leaf = &self.path[0];
        if let Some(value) = &self.value {
            let leaf_hash = leaf.get(key).context("value not found")?;
            if *leaf_hash != value.sha3_hash() {
                return Err(anyhow!("leaf hash mismatch"));
            }
        } else if leaf.get(key).is_some() {
            return Err(anyhow!("element unexpectedly found"));
        }
        Ok(())
    }
}

impl<V: Sha3Hash + Proto, const KL: usize> Proof<V, KL> {
    /// Encodes this proof into a `MerkleProof` protobuf. Note that the block descriptor must be
    /// provided by the caller.
    pub fn encode(
        &self,
        block_descriptor: dotakon::BlockDescriptor,
    ) -> Result<dotakon::MerkleProof> {
        Ok(dotakon::MerkleProof {
            block_descriptor: Some(block_descriptor),
            key: Some(self.key.clone()),
            value: match &self.value {
                Some(value) => Some(value.encode()?),
                None => None,
            },
            node: self
                .path
                .iter()
                .map(|children| dotakon::merkle_proof::Node {
                    children: children
                        .iter()
                        .map(|(label, hash)| (label.clone(), proto::h256_to_bytes32(*hash)))
                        .collect(),
                    hash: Some(proto::h256_to_bytes32(hash_flat_node(children))),
                })
                .collect(),
        })
    }

    /// Decodes a Merkle proof from the provided protobuf. The `block_descriptor` is ignored. The
    /// resulting proof is not verified (use `decode_and_verify` to decode and verify it).
    pub fn decode(proto: &dotakon::MerkleProof) -> Result<Self> {
        if proto.key.is_none() {
            return Err(anyhow!("invalid Merkle proof: the key is missing"));
        }
        let key = proto.key.as_ref().unwrap().clone();
        let value = match &proto.value {
            Some(value) => Some(V::decode(value)?),
            None => None,
        };
        let path = proto
            .node
            .iter()
            .map(|node| {
                let children = node
                    .children
                    .iter()
                    .map(|(label, hash)| (label.clone(), proto::h256_from_bytes32(hash)))
                    .collect::<BTreeMap<String, H256>>();
                if node.hash.is_none() {
                    return Err(anyhow!("invalid Merkle proof: missing node hash"));
                }
                let hash = proto::h256_from_bytes32(&node.hash.unwrap());
                if hash != hash_flat_node(&children) {
                    return Err(anyhow!("invalid Merkle proof: hash mismatch"));
                }
                Ok(children)
            })
            .collect::<Result<Vec<BTreeMap<String, H256>>>>()?;
        Self::new(key, value, path)
    }

    /// Like `decode` but also validates the decoded proof against the provided root hash.
    ///
    /// Note that the root hash should be the same as one of the root hashes specified in the block
    /// descriptor, depending on what storage component this proof is relative to. For example, if
    /// the proof was generated from an account balance lookup the root hash must be the same as the
    /// one encoded in `block_descriptor.account_balances_root_hash`.
    pub fn decode_and_verify(proto: &dotakon::MerkleProof, root_hash: H256) -> Result<Self> {
        let proof = Self::decode(proto)?;
        proof.verify(root_hash)?;
        Ok(proof)
    }
}

#[derive(Debug, Clone)]
struct MptState<V: Clone + Sha3Hash, const KL: usize> {
    values: ValueTrie<V>,
    hashes: BTreeMap<u64, HashTrie>,
}

impl<V: Clone + Sha3Hash, const KL: usize> MptState<V, KL> {
    fn new() -> Self {
        Self::default()
    }

    fn latest_version(&self) -> u64 {
        let (version, _) = self.hashes.iter().next_back().unwrap();
        *version
    }

    fn root_hash(&self, version: u64) -> H256 {
        if let Some((_, hashes)) = self.hashes.range(..=version).next_back() {
            hashes.hash()
        } else {
            panic!("invalid MPT state (version 0 missing)");
        }
    }

    fn get(&self, key: &str, version: u64) -> Option<&V> {
        self.values.get(key, version)
    }

    fn get_proof(&self, key: &str, version: u64) -> Result<Proof<V, KL>> {
        let maybe_value = self.values.get(key, version).cloned();
        if let Some((_, hashes)) = self.hashes.range(..=version).next_back() {
            let path = hashes.lookup(key);
            Proof::<V, KL>::new(key.to_string(), maybe_value, path)
        } else {
            Err(anyhow!("invalid MPT state (version 0 missing)"))
        }
    }

    fn put(&mut self, key: &str, value: V, version: u64) -> Result<()> {
        let latest_version = self.latest_version();
        if version < latest_version {
            return Err(anyhow!(
                "cannot modify past version {} (latest is {})",
                version,
                latest_version
            ));
        }
        let hash = value.sha3_hash();
        if let Some(hashes) = self.hashes.get_mut(&version) {
            hashes.put(key, hash)?;
        } else {
            let (_, hashes) = self.hashes.iter().next_back().unwrap();
            let mut hashes = hashes.clone();
            hashes.put(key, hash)?;
            self.hashes.insert(version, hashes);
        }
        self.values.put(key, value, version);
        Ok(())
    }
}

impl<V: Clone + Sha3Hash, const KL: usize> Default for MptState<V, KL> {
    fn default() -> Self {
        Self {
            values: ValueTrie::<V>::default(),
            hashes: BTreeMap::from([(0, HashTrie::default())]),
        }
    }
}

#[derive(Debug)]
pub struct MPT<V: Clone + Sha3Hash, const KL: usize> {
    state: Mutex<MptState<V, KL>>,
}

impl<V: Clone + Sha3Hash, const KL: usize> MPT<V, KL> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn latest_version(&self) -> u64 {
        self.state.lock().unwrap().latest_version()
    }

    pub fn root_hash(&self, version: u64) -> H256 {
        self.state.lock().unwrap().root_hash(version)
    }

    pub fn get(&self, key: &[u8; KL], version: u64) -> Option<V> {
        let key = encode_key(key);
        self.state
            .lock()
            .unwrap()
            .get(key.as_str(), version)
            .cloned()
    }

    pub fn get_proof(&self, key: &[u8; KL], version: u64) -> Result<Proof<V, KL>> {
        let key = encode_key(key);
        let (proof, root_hash) = {
            let state = self.state.lock().unwrap();
            (
                state.get_proof(key.as_str(), version)?,
                state.root_hash(version),
            )
        };
        proof.verify(root_hash)?;
        Ok(proof)
    }

    pub fn put(&self, key: &[u8; KL], value: V, version: u64) -> Result<()> {
        let key = encode_key(key);
        self.state.lock().unwrap().put(key.as_str(), value, version)
    }
}

impl<V: Clone + Sha3Hash, const KL: usize> Default for MPT<V, KL> {
    fn default() -> Self {
        Self {
            state: Mutex::new(MptState::<V, KL>::default()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto;
    use primitive_types::U256;

    const TEST_KEY_LENGTH: usize = 32;

    #[derive(Debug, Default, Clone, PartialEq, Eq, PartialOrd, Ord)]
    struct TestValue {
        pub inner: U256,
    }

    impl Sha3Hash for TestValue {
        fn sha3_hash(&self) -> H256 {
            let mut hasher = sha3::Sha3_256::new();
            hasher.update(self.inner.to_little_endian());
            H256::from_slice(hasher.finalize().as_slice())
        }
    }

    impl Proto for TestValue {
        fn encode(&self) -> Result<prost_types::Any> {
            Ok(prost_types::Any::from_msg(&proto::u256_to_bytes32(
                self.inner,
            ))?)
        }

        fn decode(proto: &prost_types::Any) -> Result<Self> {
            Ok(Self {
                inner: proto::u256_from_bytes32(&proto.to_msg()?),
            })
        }
    }

    fn test_value1() -> TestValue {
        TestValue {
            inner: U256::from_little_endian(&[
                1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
            ]),
        }
    }

    fn test_value2() -> TestValue {
        TestValue {
            inner: U256::from_little_endian(&[
                32u8, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13,
                12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1,
            ]),
        }
    }

    fn test_value3() -> TestValue {
        TestValue {
            inner: U256::from_little_endian(&[
                32u8, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 17, 18, 19, 20,
                21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
            ]),
        }
    }

    fn make_test_key(value: U256) -> [u8; TEST_KEY_LENGTH] {
        let mut bytes = [0u8; TEST_KEY_LENGTH];
        bytes.copy_from_slice(&value.to_big_endian());
        bytes
    }

    fn test_key1() -> [u8; TEST_KEY_LENGTH] {
        make_test_key(test_value1().inner)
    }

    fn test_key2() -> [u8; TEST_KEY_LENGTH] {
        make_test_key(test_value2().inner)
    }

    fn test_key3() -> [u8; TEST_KEY_LENGTH] {
        make_test_key(test_value3().inner)
    }

    #[test]
    fn test_initial_root_hash() {
        let mpt = MPT::<TestValue, TEST_KEY_LENGTH>::new();
        let hash: H256 = "0xb4a3716bd9261f312ea71656dda4caa0d694f0f6816712036ee8fce833e4b46f"
            .parse()
            .unwrap();
        assert_eq!(mpt.root_hash(0), hash);
        assert_eq!(mpt.root_hash(1), hash);
        assert_eq!(mpt.root_hash(2), hash);
    }

    fn test_initial_state(key: &[u8; TEST_KEY_LENGTH], version: u64) {
        let mpt = MPT::<TestValue, TEST_KEY_LENGTH>::new();
        assert!(mpt.get(key, version).is_none());
        let proof = mpt.get_proof(key, version).unwrap();
        assert_eq!(*proof.key(), *key);
        assert!(proof.value().is_none());
        assert_eq!(proof.root_hash(), mpt.root_hash(version));
        assert!(proof.verify(mpt.root_hash(version)).is_ok());
    }

    #[test]
    fn test_initial_state1() {
        let key = test_key1();
        test_initial_state(&key, 0);
        test_initial_state(&key, 1);
        test_initial_state(&key, 2);
    }

    #[test]
    fn test_initial_state2() {
        let key = test_key2();
        test_initial_state(&key, 0);
        test_initial_state(&key, 1);
        test_initial_state(&key, 2);
    }

    #[test]
    fn test_insert_one() {
        let mpt = MPT::<TestValue, TEST_KEY_LENGTH>::new();
        let key1 = test_key1();
        let key2 = test_key2();
        let value = test_value2();
        assert!(mpt.put(&key1, value.clone(), 0).is_ok());
        assert_eq!(mpt.get(&key1, 0).unwrap(), value);
        assert_eq!(mpt.get(&key1, 1).unwrap(), value);
        assert_eq!(mpt.get(&key1, 2).unwrap(), value);
        let proof1 = mpt.get_proof(&key1, 0).unwrap();
        assert_eq!(*proof1.key(), key1);
        assert_eq!(*proof1.value(), Some(value));
        assert_eq!(proof1.root_hash(), mpt.root_hash(0));
        assert_eq!(proof1.root_hash(), mpt.root_hash(1));
        assert_eq!(proof1.root_hash(), mpt.root_hash(2));
        assert!(proof1.verify(mpt.root_hash(0)).is_ok());
        assert_eq!(mpt.get_proof(&key1, 1).unwrap(), proof1);
        assert_eq!(mpt.get_proof(&key1, 2).unwrap(), proof1);
        assert!(mpt.get(&key2, 0).is_none());
        assert!(mpt.get(&key2, 1).is_none());
        assert!(mpt.get(&key2, 2).is_none());
        let proof2 = mpt.get_proof(&key2, 0).unwrap();
        assert_eq!(*proof2.key(), key2);
        assert!(proof2.value().is_none());
        assert_eq!(proof2.root_hash(), mpt.root_hash(0));
        assert_eq!(proof2.root_hash(), mpt.root_hash(1));
        assert_eq!(proof2.root_hash(), mpt.root_hash(2));
        assert!(proof2.verify(mpt.root_hash(0)).is_ok());
        assert_eq!(mpt.get_proof(&key2, 1).unwrap(), proof2);
        assert_eq!(mpt.get_proof(&key2, 2).unwrap(), proof2);
    }

    #[test]
    fn test_first_root_hash_change() {
        let mpt = MPT::<TestValue, TEST_KEY_LENGTH>::new();
        let key1 = test_key1();
        let value = test_value2();
        let hash1 = mpt.root_hash(0);
        assert!(mpt.put(&key1, value.clone(), 0).is_ok());
        let hash2 = mpt.root_hash(0);
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_insert_two() {
        let mpt = MPT::<TestValue, TEST_KEY_LENGTH>::new();
        let key1 = test_key1();
        let key2 = test_key2();
        let value1 = test_value2();
        let value2 = test_value1();
        assert!(mpt.put(&key1, value1.clone(), 0).is_ok());
        assert!(mpt.put(&key2, value2.clone(), 0).is_ok());
        assert_eq!(mpt.get(&key1, 0).unwrap(), value1);
        assert_eq!(mpt.get(&key1, 1).unwrap(), value1);
        assert_eq!(mpt.get(&key1, 2).unwrap(), value1);
        let proof1 = mpt.get_proof(&key1, 0).unwrap();
        assert_eq!(*proof1.key(), key1);
        assert_eq!(*proof1.value(), Some(value1));
        assert_eq!(proof1.root_hash(), mpt.root_hash(0));
        assert_eq!(proof1.root_hash(), mpt.root_hash(1));
        assert_eq!(proof1.root_hash(), mpt.root_hash(2));
        assert!(proof1.verify(mpt.root_hash(0)).is_ok());
        assert_eq!(mpt.get_proof(&key1, 1).unwrap(), proof1);
        assert_eq!(mpt.get_proof(&key1, 2).unwrap(), proof1);
        assert_eq!(mpt.get(&key2, 0).unwrap(), value2);
        assert_eq!(mpt.get(&key2, 1).unwrap(), value2);
        assert_eq!(mpt.get(&key2, 2).unwrap(), value2);
        let proof2 = mpt.get_proof(&key2, 0).unwrap();
        assert_eq!(*proof2.key(), key2);
        assert_eq!(*proof2.value(), Some(value2));
        assert_eq!(proof2.root_hash(), mpt.root_hash(0));
        assert_eq!(proof2.root_hash(), mpt.root_hash(1));
        assert_eq!(proof2.root_hash(), mpt.root_hash(2));
        assert!(proof2.verify(mpt.root_hash(0)).is_ok());
        assert_eq!(mpt.get_proof(&key2, 1).unwrap(), proof2);
        assert_eq!(mpt.get_proof(&key2, 2).unwrap(), proof2);
    }

    #[test]
    fn test_second_root_hash_change() {
        let mpt = MPT::<TestValue, TEST_KEY_LENGTH>::new();
        let key1 = test_key1();
        let key2 = test_key2();
        let value1 = test_value2();
        let value2 = test_value1();
        assert!(mpt.put(&key1, value1, 0).is_ok());
        let hash1 = mpt.root_hash(0);
        assert!(mpt.put(&key2, value2, 0).is_ok());
        let hash2 = mpt.root_hash(0);
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_insert_with_shared_prefix() {
        let mpt = MPT::<TestValue, TEST_KEY_LENGTH>::new();
        let key1 = test_key1();
        let key2 = test_key3();
        let value1 = test_value2();
        let value2 = test_value1();
        assert!(mpt.put(&key1, value1.clone(), 0).is_ok());
        assert!(mpt.put(&key2, value2.clone(), 0).is_ok());
        assert_eq!(mpt.get(&key1, 0).unwrap(), value1);
        assert_eq!(mpt.get(&key1, 1).unwrap(), value1);
        assert_eq!(mpt.get(&key1, 2).unwrap(), value1);
        let proof1 = mpt.get_proof(&key1, 0).unwrap();
        assert_eq!(*proof1.key(), key1);
        assert_eq!(*proof1.value(), Some(value1));
        assert_eq!(proof1.root_hash(), mpt.root_hash(0));
        assert_eq!(proof1.root_hash(), mpt.root_hash(1));
        assert_eq!(proof1.root_hash(), mpt.root_hash(2));
        assert!(proof1.verify(mpt.root_hash(0)).is_ok());
        assert_eq!(mpt.get_proof(&key1, 1).unwrap(), proof1);
        assert_eq!(mpt.get_proof(&key1, 2).unwrap(), proof1);
        assert_eq!(mpt.get(&key2, 0).unwrap(), value2);
        assert_eq!(mpt.get(&key2, 1).unwrap(), value2);
        assert_eq!(mpt.get(&key2, 2).unwrap(), value2);
        let proof2 = mpt.get_proof(&key2, 0).unwrap();
        assert_eq!(*proof2.key(), key2);
        assert_eq!(*proof2.value(), Some(value2));
        assert_eq!(proof2.root_hash(), mpt.root_hash(0));
        assert_eq!(proof2.root_hash(), mpt.root_hash(1));
        assert_eq!(proof2.root_hash(), mpt.root_hash(2));
        assert!(proof2.verify(mpt.root_hash(0)).is_ok());
        assert_eq!(mpt.get_proof(&key2, 1).unwrap(), proof2);
        assert_eq!(mpt.get_proof(&key2, 2).unwrap(), proof2);
    }

    fn test_insert_three(value1: TestValue, value2: TestValue, value3: TestValue) {
        let mpt = MPT::<TestValue, TEST_KEY_LENGTH>::new();
        let key1 = make_test_key(value1.inner);
        let key2 = make_test_key(value2.inner);
        let key3 = make_test_key(value3.inner);
        assert!(mpt.put(&key1, value1.clone(), 0).is_ok());
        assert!(mpt.put(&key2, value2.clone(), 0).is_ok());
        assert!(mpt.put(&key3, value3.clone(), 0).is_ok());
        assert_eq!(mpt.get(&key1, 0).unwrap(), value1);
        assert_eq!(mpt.get(&key1, 1).unwrap(), value1);
        assert_eq!(mpt.get(&key1, 2).unwrap(), value1);
        let proof1 = mpt.get_proof(&key1, 0).unwrap();
        assert_eq!(*proof1.key(), key1);
        assert_eq!(*proof1.value(), Some(value1));
        assert_eq!(proof1.root_hash(), mpt.root_hash(0));
        assert_eq!(proof1.root_hash(), mpt.root_hash(1));
        assert_eq!(proof1.root_hash(), mpt.root_hash(2));
        assert!(proof1.verify(mpt.root_hash(0)).is_ok());
        assert_eq!(mpt.get_proof(&key1, 1).unwrap(), proof1);
        assert_eq!(mpt.get_proof(&key1, 2).unwrap(), proof1);
        assert_eq!(mpt.get(&key2, 0).unwrap(), value2);
        assert_eq!(mpt.get(&key2, 1).unwrap(), value2);
        assert_eq!(mpt.get(&key2, 2).unwrap(), value2);
        let proof2 = mpt.get_proof(&key2, 0).unwrap();
        assert_eq!(*proof2.key(), key2);
        assert_eq!(*proof2.value(), Some(value2));
        assert_eq!(proof2.root_hash(), mpt.root_hash(0));
        assert_eq!(proof2.root_hash(), mpt.root_hash(1));
        assert_eq!(proof2.root_hash(), mpt.root_hash(2));
        assert!(proof2.verify(mpt.root_hash(0)).is_ok());
        assert_eq!(mpt.get_proof(&key2, 1).unwrap(), proof2);
        assert_eq!(mpt.get_proof(&key2, 2).unwrap(), proof2);
        assert_eq!(mpt.get(&key3, 0).unwrap(), value3);
        assert_eq!(mpt.get(&key3, 1).unwrap(), value3);
        assert_eq!(mpt.get(&key3, 2).unwrap(), value3);
        let proof3 = mpt.get_proof(&key3, 0).unwrap();
        assert_eq!(*proof3.key(), key3);
        assert_eq!(*proof3.value(), Some(value3));
        assert_eq!(proof3.root_hash(), mpt.root_hash(0));
        assert_eq!(proof3.root_hash(), mpt.root_hash(1));
        assert_eq!(proof3.root_hash(), mpt.root_hash(2));
        assert!(proof3.verify(mpt.root_hash(0)).is_ok());
        assert_eq!(mpt.get_proof(&key3, 1).unwrap(), proof3);
        assert_eq!(mpt.get_proof(&key3, 2).unwrap(), proof3);
    }

    #[test]
    fn test_insert_three1() {
        test_insert_three(test_value1(), test_value2(), test_value3());
    }

    #[test]
    fn test_insert_three2() {
        test_insert_three(test_value1(), test_value3(), test_value2());
    }

    #[test]
    fn test_insert_three3() {
        test_insert_three(test_value2(), test_value1(), test_value3());
    }

    #[test]
    fn test_insert_three4() {
        test_insert_three(test_value2(), test_value3(), test_value1());
    }

    #[test]
    fn test_insert_three5() {
        test_insert_three(test_value3(), test_value1(), test_value2());
    }

    #[test]
    fn test_insert_three6() {
        test_insert_three(test_value3(), test_value2(), test_value1());
    }

    #[test]
    fn test_update() {
        let mpt = MPT::<TestValue, TEST_KEY_LENGTH>::new();
        let key1 = test_key1();
        let key2 = test_key2();
        let value1 = test_value2();
        let value2 = test_value1();
        assert!(mpt.put(&key1, value1, 0).is_ok());
        assert!(mpt.put(&key1, value2.clone(), 0).is_ok());
        assert_eq!(mpt.get(&key1, 0).unwrap(), value2);
        assert_eq!(mpt.get(&key1, 1).unwrap(), value2);
        assert_eq!(mpt.get(&key1, 2).unwrap(), value2);
        let proof1 = mpt.get_proof(&key1, 0).unwrap();
        assert_eq!(*proof1.key(), key1);
        assert_eq!(*proof1.value(), Some(value2));
        assert_eq!(proof1.root_hash(), mpt.root_hash(0));
        assert_eq!(proof1.root_hash(), mpt.root_hash(1));
        assert_eq!(proof1.root_hash(), mpt.root_hash(2));
        assert!(proof1.verify(mpt.root_hash(0)).is_ok());
        assert_eq!(mpt.get_proof(&key1, 1).unwrap(), proof1);
        assert_eq!(mpt.get_proof(&key1, 2).unwrap(), proof1);
        assert!(mpt.get(&key2, 0).is_none());
        assert!(mpt.get(&key2, 1).is_none());
        assert!(mpt.get(&key2, 2).is_none());
        let proof2 = mpt.get_proof(&key2, 0).unwrap();
        assert_eq!(*proof2.key(), key2);
        assert!(proof2.value().is_none());
        assert_eq!(proof2.root_hash(), mpt.root_hash(0));
        assert_eq!(proof2.root_hash(), mpt.root_hash(1));
        assert_eq!(proof2.root_hash(), mpt.root_hash(2));
        assert!(proof2.verify(mpt.root_hash(0)).is_ok());
        assert_eq!(mpt.get_proof(&key2, 1).unwrap(), proof2);
        assert_eq!(mpt.get_proof(&key2, 2).unwrap(), proof2);
    }

    #[test]
    fn test_new_version() {
        let mpt = MPT::<TestValue, TEST_KEY_LENGTH>::new();
        let key1 = test_key1();
        let key2 = test_key2();
        let value1 = test_value2();
        let value2 = test_value1();
        assert!(mpt.put(&key1, value1.clone(), 0).is_ok());
        assert!(mpt.put(&key1, value2.clone(), 1).is_ok());
        assert_eq!(mpt.get(&key1, 0).unwrap(), value1);
        assert_eq!(mpt.get(&key1, 1).unwrap(), value2);
        assert_eq!(mpt.get(&key1, 2).unwrap(), value2);
        let proof11 = mpt.get_proof(&key1, 0).unwrap();
        assert_eq!(*proof11.key(), key1);
        assert_eq!(*proof11.value(), Some(value1));
        assert_eq!(proof11.root_hash(), mpt.root_hash(0));
        assert_ne!(proof11.root_hash(), mpt.root_hash(1));
        assert_ne!(proof11.root_hash(), mpt.root_hash(2));
        assert!(proof11.verify(mpt.root_hash(0)).is_ok());
        assert!(proof11.verify(mpt.root_hash(1)).is_err());
        let proof12 = mpt.get_proof(&key1, 1).unwrap();
        assert_eq!(*proof12.key(), key1);
        assert_eq!(*proof12.value(), Some(value2));
        assert_ne!(proof12.root_hash(), mpt.root_hash(0));
        assert_eq!(proof12.root_hash(), mpt.root_hash(1));
        assert_eq!(proof12.root_hash(), mpt.root_hash(2));
        assert!(proof12.verify(mpt.root_hash(0)).is_err());
        assert!(proof12.verify(mpt.root_hash(1)).is_ok());
        assert_eq!(mpt.get_proof(&key1, 2).unwrap(), proof12);
        assert!(mpt.get(&key2, 0).is_none());
        assert!(mpt.get(&key2, 1).is_none());
        assert!(mpt.get(&key2, 2).is_none());
        let proof21 = mpt.get_proof(&key2, 0).unwrap();
        assert_eq!(*proof21.key(), key2);
        assert!(proof21.value().is_none());
        assert_eq!(proof21.root_hash(), mpt.root_hash(0));
        assert_ne!(proof21.root_hash(), mpt.root_hash(1));
        assert_ne!(proof21.root_hash(), mpt.root_hash(2));
        assert!(proof21.verify(mpt.root_hash(0)).is_ok());
        assert!(proof21.verify(mpt.root_hash(1)).is_err());
        let proof22 = mpt.get_proof(&key2, 1).unwrap();
        assert_eq!(*proof22.key(), key2);
        assert!(proof22.value().is_none());
        assert_ne!(proof22.root_hash(), mpt.root_hash(0));
        assert_eq!(proof22.root_hash(), mpt.root_hash(1));
        assert_eq!(proof22.root_hash(), mpt.root_hash(2));
        assert!(proof22.verify(mpt.root_hash(0)).is_err());
        assert!(proof22.verify(mpt.root_hash(1)).is_ok());
        assert_eq!(mpt.get_proof(&key2, 1).unwrap(), proof22);
        assert_eq!(mpt.get_proof(&key2, 2).unwrap(), proof22);
    }

    #[test]
    fn test_skip_version() {
        let mpt = MPT::<TestValue, TEST_KEY_LENGTH>::new();
        let key1 = test_key1();
        let key2 = test_key2();
        let value1 = test_value2();
        let value2 = test_value1();
        assert!(mpt.put(&key1, value1.clone(), 0).is_ok());
        assert!(mpt.put(&key1, value2.clone(), 2).is_ok());
        assert_eq!(mpt.get(&key1, 0).unwrap(), value1);
        assert_eq!(mpt.get(&key1, 1).unwrap(), value1);
        assert_eq!(mpt.get(&key1, 2).unwrap(), value2);
        let proof11 = mpt.get_proof(&key1, 0).unwrap();
        assert_eq!(*proof11.key(), key1);
        assert_eq!(*proof11.value(), Some(value1));
        assert_eq!(proof11.root_hash(), mpt.root_hash(0));
        assert_eq!(proof11.root_hash(), mpt.root_hash(1));
        assert_ne!(proof11.root_hash(), mpt.root_hash(2));
        assert!(proof11.verify(mpt.root_hash(0)).is_ok());
        assert!(proof11.verify(mpt.root_hash(1)).is_ok());
        assert!(proof11.verify(mpt.root_hash(2)).is_err());
        let proof12 = mpt.get_proof(&key1, 2).unwrap();
        assert_eq!(*proof12.key(), key1);
        assert_eq!(*proof12.value(), Some(value2));
        assert_ne!(proof12.root_hash(), mpt.root_hash(0));
        assert_ne!(proof12.root_hash(), mpt.root_hash(1));
        assert_eq!(proof12.root_hash(), mpt.root_hash(2));
        assert!(proof12.verify(mpt.root_hash(0)).is_err());
        assert!(proof12.verify(mpt.root_hash(1)).is_err());
        assert!(proof12.verify(mpt.root_hash(2)).is_ok());
        assert_eq!(mpt.get_proof(&key1, 1).unwrap(), proof11);
        assert!(mpt.get(&key2, 0).is_none());
        assert!(mpt.get(&key2, 1).is_none());
        assert!(mpt.get(&key2, 2).is_none());
        let proof21 = mpt.get_proof(&key2, 0).unwrap();
        assert_eq!(*proof21.key(), key2);
        assert!(proof21.value().is_none());
        assert_eq!(proof21.root_hash(), mpt.root_hash(0));
        assert_eq!(proof21.root_hash(), mpt.root_hash(1));
        assert_ne!(proof21.root_hash(), mpt.root_hash(2));
        assert!(proof21.verify(mpt.root_hash(0)).is_ok());
        assert!(proof21.verify(mpt.root_hash(1)).is_ok());
        assert!(proof21.verify(mpt.root_hash(2)).is_err());
        let proof22 = mpt.get_proof(&key2, 2).unwrap();
        assert_eq!(*proof22.key(), key2);
        assert!(proof22.value().is_none());
        assert_ne!(proof22.root_hash(), mpt.root_hash(0));
        assert_ne!(proof22.root_hash(), mpt.root_hash(1));
        assert_eq!(proof22.root_hash(), mpt.root_hash(2));
        assert!(proof22.verify(mpt.root_hash(0)).is_err());
        assert!(proof22.verify(mpt.root_hash(1)).is_err());
        assert!(proof22.verify(mpt.root_hash(2)).is_ok());
        assert_eq!(mpt.get_proof(&key2, 1).unwrap(), proof21);
    }

    #[test]
    fn test_two_values_across_versions() {
        let mpt = MPT::<TestValue, TEST_KEY_LENGTH>::new();
        let key1 = test_key1();
        let key2 = test_key2();
        let value1 = test_value2();
        let value2 = test_value3();
        let value3 = test_value1();
        assert!(mpt.put(&key1, value1.clone(), 0).is_ok());
        assert!(mpt.put(&key2, value2.clone(), 0).is_ok());
        assert!(mpt.put(&key2, value3.clone(), 2).is_ok());
        assert_eq!(mpt.get(&key1, 0).unwrap(), value1);
        assert_eq!(mpt.get(&key1, 1).unwrap(), value1);
        assert_eq!(mpt.get(&key1, 2).unwrap(), value1);
        let proof11 = mpt.get_proof(&key1, 0).unwrap();
        assert_eq!(*proof11.key(), key1);
        assert_eq!(*proof11.value(), Some(value1.clone()));
        assert_eq!(proof11.root_hash(), mpt.root_hash(0));
        assert_eq!(proof11.root_hash(), mpt.root_hash(1));
        assert_ne!(proof11.root_hash(), mpt.root_hash(2));
        assert!(proof11.verify(mpt.root_hash(0)).is_ok());
        assert!(proof11.verify(mpt.root_hash(1)).is_ok());
        assert!(proof11.verify(mpt.root_hash(2)).is_err());
        let proof12 = mpt.get_proof(&key1, 2).unwrap();
        assert_eq!(*proof12.key(), key1);
        assert_eq!(*proof12.value(), Some(value1));
        assert_ne!(proof12.root_hash(), mpt.root_hash(0));
        assert_ne!(proof12.root_hash(), mpt.root_hash(1));
        assert_eq!(proof12.root_hash(), mpt.root_hash(2));
        assert!(proof12.verify(mpt.root_hash(0)).is_err());
        assert!(proof12.verify(mpt.root_hash(1)).is_err());
        assert!(proof12.verify(mpt.root_hash(2)).is_ok());
        assert_eq!(mpt.get_proof(&key1, 1).unwrap(), proof11);
        assert_eq!(mpt.get(&key2, 0).unwrap(), value2);
        assert_eq!(mpt.get(&key2, 1).unwrap(), value2);
        assert_eq!(mpt.get(&key2, 2).unwrap(), value3);
        let proof21 = mpt.get_proof(&key2, 0).unwrap();
        assert_eq!(*proof21.key(), key2);
        assert_eq!(*proof21.value(), Some(value2));
        assert_eq!(proof21.root_hash(), mpt.root_hash(0));
        assert_eq!(proof21.root_hash(), mpt.root_hash(1));
        assert_ne!(proof21.root_hash(), mpt.root_hash(2));
        assert!(proof21.verify(mpt.root_hash(0)).is_ok());
        assert!(proof21.verify(mpt.root_hash(1)).is_ok());
        assert!(proof21.verify(mpt.root_hash(2)).is_err());
        let proof22 = mpt.get_proof(&key2, 2).unwrap();
        assert_eq!(*proof22.key(), key2);
        assert_eq!(*proof22.value(), Some(value3));
        assert_ne!(proof22.root_hash(), mpt.root_hash(0));
        assert_ne!(proof22.root_hash(), mpt.root_hash(1));
        assert_eq!(proof22.root_hash(), mpt.root_hash(2));
        assert!(proof22.verify(mpt.root_hash(0)).is_err());
        assert!(proof22.verify(mpt.root_hash(1)).is_err());
        assert!(proof22.verify(mpt.root_hash(2)).is_ok());
        assert_eq!(mpt.get_proof(&key2, 1).unwrap(), proof21);
    }

    #[test]
    fn test_transcode_proof() {
        let mpt = MPT::<TestValue, TEST_KEY_LENGTH>::new();
        let key1 = test_key1();
        let key2 = test_key2();
        let key3 = test_key3();
        let value1 = test_value2();
        let value2 = test_value3();
        let value3 = test_value1();
        assert!(mpt.put(&key1, value1.clone(), 0).is_ok());
        assert!(mpt.put(&key2, value2.clone(), 0).is_ok());
        assert!(mpt.put(&key3, value3.clone(), 0).is_ok());
        let proof = mpt.get_proof(&key2, 0).unwrap();
        let proto = proof
            .encode(dotakon::BlockDescriptor {
                block_hash: None,
                block_number: None,
                previous_block_hash: None,
                network_topology_root_hash: None,
                account_balances_root_hash: Some(proto::h256_to_bytes32(mpt.root_hash(0))),
                program_storage_root_hash: None,
            })
            .unwrap();
        assert_eq!(
            Proof::<TestValue, TEST_KEY_LENGTH>::decode(&proto).unwrap(),
            proof
        );
    }

    #[test]
    fn test_decode_and_verify_proof() {
        let mpt = MPT::<TestValue, TEST_KEY_LENGTH>::new();
        let key1 = test_key1();
        let key2 = test_key2();
        let key3 = test_key3();
        let value1 = test_value2();
        let value2 = test_value3();
        let value3 = test_value1();
        assert!(mpt.put(&key1, value1.clone(), 0).is_ok());
        assert!(mpt.put(&key2, value2.clone(), 0).is_ok());
        assert!(mpt.put(&key3, value3.clone(), 0).is_ok());
        let proof = mpt.get_proof(&key2, 0).unwrap();
        let proto = proof
            .encode(dotakon::BlockDescriptor {
                block_hash: None,
                block_number: None,
                previous_block_hash: None,
                network_topology_root_hash: None,
                account_balances_root_hash: Some(proto::h256_to_bytes32(mpt.root_hash(0))),
                program_storage_root_hash: None,
            })
            .unwrap();
        assert_eq!(
            Proof::<TestValue, TEST_KEY_LENGTH>::decode_and_verify(&proto, mpt.root_hash(0))
                .unwrap(),
            proof
        );
    }

    #[test]
    fn test_decode_sabotaged_proof() {
        let mpt = MPT::<TestValue, TEST_KEY_LENGTH>::new();
        let key1 = test_key1();
        let key2 = test_key2();
        let key3 = test_key3();
        let value1 = test_value2();
        let value2 = test_value3();
        let value3 = test_value1();
        assert!(mpt.put(&key1, value1.clone(), 0).is_ok());
        assert!(mpt.put(&key2, value2.clone(), 0).is_ok());
        assert!(mpt.put(&key3, value3.clone(), 0).is_ok());
        let proof = mpt.get_proof(&key2, 0).unwrap();
        let mut proto = proof
            .encode(dotakon::BlockDescriptor {
                block_hash: None,
                block_number: None,
                previous_block_hash: None,
                network_topology_root_hash: None,
                account_balances_root_hash: Some(proto::h256_to_bytes32(mpt.root_hash(0))),
                program_storage_root_hash: None,
            })
            .unwrap();
        proto.node[0].hash = Some(proto::h256_to_bytes32(H256::zero()));
        assert!(
            Proof::<TestValue, TEST_KEY_LENGTH>::decode_and_verify(&proto, mpt.root_hash(0))
                .is_err()
        );
    }

    #[test]
    fn test_decode_and_verify_sabotaged_proof() {
        let mpt = MPT::<TestValue, TEST_KEY_LENGTH>::new();
        let key1 = test_key1();
        let key2 = test_key2();
        let key3 = test_key3();
        let value1 = test_value2();
        let value2 = test_value3();
        let value3 = test_value1();
        assert!(mpt.put(&key1, value1.clone(), 0).is_ok());
        assert!(mpt.put(&key2, value2.clone(), 0).is_ok());
        assert!(mpt.put(&key3, value3.clone(), 0).is_ok());
        let proof = mpt.get_proof(&key2, 0).unwrap();
        let mut proto = proof
            .encode(dotakon::BlockDescriptor {
                block_hash: None,
                block_number: None,
                previous_block_hash: None,
                network_topology_root_hash: None,
                account_balances_root_hash: Some(proto::h256_to_bytes32(mpt.root_hash(0))),
                program_storage_root_hash: None,
            })
            .unwrap();
        proto.node[0].hash = Some(proto::h256_to_bytes32(H256::zero()));
        assert!(
            Proof::<TestValue, TEST_KEY_LENGTH>::decode_and_verify(&proto, mpt.root_hash(0))
                .is_err()
        );
    }

    #[test]
    fn test_decode_wrong_proof() {
        let mpt = MPT::<TestValue, TEST_KEY_LENGTH>::new();
        let key1 = test_key1();
        let key2 = test_key2();
        let key3 = test_key3();
        let value1 = test_value2();
        let value2 = test_value3();
        let value3 = test_value1();
        assert!(mpt.put(&key1, value1.clone(), 0).is_ok());
        assert!(mpt.put(&key2, value2.clone(), 0).is_ok());
        assert!(mpt.put(&key3, value3.clone(), 0).is_ok());
        let proof = mpt.get_proof(&key2, 0).unwrap();
        let mut proto = proof
            .encode(dotakon::BlockDescriptor {
                block_hash: None,
                block_number: None,
                previous_block_hash: None,
                network_topology_root_hash: None,
                account_balances_root_hash: Some(proto::h256_to_bytes32(mpt.root_hash(0))),
                program_storage_root_hash: None,
            })
            .unwrap();
        proto.value = None;
        assert!(Proof::<TestValue, TEST_KEY_LENGTH>::decode(&proto).is_ok());
    }

    #[test]
    fn test_decode_and_verify_wrong_proof() {
        let mpt = MPT::<TestValue, TEST_KEY_LENGTH>::new();
        let key1 = test_key1();
        let key2 = test_key2();
        let key3 = test_key3();
        let value1 = test_value2();
        let value2 = test_value3();
        let value3 = test_value1();
        assert!(mpt.put(&key1, value1.clone(), 0).is_ok());
        assert!(mpt.put(&key2, value2.clone(), 0).is_ok());
        assert!(mpt.put(&key3, value3.clone(), 0).is_ok());
        let proof = mpt.get_proof(&key2, 0).unwrap();
        let mut proto = proof
            .encode(dotakon::BlockDescriptor {
                block_hash: None,
                block_number: None,
                previous_block_hash: None,
                network_topology_root_hash: None,
                account_balances_root_hash: Some(proto::h256_to_bytes32(mpt.root_hash(0))),
                program_storage_root_hash: None,
            })
            .unwrap();
        proto.value = None;
        assert!(
            Proof::<TestValue, TEST_KEY_LENGTH>::decode_and_verify(&proto, mpt.root_hash(0))
                .is_err()
        );
    }

    #[test]
    fn test_past_modification() {
        let mpt = MPT::<TestValue, TEST_KEY_LENGTH>::new();
        let key1 = test_key1();
        let key2 = test_key2();
        let key3 = test_key3();
        let value1 = test_value2();
        let value2 = test_value3();
        let value3 = test_value1();
        assert!(mpt.put(&key1, value1.clone(), 0).is_ok());
        assert!(mpt.put(&key2, value2.clone(), 1).is_ok());
        assert!(mpt.put(&key1, value3.clone(), 0).is_err());
        assert!(mpt.put(&key3, value3.clone(), 0).is_err());
        assert_eq!(mpt.get(&key1, 2).unwrap(), value1);
        assert_eq!(mpt.get(&key2, 2).unwrap(), value2);
        assert!(mpt.get(&key3, 2).is_none());
    }
}
