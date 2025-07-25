use crate::dotakon;
use crate::proto;
use anyhow::{Context, Result, anyhow};
use ff::{Field, PrimeField};
use pasta_curves::pallas::Scalar;
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::sync::Arc;

use crate::utils;

/// ASCII codes of lower-case hex characters (0-9 and a-f).
const KEY_CHAR_CODES: [u8; 16] = [
    48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 97, 98, 99, 100, 101, 102,
];

/// Makes a type hashable with Poseidon-128.
pub trait PoseidonHash {
    fn poseidon_hash(&self) -> Scalar;
}

impl PoseidonHash for Scalar {
    fn poseidon_hash(&self) -> Scalar {
        utils::poseidon_hash([*self])
    }
}

fn key_char_code_by_nibble(nibble: u8) -> u8 {
    KEY_CHAR_CODES[nibble as usize]
}

fn key_char_by_nibble(nibble: u8) -> char {
    KEY_CHAR_CODES[nibble as usize] as char
}

fn key_nibble_by_char_code(code: u8) -> u8 {
    let mut i = 0u8;
    let mut j = 16u8;
    while i < j {
        let k = i + ((j - i) >> 1);
        if code < KEY_CHAR_CODES[k as usize] {
            j = k;
        } else if code > KEY_CHAR_CODES[k as usize] {
            i = k + 1;
        } else {
            return k;
        }
    }
    panic!("invalid MPT key character")
}

fn key_nibble_by_char(ch: char) -> u8 {
    key_nibble_by_char_code(ch as u8)
}

/// Hex string encoder that can be used by `KeyEncoder` implementations.
pub fn encode_key<const L: usize>(bytes: &[u8; L]) -> String {
    let mut key = String::default();
    for byte in bytes {
        key.push(key_char_by_nibble(byte >> 4));
        key.push(key_char_by_nibble(byte & 15));
    }
    key
}

/// Hex string decoder that can be used by `KeyEncoder` implementations.
pub fn decode_key<const L: usize>(key: &str) -> [u8; L] {
    let key = key.as_bytes();
    let mut bytes = [0u8; L];
    for i in 0..L {
        bytes[i] =
            key_nibble_by_char_code(key[i * 2]) * 16 + key_nibble_by_char_code(key[i * 2 + 1]);
    }
    bytes
}

/// Defines how an MPT key is encoded/decoded to/from hex strings.
pub trait KeyEncoder<K>: Debug + PartialEq + Eq + Send + Sync + 'static {
    /// Encodes the key to a sequence of lower-case hex characters.
    fn encode_key(key: K) -> String;

    /// Decodes the key from a sequence of lower-case hex characters.
    fn decode_key(key: &str) -> K;
}

/// Defines how an MPT key fragment is encoded to a list of scalars for Poseidon hashing.
///
/// `L` is the number of scalars needed to encode a node, which in turn is the number of scalars
/// needed to encode a full key (worst case of a key fragment) plus one to carry the Poseidon hash
/// of the node.
pub trait NodeEncoder<const L: usize>: Debug + PartialEq + Eq + Send + Sync + 'static {
    /// Encodes the node using the first `L-1` scalars for the `key` and the remaining one for the
    /// `hash`.
    fn encode_node(key: &str, hash: Scalar) -> [Scalar; L];
}

pub trait Encoder<K, const L: usize>: KeyEncoder<K> + NodeEncoder<L> {}

/// Hashes a "flat node", which is made up of a set of child hashes indexed by their key fragments.
/// The `children` data structure is obtained by taking the children of an actual node and replacing
/// them with their hashes. All hashing is done using Poseidon-128. The generic parameter `L` is the
/// number of scalars resulting from hashing each child (it depends on how many scalars we need to
/// encode a key fragment), while `L16` must be exactly `L * 16` (it needs to be provided separately
/// because the current version of Rust doesn't allow constant expressions in generic arguments).
fn hash_flat_node<E: NodeEncoder<L>, const L: usize, const L16: usize>(
    children: &BTreeMap<String, Scalar>,
) -> Scalar {
    let mut inputs = [Scalar::ZERO; L16];
    for (label, child) in children {
        let i = key_nibble_by_char_code(label.as_bytes()[0]) as usize;
        let scalars = E::encode_node(label.as_str(), child.poseidon_hash());
        for j in 0..L {
            inputs[i * L + j] = scalars[j];
        }
    }
    utils::poseidon_hash(inputs)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof<K: Copy, V: PoseidonHash, E: Encoder<K, L>, const L: usize, const L16: usize> {
    key: K,
    value: Option<V>,
    path: Vec<BTreeMap<String, Scalar>>,
    root_hash: Scalar,
    _encoder: PhantomData<E>,
}

impl<K: Copy, V: PoseidonHash, E: Encoder<K, L>, const L: usize, const L16: usize>
    Proof<K, V, E, L, L16>
{
    pub fn key(&self) -> &K {
        &self.key
    }

    pub fn value(&self) -> &Option<V> {
        &self.value
    }

    pub fn root_hash(&self) -> Scalar {
        self.root_hash
    }

    fn verify_step<'a>(
        node: &BTreeMap<String, Scalar>,
        key: &'a str,
        hash: Scalar,
    ) -> Result<&'a str> {
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

    pub fn verify(&self, root_hash: Scalar) -> Result<()> {
        if root_hash != self.root_hash {
            return Err(anyhow!(
                "root hash mismatch: got {:#x}, want {:#x}",
                utils::pallas_scalar_to_u256(self.root_hash),
                utils::pallas_scalar_to_u256(root_hash)
            ));
        }
        let hashes: Vec<Scalar> = self.path.iter().map(hash_flat_node::<E, L, L16>).collect();
        let key = E::encode_key(self.key);
        let mut key = key.as_str();
        for i in (1..self.path.len()).rev() {
            key = Self::verify_step(&self.path[i], key, hashes[i - 1])?;
        }
        let leaf = &self.path[0];
        if let Some(value) = &self.value {
            let leaf_hash = leaf.get(key).context("value not found")?;
            if *leaf_hash != value.poseidon_hash() {
                return Err(anyhow!("leaf hash mismatch"));
            }
        } else if leaf.get(key).is_some() {
            return Err(anyhow!("element unexpectedly found"));
        }
        Ok(())
    }
}

impl<K: Copy, V: PoseidonHash + proto::AnyProto, E: Encoder<K, L>, const L: usize, const L16: usize>
    Proof<K, V, E, L, L16>
{
    /// Encodes this proof into a `MerkleProof` protobuf. Note that the block descriptor must be
    /// provided by the caller.
    pub fn encode(
        &self,
        block_descriptor: dotakon::BlockDescriptor,
    ) -> Result<dotakon::MerkleProof> {
        Ok(dotakon::MerkleProof {
            block_descriptor: Some(block_descriptor),
            key: Some(E::encode_key(self.key)),
            value: match &self.value {
                Some(value) => Some(value.encode_to_any()?),
                None => None,
            },
            node: self
                .path
                .iter()
                .map(|children| dotakon::merkle_proof::Node {
                    children: children
                        .iter()
                        .map(|(label, hash)| {
                            (label.clone(), proto::pallas_scalar_to_bytes32(*hash))
                        })
                        .collect(),
                    hash: Some(proto::pallas_scalar_to_bytes32(
                        hash_flat_node::<E, L, L16>(children),
                    )),
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
        let key = E::decode_key(proto.key.as_ref().unwrap().as_str());
        let value = match &proto.value {
            Some(value) => Some(V::decode_from_any(value)?),
            None => None,
        };
        let path = proto
            .node
            .iter()
            .map(|node| {
                let children = node
                    .children
                    .iter()
                    .map(|(label, hash)| {
                        Ok((label.clone(), proto::pallas_scalar_from_bytes32(hash)?))
                    })
                    .collect::<Result<BTreeMap<String, Scalar>>>()?;
                if node.hash.is_none() {
                    return Err(anyhow!("invalid Merkle proof: missing node hash"));
                }
                let hash = proto::pallas_scalar_from_bytes32(&node.hash.unwrap())?;
                if hash != hash_flat_node::<E, L, L16>(&children) {
                    return Err(anyhow!("invalid Merkle proof: hash mismatch"));
                }
                Ok(children)
            })
            .collect::<Result<Vec<BTreeMap<String, Scalar>>>>()?;
        let root_hash = hash_flat_node::<E, L, L16>(&path[path.len() - 1]);
        Ok(Self {
            key,
            value,
            path,
            root_hash,
            _encoder: PhantomData {},
        })
    }

    /// Like `decode` but also validates the decoded proof against the provided root hash.
    ///
    /// Note that the root hash should be the same as one of the root hashes specified in the block
    /// descriptor, depending on what storage component this proof is relative to. For example, if
    /// the proof was generated from an account balance lookup the root hash must be the same as the
    /// one encoded in `block_descriptor.account_balances_root_hash`.
    pub fn decode_and_verify(proto: &dotakon::MerkleProof, root_hash: Scalar) -> Result<Self> {
        let proof = Self::decode(proto)?;
        proof.verify(root_hash)?;
        Ok(proof)
    }
}

trait Node<V: Debug + PoseidonHash>: Debug + PoseidonHash + Send + Sync + 'static {
    fn get(&self, key: &str) -> Option<&V>;
    fn lookup(&self, key: &str) -> (Option<&V>, Vec<BTreeMap<String, Scalar>>);
    fn put(&self, key: &str, value: V) -> Box<dyn Node<V>>;
}

#[derive(Debug)]
struct Leaf<V: Debug + PoseidonHash + Send + Sync + 'static> {
    value: V,
    hash: Scalar,
}

impl<V: Debug + PoseidonHash + Send + Sync + 'static> Leaf<V> {
    fn new(value: V) -> Self {
        let hash = value.poseidon_hash();
        Self { value, hash }
    }
}

impl<V: Debug + PoseidonHash + Send + Sync + 'static> Node<V> for Leaf<V> {
    fn get(&self, key: &str) -> Option<&V> {
        if key.is_empty() {
            Some(&self.value)
        } else {
            None
        }
    }

    fn lookup(&self, key: &str) -> (Option<&V>, Vec<BTreeMap<String, Scalar>>) {
        if key.is_empty() {
            (Some(&self.value), vec![])
        } else {
            (None, vec![])
        }
    }

    fn put(&self, key: &str, value: V) -> Box<dyn Node<V>> {
        assert!(key.is_empty());
        Box::new(Self::new(value))
    }
}

impl<V: Debug + PoseidonHash + Send + Sync + 'static> PoseidonHash for Leaf<V> {
    fn poseidon_hash(&self) -> Scalar {
        self.hash
    }
}

#[derive(Debug)]
struct InternalNode<
    V: Debug + PoseidonHash + Send + Sync + 'static,
    E: NodeEncoder<L>,
    const L: usize,
    const L16: usize,
> {
    children: BTreeMap<String, Arc<dyn Node<V>>>,
    hash: Scalar,
    _encoder: PhantomData<E>,
}

impl<
    V: Debug + PoseidonHash + Send + Sync + 'static,
    E: NodeEncoder<L>,
    const L: usize,
    const L16: usize,
> InternalNode<V, E, L, L16>
{
    fn with_children(children: BTreeMap<String, Arc<dyn Node<V>>>) -> Self {
        let hash = hash_flat_node::<E, L, L16>(
            &children
                .iter()
                .map(|(key, node)| (key.clone(), node.poseidon_hash()))
                .collect(),
        );
        Self {
            children,
            hash,
            _encoder: PhantomData {},
        }
    }

    fn common_prefix<'a>(key1: &'a str, key2: &str) -> &'a str {
        for ((i, ch1), ch2) in key1.char_indices().zip(key2.chars()) {
            if ch1 != ch2 {
                return &key1[0..i];
            }
        }
        key1
    }

    fn put_to_children(children: &mut BTreeMap<String, Arc<dyn Node<V>>>, key: &str, value: V) {
        if let Some((label, child)) = children.range_mut(..=key.to_string()).next_back() {
            let prefix = Self::common_prefix(key, label);
            if !prefix.is_empty() {
                let child = if prefix.len() < label.len() {
                    let label = label.clone();
                    let child = children.remove(label.as_str()).unwrap();
                    let child = Arc::new(Self::with_children(BTreeMap::from([(
                        label[prefix.len()..].to_string(),
                        child,
                    )])));
                    child.put(&key[prefix.len()..], value)
                } else {
                    child.put(&key[prefix.len()..], value)
                };
                children.insert(prefix.to_string(), child.into());
                return;
            }
        }
        children.insert(key.to_string(), Arc::new(Leaf::<V>::new(value)));
    }

    fn put_self(&self, key: &str, value: V) -> Self {
        assert!(!key.is_empty());
        let mut children = self.children.clone();
        Self::put_to_children(&mut children, key, value);
        Self::with_children(children)
    }
}

impl<
    V: Debug + PoseidonHash + Send + Sync + 'static,
    E: NodeEncoder<L>,
    const L: usize,
    const L16: usize,
> Node<V> for InternalNode<V, E, L, L16>
{
    fn get(&self, key: &str) -> Option<&V> {
        if key.is_empty() {
            return None;
        }
        if let Some((label, child)) = self.children.range(..=key.to_string()).next_back() {
            if key.len() >= label.len() && key.starts_with(label) {
                return child.get(&key[label.len()..]);
            }
        }
        None
    }

    fn lookup(&self, key: &str) -> (Option<&V>, Vec<BTreeMap<String, Scalar>>) {
        if key.is_empty() {
            return (None, vec![]);
        }
        let child_hashes: BTreeMap<String, Scalar> = self
            .children
            .iter()
            .map(|(label, child)| (label.clone(), child.poseidon_hash()))
            .collect();
        if let Some((label, child)) = self.children.range(..=key.to_string()).next_back() {
            if key.len() >= label.len() && key.starts_with(label) {
                let suffix = &key[label.len()..];
                let (value, mut path) = child.lookup(suffix);
                path.push(child_hashes);
                return (value, path);
            }
        }
        (None, vec![child_hashes])
    }

    fn put(&self, key: &str, value: V) -> Box<dyn Node<V>> {
        Box::new(self.put_self(key, value))
    }
}

impl<
    V: Debug + PoseidonHash + Send + Sync + 'static,
    E: NodeEncoder<L>,
    const L: usize,
    const L16: usize,
> Default for InternalNode<V, E, L, L16>
{
    fn default() -> Self {
        Self {
            children: BTreeMap::default(),
            hash: hash_flat_node::<E, L, L16>(&BTreeMap::default()),
            _encoder: PhantomData {},
        }
    }
}

impl<
    V: Debug + PoseidonHash + Send + Sync + 'static,
    E: NodeEncoder<L>,
    const L: usize,
    const L16: usize,
> PoseidonHash for InternalNode<V, E, L, L16>
{
    fn poseidon_hash(&self) -> Scalar {
        self.hash
    }
}

#[derive(Debug)]
pub struct Tree<
    K: Copy,
    V: Debug + Clone + PoseidonHash + Send + Sync + 'static,
    E: Encoder<K, L>,
    const L: usize,
    const L16: usize,
> {
    roots: BTreeMap<u64, InternalNode<V, E, L, L16>>,
    _key: PhantomData<K>,
}

impl<
    K: Copy,
    V: Debug + Clone + PoseidonHash + Send + Sync + 'static,
    E: Encoder<K, L>,
    const L: usize,
    const L16: usize,
> Tree<K, V, E, L, L16>
{
    pub fn root_hash(&self, version: u64) -> Scalar {
        let (_, root) = self.roots.range(0..=version).next_back().unwrap();
        root.poseidon_hash()
    }

    pub fn get(&self, key: K, version: u64) -> Option<&V> {
        let (_, root) = self.roots.range(0..=version).next_back()?;
        root.get(E::encode_key(key).as_str())
    }

    pub fn get_proof(&self, key: K, version: u64) -> Proof<K, V, E, L, L16> {
        let (_, root) = self.roots.range(0..=version).next_back().unwrap();
        let (value, path) = root.lookup(E::encode_key(key).as_str());
        Proof::<K, V, E, L, L16> {
            key,
            value: value.cloned(),
            path,
            root_hash: root.poseidon_hash(),
            _encoder: PhantomData {},
        }
    }

    pub fn put(&mut self, key: K, value: V, version: u64) {
        let (_, root) = self.roots.range_mut(0..=version).next_back().unwrap();
        let new_root = root.put_self(E::encode_key(key).as_str(), value);
        if new_root.poseidon_hash() != root.poseidon_hash() {
            self.roots.insert(version, new_root);
        }
    }
}

impl<
    K: Copy,
    V: Debug + Clone + PoseidonHash + Send + Sync + 'static,
    E: Encoder<K, L>,
    const L: usize,
    const L16: usize,
> Default for Tree<K, V, E, L, L16>
{
    fn default() -> Self {
        Self {
            roots: BTreeMap::from([(0, InternalNode::<V, E, L, L16>::default())]),
            _key: PhantomData {},
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct AccountAddressEncoder {}

impl KeyEncoder<Scalar> for AccountAddressEncoder {
    fn encode_key(key: Scalar) -> String {
        encode_key(&key.to_repr())
    }

    fn decode_key(key: &str) -> Scalar {
        Scalar::from_repr_vartime(decode_key::<32>(key)).unwrap()
    }
}

impl NodeEncoder<2> for AccountAddressEncoder {
    fn encode_node(key: &str, hash: Scalar) -> [Scalar; 2] {
        [Self::decode_key(key), hash]
    }
}

impl Encoder<Scalar, 2> for AccountAddressEncoder {}

pub type AccountBalanceTree = Tree<Scalar, Scalar, AccountAddressEncoder, 2, 32>;
pub type AccountBalanceProof = Proof<Scalar, Scalar, AccountAddressEncoder, 2, 32>;

#[derive(Debug, PartialEq, Eq)]
pub struct ProgramStorageKeyEncoder {}

impl KeyEncoder<(Scalar, u64)> for ProgramStorageKeyEncoder {
    fn encode_key((program_address, memory_address): (Scalar, u64)) -> String {
        let mut bytes = [0u8; 40];
        bytes[0..32].copy_from_slice(&program_address.to_repr());
        bytes[32..40].copy_from_slice(&memory_address.to_be_bytes());
        encode_key(&bytes)
    }

    fn decode_key(key: &str) -> (Scalar, u64) {
        let bytes = decode_key::<40>(key);
        let mut program_address_bytes = [0u8; 32];
        program_address_bytes.copy_from_slice(&bytes[0..32]);
        let mut memory_address_bytes = [0u8; 8];
        memory_address_bytes.copy_from_slice(&bytes[32..40]);
        (
            Scalar::from_repr_vartime(program_address_bytes).unwrap(),
            u64::from_be_bytes(memory_address_bytes),
        )
    }
}

impl NodeEncoder<3> for ProgramStorageKeyEncoder {
    fn encode_node(key: &str, hash: Scalar) -> [Scalar; 3] {
        let (program_address, memory_address) = Self::decode_key(key);
        [program_address, memory_address.into(), hash]
    }
}

impl Encoder<(Scalar, u64), 3> for ProgramStorageKeyEncoder {}

pub type ProgramStorageTree = Tree<(Scalar, u64), Scalar, ProgramStorageKeyEncoder, 3, 48>;
pub type ProgramStorageProof = Proof<(Scalar, u64), Scalar, ProgramStorageKeyEncoder, 3, 48>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils;

    fn test_scalar1() -> Scalar {
        Scalar::from_repr_vartime([
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 0,
        ])
        .unwrap()
    }

    fn test_scalar2() -> Scalar {
        Scalar::from_repr_vartime([
            31u8, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11,
            10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0,
        ])
        .unwrap()
    }

    fn test_scalar3() -> Scalar {
        Scalar::from_repr_vartime([
            32u8, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 17, 18, 19, 20, 21,
            22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 0,
        ])
        .unwrap()
    }

    #[test]
    fn test_scalar_hash() {
        assert_eq!(
            test_scalar1().poseidon_hash(),
            utils::parse_pallas_scalar(
                "0x37a79793bd72030e3b27f3265b468a632a4e172f180c6992a15f055f3bfbc58c"
            )
        );
    }

    #[test]
    fn test_encode_key() {
        assert_eq!(
            encode_key(&[
                1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 31, 32
            ]),
            "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
        );
        assert_eq!(
            encode_key(&[
                32u8, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13,
                12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1
            ]),
            "201f1e1d1c1b1a191817161514131211100f0e0d0c0b0a090807060504030201"
        );
    }

    #[test]
    fn test_decode_key() {
        assert_eq!(
            decode_key("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
            [
                1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 31, 32
            ]
        );
        assert_eq!(
            decode_key("201f1e1d1c1b1a191817161514131211100f0e0d0c0b0a090807060504030201"),
            [
                32u8, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13,
                12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1
            ]
        );
    }

    #[test]
    fn test_empty_node() {
        assert_eq!(
            InternalNode::<Scalar, AccountAddressEncoder, 2, 32>::default().poseidon_hash(),
            utils::parse_pallas_scalar(
                "0x375830d6862157562431f637dcb4aa91e2bba7220abfa58b7618a713e9bb8803"
            )
        );
    }

    #[test]
    fn test_initial_root_hash() {
        let tree = AccountBalanceTree::default();
        let hash = utils::parse_pallas_scalar(
            "0x375830d6862157562431f637dcb4aa91e2bba7220abfa58b7618a713e9bb8803",
        );
        assert_eq!(tree.root_hash(0), hash);
        assert_eq!(tree.root_hash(1), hash);
        assert_eq!(tree.root_hash(2), hash);
    }

    fn test_initial_state(key: Scalar, version: u64) {
        let tree = AccountBalanceTree::default();
        assert!(tree.get(key, version).is_none());
        let proof = tree.get_proof(key, version);
        assert_eq!(*proof.key(), key);
        assert!(proof.value().is_none());
        assert_eq!(proof.root_hash(), tree.root_hash(version));
        assert!(proof.verify(tree.root_hash(version)).is_ok());
    }

    #[test]
    fn test_initial_state1() {
        let key = test_scalar1();
        test_initial_state(key, 0);
        test_initial_state(key, 1);
        test_initial_state(key, 2);
    }

    #[test]
    fn test_initial_state2() {
        let key = test_scalar2();
        test_initial_state(key, 0);
        test_initial_state(key, 1);
        test_initial_state(key, 2);
    }

    #[test]
    fn test_insert_one() {
        let mut tree = AccountBalanceTree::default();
        let key1 = test_scalar1();
        let key2 = test_scalar2();
        let value = test_scalar2();
        tree.put(key1, value.clone(), 0);
        assert_eq!(*tree.get(key1, 0).unwrap(), value);
        assert_eq!(*tree.get(key1, 1).unwrap(), value);
        assert_eq!(*tree.get(key1, 2).unwrap(), value);
        let proof1 = tree.get_proof(key1, 0);
        assert_eq!(*proof1.key(), key1);
        assert_eq!(*proof1.value(), Some(value));
        assert_eq!(proof1.root_hash(), tree.root_hash(0));
        assert_eq!(proof1.root_hash(), tree.root_hash(1));
        assert_eq!(proof1.root_hash(), tree.root_hash(2));
        assert!(proof1.verify(tree.root_hash(0)).is_ok());
        assert_eq!(tree.get_proof(key1, 1), proof1);
        assert_eq!(tree.get_proof(key1, 2), proof1);
        assert!(tree.get(key2, 0).is_none());
        assert!(tree.get(key2, 1).is_none());
        assert!(tree.get(key2, 2).is_none());
        let proof2 = tree.get_proof(key2, 0);
        assert_eq!(*proof2.key(), key2);
        assert!(proof2.value().is_none());
        assert_eq!(proof2.root_hash(), tree.root_hash(0));
        assert_eq!(proof2.root_hash(), tree.root_hash(1));
        assert_eq!(proof2.root_hash(), tree.root_hash(2));
        assert!(proof2.verify(tree.root_hash(0)).is_ok());
        assert_eq!(tree.get_proof(key2, 1), proof2);
        assert_eq!(tree.get_proof(key2, 2), proof2);
    }

    #[test]
    fn test_first_root_hash_change() {
        let mut tree = AccountBalanceTree::default();
        let key1 = test_scalar1();
        let value = test_scalar2();
        let hash1 = tree.root_hash(0);
        tree.put(key1, value.clone(), 0);
        let hash2 = tree.root_hash(0);
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_insert_two() {
        let mut tree = AccountBalanceTree::default();
        let key1 = test_scalar1();
        let key2 = test_scalar2();
        let value1 = test_scalar2();
        let value2 = test_scalar1();
        tree.put(key1, value1.clone(), 0);
        tree.put(key2, value2.clone(), 0);
        assert_eq!(*tree.get(key1, 0).unwrap(), value1);
        assert_eq!(*tree.get(key1, 1).unwrap(), value1);
        assert_eq!(*tree.get(key1, 2).unwrap(), value1);
        let proof1 = tree.get_proof(key1, 0);
        assert_eq!(*proof1.key(), key1);
        assert_eq!(*proof1.value(), Some(value1));
        assert_eq!(proof1.root_hash(), tree.root_hash(0));
        assert_eq!(proof1.root_hash(), tree.root_hash(1));
        assert_eq!(proof1.root_hash(), tree.root_hash(2));
        assert!(proof1.verify(tree.root_hash(0)).is_ok());
        assert_eq!(tree.get_proof(key1, 1), proof1);
        assert_eq!(tree.get_proof(key1, 2), proof1);
        assert_eq!(*tree.get(key2, 0).unwrap(), value2);
        assert_eq!(*tree.get(key2, 1).unwrap(), value2);
        assert_eq!(*tree.get(key2, 2).unwrap(), value2);
        let proof2 = tree.get_proof(key2, 0);
        assert_eq!(*proof2.key(), key2);
        assert_eq!(*proof2.value(), Some(value2));
        assert_eq!(proof2.root_hash(), tree.root_hash(0));
        assert_eq!(proof2.root_hash(), tree.root_hash(1));
        assert_eq!(proof2.root_hash(), tree.root_hash(2));
        assert!(proof2.verify(tree.root_hash(0)).is_ok());
        assert_eq!(tree.get_proof(key2, 1), proof2);
        assert_eq!(tree.get_proof(key2, 2), proof2);
    }

    #[test]
    fn test_second_root_hash_change() {
        let mut tree = AccountBalanceTree::default();
        let key1 = test_scalar1();
        let key2 = test_scalar2();
        let value1 = test_scalar2();
        let value2 = test_scalar1();
        tree.put(key1, value1, 0);
        let hash1 = tree.root_hash(0);
        tree.put(key2, value2, 0);
        let hash2 = tree.root_hash(0);
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_insert_with_shared_prefix() {
        let mut tree = AccountBalanceTree::default();
        let key1 = test_scalar1();
        let key2 = test_scalar3();
        let value1 = test_scalar2();
        let value2 = test_scalar1();
        tree.put(key1, value1.clone(), 0);
        tree.put(key2, value2.clone(), 0);
        assert_eq!(*tree.get(key1, 0).unwrap(), value1);
        assert_eq!(*tree.get(key1, 1).unwrap(), value1);
        assert_eq!(*tree.get(key1, 2).unwrap(), value1);
        let proof1 = tree.get_proof(key1, 0);
        assert_eq!(*proof1.key(), key1);
        assert_eq!(*proof1.value(), Some(value1));
        assert_eq!(proof1.root_hash(), tree.root_hash(0));
        assert_eq!(proof1.root_hash(), tree.root_hash(1));
        assert_eq!(proof1.root_hash(), tree.root_hash(2));
        assert!(proof1.verify(tree.root_hash(0)).is_ok());
        assert_eq!(tree.get_proof(key1, 1), proof1);
        assert_eq!(tree.get_proof(key1, 2), proof1);
        assert_eq!(*tree.get(key2, 0).unwrap(), value2);
        assert_eq!(*tree.get(key2, 1).unwrap(), value2);
        assert_eq!(*tree.get(key2, 2).unwrap(), value2);
        let proof2 = tree.get_proof(key2, 0);
        assert_eq!(*proof2.key(), key2);
        assert_eq!(*proof2.value(), Some(value2));
        assert_eq!(proof2.root_hash(), tree.root_hash(0));
        assert_eq!(proof2.root_hash(), tree.root_hash(1));
        assert_eq!(proof2.root_hash(), tree.root_hash(2));
        assert!(proof2.verify(tree.root_hash(0)).is_ok());
        assert_eq!(tree.get_proof(key2, 1), proof2);
        assert_eq!(tree.get_proof(key2, 2), proof2);
    }

    fn test_insert_three(value1: Scalar, value2: Scalar, value3: Scalar) {
        let mut tree = AccountBalanceTree::default();
        tree.put(value1, value1.clone(), 0);
        tree.put(value2, value2.clone(), 0);
        tree.put(value3, value3.clone(), 0);
        assert_eq!(*tree.get(value1, 0).unwrap(), value1);
        assert_eq!(*tree.get(value1, 1).unwrap(), value1);
        assert_eq!(*tree.get(value1, 2).unwrap(), value1);
        let proof1 = tree.get_proof(value1, 0);
        assert_eq!(*proof1.key(), value1);
        assert_eq!(*proof1.value(), Some(value1));
        assert_eq!(proof1.root_hash(), tree.root_hash(0));
        assert_eq!(proof1.root_hash(), tree.root_hash(1));
        assert_eq!(proof1.root_hash(), tree.root_hash(2));
        assert!(proof1.verify(tree.root_hash(0)).is_ok());
        assert_eq!(tree.get_proof(value1, 1), proof1);
        assert_eq!(tree.get_proof(value1, 2), proof1);
        assert_eq!(*tree.get(value2, 0).unwrap(), value2);
        assert_eq!(*tree.get(value2, 1).unwrap(), value2);
        assert_eq!(*tree.get(value2, 2).unwrap(), value2);
        let proof2 = tree.get_proof(value2, 0);
        assert_eq!(*proof2.key(), value2);
        assert_eq!(*proof2.value(), Some(value2));
        assert_eq!(proof2.root_hash(), tree.root_hash(0));
        assert_eq!(proof2.root_hash(), tree.root_hash(1));
        assert_eq!(proof2.root_hash(), tree.root_hash(2));
        assert!(proof2.verify(tree.root_hash(0)).is_ok());
        assert_eq!(tree.get_proof(value2, 1), proof2);
        assert_eq!(tree.get_proof(value2, 2), proof2);
        assert_eq!(*tree.get(value3, 0).unwrap(), value3);
        assert_eq!(*tree.get(value3, 1).unwrap(), value3);
        assert_eq!(*tree.get(value3, 2).unwrap(), value3);
        let proof3 = tree.get_proof(value3, 0);
        assert_eq!(*proof3.key(), value3);
        assert_eq!(*proof3.value(), Some(value3));
        assert_eq!(proof3.root_hash(), tree.root_hash(0));
        assert_eq!(proof3.root_hash(), tree.root_hash(1));
        assert_eq!(proof3.root_hash(), tree.root_hash(2));
        assert!(proof3.verify(tree.root_hash(0)).is_ok());
        assert_eq!(tree.get_proof(value3, 1), proof3);
        assert_eq!(tree.get_proof(value3, 2), proof3);
    }

    #[test]
    fn test_insert_three1() {
        test_insert_three(test_scalar1(), test_scalar2(), test_scalar3());
    }

    #[test]
    fn test_insert_three2() {
        test_insert_three(test_scalar1(), test_scalar3(), test_scalar2());
    }

    #[test]
    fn test_insert_three3() {
        test_insert_three(test_scalar2(), test_scalar1(), test_scalar3());
    }

    #[test]
    fn test_insert_three4() {
        test_insert_three(test_scalar2(), test_scalar3(), test_scalar1());
    }

    #[test]
    fn test_insert_three5() {
        test_insert_three(test_scalar3(), test_scalar1(), test_scalar2());
    }

    #[test]
    fn test_insert_three6() {
        test_insert_three(test_scalar3(), test_scalar2(), test_scalar1());
    }

    #[test]
    fn test_update() {
        let mut tree = AccountBalanceTree::default();
        let key1 = test_scalar1();
        let key2 = test_scalar2();
        let value1 = test_scalar2();
        let value2 = test_scalar1();
        tree.put(key1, value1, 0);
        tree.put(key1, value2.clone(), 0);
        assert_eq!(*tree.get(key1, 0).unwrap(), value2);
        assert_eq!(*tree.get(key1, 1).unwrap(), value2);
        assert_eq!(*tree.get(key1, 2).unwrap(), value2);
        let proof1 = tree.get_proof(key1, 0);
        assert_eq!(*proof1.key(), key1);
        assert_eq!(*proof1.value(), Some(value2));
        assert_eq!(proof1.root_hash(), tree.root_hash(0));
        assert_eq!(proof1.root_hash(), tree.root_hash(1));
        assert_eq!(proof1.root_hash(), tree.root_hash(2));
        assert!(proof1.verify(tree.root_hash(0)).is_ok());
        assert_eq!(tree.get_proof(key1, 1), proof1);
        assert_eq!(tree.get_proof(key1, 2), proof1);
        assert!(tree.get(key2, 0).is_none());
        assert!(tree.get(key2, 1).is_none());
        assert!(tree.get(key2, 2).is_none());
        let proof2 = tree.get_proof(key2, 0);
        assert_eq!(*proof2.key(), key2);
        assert!(proof2.value().is_none());
        assert_eq!(proof2.root_hash(), tree.root_hash(0));
        assert_eq!(proof2.root_hash(), tree.root_hash(1));
        assert_eq!(proof2.root_hash(), tree.root_hash(2));
        assert!(proof2.verify(tree.root_hash(0)).is_ok());
        assert_eq!(tree.get_proof(key2, 1), proof2);
        assert_eq!(tree.get_proof(key2, 2), proof2);
    }

    #[test]
    fn test_new_version() {
        let mut tree = AccountBalanceTree::default();
        let key1 = test_scalar1();
        let key2 = test_scalar2();
        let value1 = test_scalar2();
        let value2 = test_scalar1();
        tree.put(key1, value1.clone(), 0);
        tree.put(key1, value2.clone(), 1);
        assert_eq!(*tree.get(key1, 0).unwrap(), value1);
        assert_eq!(*tree.get(key1, 1).unwrap(), value2);
        assert_eq!(*tree.get(key1, 2).unwrap(), value2);
        let proof11 = tree.get_proof(key1, 0);
        assert_eq!(*proof11.key(), key1);
        assert_eq!(*proof11.value(), Some(value1));
        assert_eq!(proof11.root_hash(), tree.root_hash(0));
        assert_ne!(proof11.root_hash(), tree.root_hash(1));
        assert_ne!(proof11.root_hash(), tree.root_hash(2));
        assert!(proof11.verify(tree.root_hash(0)).is_ok());
        assert!(proof11.verify(tree.root_hash(1)).is_err());
        let proof12 = tree.get_proof(key1, 1);
        assert_eq!(*proof12.key(), key1);
        assert_eq!(*proof12.value(), Some(value2));
        assert_ne!(proof12.root_hash(), tree.root_hash(0));
        assert_eq!(proof12.root_hash(), tree.root_hash(1));
        assert_eq!(proof12.root_hash(), tree.root_hash(2));
        assert!(proof12.verify(tree.root_hash(0)).is_err());
        assert!(proof12.verify(tree.root_hash(1)).is_ok());
        assert_eq!(tree.get_proof(key1, 2), proof12);
        assert!(tree.get(key2, 0).is_none());
        assert!(tree.get(key2, 1).is_none());
        assert!(tree.get(key2, 2).is_none());
        let proof21 = tree.get_proof(key2, 0);
        assert_eq!(*proof21.key(), key2);
        assert!(proof21.value().is_none());
        assert_eq!(proof21.root_hash(), tree.root_hash(0));
        assert_ne!(proof21.root_hash(), tree.root_hash(1));
        assert_ne!(proof21.root_hash(), tree.root_hash(2));
        assert!(proof21.verify(tree.root_hash(0)).is_ok());
        assert!(proof21.verify(tree.root_hash(1)).is_err());
        let proof22 = tree.get_proof(key2, 1);
        assert_eq!(*proof22.key(), key2);
        assert!(proof22.value().is_none());
        assert_ne!(proof22.root_hash(), tree.root_hash(0));
        assert_eq!(proof22.root_hash(), tree.root_hash(1));
        assert_eq!(proof22.root_hash(), tree.root_hash(2));
        assert!(proof22.verify(tree.root_hash(0)).is_err());
        assert!(proof22.verify(tree.root_hash(1)).is_ok());
        assert_eq!(tree.get_proof(key2, 1), proof22);
        assert_eq!(tree.get_proof(key2, 2), proof22);
    }

    #[test]
    fn test_skip_version() {
        let mut tree = AccountBalanceTree::default();
        let key1 = test_scalar1();
        let key2 = test_scalar2();
        let value1 = test_scalar2();
        let value2 = test_scalar1();
        tree.put(key1, value1.clone(), 0);
        tree.put(key1, value2.clone(), 2);
        assert_eq!(*tree.get(key1, 0).unwrap(), value1);
        assert_eq!(*tree.get(key1, 1).unwrap(), value1);
        assert_eq!(*tree.get(key1, 2).unwrap(), value2);
        let proof11 = tree.get_proof(key1, 0);
        assert_eq!(*proof11.key(), key1);
        assert_eq!(*proof11.value(), Some(value1));
        assert_eq!(proof11.root_hash(), tree.root_hash(0));
        assert_eq!(proof11.root_hash(), tree.root_hash(1));
        assert_ne!(proof11.root_hash(), tree.root_hash(2));
        assert!(proof11.verify(tree.root_hash(0)).is_ok());
        assert!(proof11.verify(tree.root_hash(1)).is_ok());
        assert!(proof11.verify(tree.root_hash(2)).is_err());
        let proof12 = tree.get_proof(key1, 2);
        assert_eq!(*proof12.key(), key1);
        assert_eq!(*proof12.value(), Some(value2));
        assert_ne!(proof12.root_hash(), tree.root_hash(0));
        assert_ne!(proof12.root_hash(), tree.root_hash(1));
        assert_eq!(proof12.root_hash(), tree.root_hash(2));
        assert!(proof12.verify(tree.root_hash(0)).is_err());
        assert!(proof12.verify(tree.root_hash(1)).is_err());
        assert!(proof12.verify(tree.root_hash(2)).is_ok());
        assert_eq!(tree.get_proof(key1, 1), proof11);
        assert!(tree.get(key2, 0).is_none());
        assert!(tree.get(key2, 1).is_none());
        assert!(tree.get(key2, 2).is_none());
        let proof21 = tree.get_proof(key2, 0);
        assert_eq!(*proof21.key(), key2);
        assert!(proof21.value().is_none());
        assert_eq!(proof21.root_hash(), tree.root_hash(0));
        assert_eq!(proof21.root_hash(), tree.root_hash(1));
        assert_ne!(proof21.root_hash(), tree.root_hash(2));
        assert!(proof21.verify(tree.root_hash(0)).is_ok());
        assert!(proof21.verify(tree.root_hash(1)).is_ok());
        assert!(proof21.verify(tree.root_hash(2)).is_err());
        let proof22 = tree.get_proof(key2, 2);
        assert_eq!(*proof22.key(), key2);
        assert!(proof22.value().is_none());
        assert_ne!(proof22.root_hash(), tree.root_hash(0));
        assert_ne!(proof22.root_hash(), tree.root_hash(1));
        assert_eq!(proof22.root_hash(), tree.root_hash(2));
        assert!(proof22.verify(tree.root_hash(0)).is_err());
        assert!(proof22.verify(tree.root_hash(1)).is_err());
        assert!(proof22.verify(tree.root_hash(2)).is_ok());
        assert_eq!(tree.get_proof(key2, 1), proof21);
    }

    #[test]
    fn test_two_values_across_versions() {
        let mut tree = AccountBalanceTree::default();
        let key1 = test_scalar1();
        let key2 = test_scalar2();
        let value1 = test_scalar2();
        let value2 = test_scalar3();
        let value3 = test_scalar1();
        tree.put(key1, value1.clone(), 0);
        tree.put(key2, value2.clone(), 0);
        tree.put(key2, value3.clone(), 2);
        assert_eq!(*tree.get(key1, 0).unwrap(), value1);
        assert_eq!(*tree.get(key1, 1).unwrap(), value1);
        assert_eq!(*tree.get(key1, 2).unwrap(), value1);
        let proof11 = tree.get_proof(key1, 0);
        assert_eq!(*proof11.key(), key1);
        assert_eq!(*proof11.value(), Some(value1.clone()));
        assert_eq!(proof11.root_hash(), tree.root_hash(0));
        assert_eq!(proof11.root_hash(), tree.root_hash(1));
        assert_ne!(proof11.root_hash(), tree.root_hash(2));
        assert!(proof11.verify(tree.root_hash(0)).is_ok());
        assert!(proof11.verify(tree.root_hash(1)).is_ok());
        assert!(proof11.verify(tree.root_hash(2)).is_err());
        let proof12 = tree.get_proof(key1, 2);
        assert_eq!(*proof12.key(), key1);
        assert_eq!(*proof12.value(), Some(value1));
        assert_ne!(proof12.root_hash(), tree.root_hash(0));
        assert_ne!(proof12.root_hash(), tree.root_hash(1));
        assert_eq!(proof12.root_hash(), tree.root_hash(2));
        assert!(proof12.verify(tree.root_hash(0)).is_err());
        assert!(proof12.verify(tree.root_hash(1)).is_err());
        assert!(proof12.verify(tree.root_hash(2)).is_ok());
        assert_eq!(tree.get_proof(key1, 1), proof11);
        assert_eq!(*tree.get(key2, 0).unwrap(), value2);
        assert_eq!(*tree.get(key2, 1).unwrap(), value2);
        assert_eq!(*tree.get(key2, 2).unwrap(), value3);
        let proof21 = tree.get_proof(key2, 0);
        assert_eq!(*proof21.key(), key2);
        assert_eq!(*proof21.value(), Some(value2));
        assert_eq!(proof21.root_hash(), tree.root_hash(0));
        assert_eq!(proof21.root_hash(), tree.root_hash(1));
        assert_ne!(proof21.root_hash(), tree.root_hash(2));
        assert!(proof21.verify(tree.root_hash(0)).is_ok());
        assert!(proof21.verify(tree.root_hash(1)).is_ok());
        assert!(proof21.verify(tree.root_hash(2)).is_err());
        let proof22 = tree.get_proof(key2, 2);
        assert_eq!(*proof22.key(), key2);
        assert_eq!(*proof22.value(), Some(value3));
        assert_ne!(proof22.root_hash(), tree.root_hash(0));
        assert_ne!(proof22.root_hash(), tree.root_hash(1));
        assert_eq!(proof22.root_hash(), tree.root_hash(2));
        assert!(proof22.verify(tree.root_hash(0)).is_err());
        assert!(proof22.verify(tree.root_hash(1)).is_err());
        assert!(proof22.verify(tree.root_hash(2)).is_ok());
        assert_eq!(tree.get_proof(key2, 1), proof21);
    }

    #[test]
    fn test_transcode_proof() {
        let mut tree = AccountBalanceTree::default();
        let key1 = test_scalar1();
        let key2 = test_scalar2();
        let key3 = test_scalar3();
        let value1 = test_scalar2();
        let value2 = test_scalar3();
        let value3 = test_scalar1();
        tree.put(key1, value1.clone(), 0);
        tree.put(key2, value2.clone(), 0);
        tree.put(key3, value3.clone(), 0);
        let proof = tree.get_proof(key2, 0);
        let proto = proof
            .encode(dotakon::BlockDescriptor {
                block_hash: None,
                block_number: None,
                previous_block_hash: None,
                timestamp: None,
                network_topology_root_hash: None,
                last_transaction_hash: None,
                account_balances_root_hash: Some(proto::pallas_scalar_to_bytes32(
                    tree.root_hash(0),
                )),
                program_storage_root_hash: None,
            })
            .unwrap();
        assert_eq!(AccountBalanceProof::decode(&proto).unwrap(), proof);
    }

    #[test]
    fn test_decode_and_verify_proof() {
        let mut tree = AccountBalanceTree::default();
        let key1 = test_scalar1();
        let key2 = test_scalar2();
        let key3 = test_scalar3();
        let value1 = test_scalar2();
        let value2 = test_scalar3();
        let value3 = test_scalar1();
        tree.put(key1, value1.clone(), 0);
        tree.put(key2, value2.clone(), 0);
        tree.put(key3, value3.clone(), 0);
        let proof = tree.get_proof(key2, 0);
        let proto = proof
            .encode(dotakon::BlockDescriptor {
                block_hash: None,
                block_number: None,
                previous_block_hash: None,
                timestamp: None,
                network_topology_root_hash: None,
                last_transaction_hash: None,
                account_balances_root_hash: Some(proto::pallas_scalar_to_bytes32(
                    tree.root_hash(0),
                )),
                program_storage_root_hash: None,
            })
            .unwrap();
        assert_eq!(
            AccountBalanceProof::decode_and_verify(&proto, tree.root_hash(0)).unwrap(),
            proof
        );
    }

    #[test]
    fn test_decode_sabotaged_proof() {
        let mut tree = AccountBalanceTree::default();
        let key1 = test_scalar1();
        let key2 = test_scalar2();
        let key3 = test_scalar3();
        let value1 = test_scalar2();
        let value2 = test_scalar3();
        let value3 = test_scalar1();
        tree.put(key1, value1.clone(), 0);
        tree.put(key2, value2.clone(), 0);
        tree.put(key3, value3.clone(), 0);
        let proof = tree.get_proof(key2, 0);
        let mut proto = proof
            .encode(dotakon::BlockDescriptor {
                block_hash: None,
                block_number: None,
                previous_block_hash: None,
                timestamp: None,
                network_topology_root_hash: None,
                last_transaction_hash: None,
                account_balances_root_hash: Some(proto::pallas_scalar_to_bytes32(
                    tree.root_hash(0),
                )),
                program_storage_root_hash: None,
            })
            .unwrap();
        proto.node[0].hash = Some(proto::pallas_scalar_to_bytes32(Scalar::ZERO));
        assert!(AccountBalanceProof::decode_and_verify(&proto, tree.root_hash(0)).is_err());
    }

    #[test]
    fn test_decode_and_verify_sabotaged_proof() {
        let mut tree = AccountBalanceTree::default();
        let key1 = test_scalar1();
        let key2 = test_scalar2();
        let key3 = test_scalar3();
        let value1 = test_scalar2();
        let value2 = test_scalar3();
        let value3 = test_scalar1();
        tree.put(key1, value1.clone(), 0);
        tree.put(key2, value2.clone(), 0);
        tree.put(key3, value3.clone(), 0);
        let proof = tree.get_proof(key2, 0);
        let mut proto = proof
            .encode(dotakon::BlockDescriptor {
                block_hash: None,
                block_number: None,
                previous_block_hash: None,
                timestamp: None,
                network_topology_root_hash: None,
                last_transaction_hash: None,
                account_balances_root_hash: Some(proto::pallas_scalar_to_bytes32(
                    tree.root_hash(0),
                )),
                program_storage_root_hash: None,
            })
            .unwrap();
        proto.node[0].hash = Some(proto::pallas_scalar_to_bytes32(Scalar::ZERO));
        assert!(AccountBalanceProof::decode_and_verify(&proto, tree.root_hash(0)).is_err());
    }

    #[test]
    fn test_decode_wrong_proof() {
        let mut tree = AccountBalanceTree::default();
        let key1 = test_scalar1();
        let key2 = test_scalar2();
        let key3 = test_scalar3();
        let value1 = test_scalar2();
        let value2 = test_scalar3();
        let value3 = test_scalar1();
        tree.put(key1, value1.clone(), 0);
        tree.put(key2, value2.clone(), 0);
        tree.put(key3, value3.clone(), 0);
        let proof = tree.get_proof(key2, 0);
        let mut proto = proof
            .encode(dotakon::BlockDescriptor {
                block_hash: None,
                block_number: None,
                previous_block_hash: None,
                timestamp: None,
                network_topology_root_hash: None,
                last_transaction_hash: None,
                account_balances_root_hash: Some(proto::pallas_scalar_to_bytes32(
                    tree.root_hash(0),
                )),
                program_storage_root_hash: None,
            })
            .unwrap();
        proto.value = None;
        assert!(AccountBalanceProof::decode(&proto).is_ok());
    }

    #[test]
    fn test_decode_and_verify_wrong_proof() {
        let mut tree = AccountBalanceTree::default();
        let key1 = test_scalar1();
        let key2 = test_scalar2();
        let key3 = test_scalar3();
        let value1 = test_scalar2();
        let value2 = test_scalar3();
        let value3 = test_scalar1();
        tree.put(key1, value1.clone(), 0);
        tree.put(key2, value2.clone(), 0);
        tree.put(key3, value3.clone(), 0);
        let proof = tree.get_proof(key2, 0);
        let mut proto = proof
            .encode(dotakon::BlockDescriptor {
                block_hash: None,
                block_number: None,
                previous_block_hash: None,
                timestamp: None,
                network_topology_root_hash: None,
                last_transaction_hash: None,
                account_balances_root_hash: Some(proto::pallas_scalar_to_bytes32(
                    tree.root_hash(0),
                )),
                program_storage_root_hash: None,
            })
            .unwrap();
        proto.value = None;
        assert!(AccountBalanceProof::decode_and_verify(&proto, tree.root_hash(0)).is_err());
    }

    #[test]
    fn test_past_modification() {
        let mut tree = AccountBalanceTree::default();
        let key1 = test_scalar1();
        let key2 = test_scalar2();
        let key3 = test_scalar3();
        let value1 = test_scalar2();
        let value2 = test_scalar3();
        let value3 = test_scalar1();
        tree.put(key1, value1.clone(), 0);
        tree.put(key2, value2.clone(), 1);
        tree.put(key1, value3.clone(), 0);
        tree.put(key3, value3.clone(), 0);
        assert_eq!(*tree.get(key1, 0).unwrap(), value3);
        assert_eq!(*tree.get(key1, 1).unwrap(), value1);
        assert_eq!(*tree.get(key1, 2).unwrap(), value1);
        assert!(tree.get(key2, 0).is_none());
        assert_eq!(*tree.get(key2, 1).unwrap(), value2);
        assert_eq!(*tree.get(key2, 2).unwrap(), value2);
        assert_eq!(*tree.get(key3, 0).unwrap(), value3);
        assert!(tree.get(key3, 1).is_none());
        assert!(tree.get(key3, 2).is_none());
    }
}
