use crate::bits;
use crate::chips;
use crate::dotakon;
use crate::proto;
use crate::utils;
use anyhow::{Result, anyhow};
use ff::{Field, PrimeField};
use halo2_proofs::{circuit, plonk, poly};
use pasta_curves::pallas::Scalar;
use std::any::Any;
use std::any::TypeId;
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::Mutex;

pub trait AsScalar {
    fn as_scalar(&self) -> Scalar;
}

impl AsScalar for Scalar {
    fn as_scalar(&self) -> Scalar {
        *self
    }
}

impl AsScalar for u64 {
    fn as_scalar(&self) -> Scalar {
        Scalar::from(*self)
    }
}

pub trait FromScalar: Sized {
    fn from_scalar(scalar: Scalar) -> Result<Self>;
}

impl FromScalar for Scalar {
    fn from_scalar(scalar: Scalar) -> Result<Self> {
        Ok(scalar)
    }
}

impl FromScalar for u64 {
    fn from_scalar(scalar: Scalar) -> Result<Self> {
        let bytes32 = scalar.to_repr();
        for i in 8..32 {
            if bytes32[i] != 0 {
                return Err(anyhow!("invalid 64-bit scalar"));
            }
        }
        let mut bytes8 = [0u8; 8];
        bytes8.copy_from_slice(&bytes32[0..8]);
        Ok(u64::from_le_bytes(bytes8))
    }
}

pub trait PoseidonHash {
    fn poseidon_hash(&self) -> Scalar;
}

trait Node<
    K: Debug + Copy + Send + Sync + FromScalar + Into<Scalar> + 'static,
    V: Debug + Default + Clone + Send + Sync + AsScalar + 'static,
>: Debug + Send + Sync + PoseidonHash + AsScalar + 'static
{
    fn get(&self, key: K) -> &V;
    fn lookup(&self, key: K) -> (&V, Vec<(Scalar, Scalar)>);
    fn put(&self, key: K, value: V) -> Arc<dyn Node<K, V>>;
}

#[derive(Debug)]
struct PhantomNodes<
    K: Debug + Copy + Send + Sync + FromScalar + Into<Scalar> + 'static,
    V: Debug + Default + Clone + Send + Sync + AsScalar + 'static,
> {
    nodes: [Arc<dyn Node<K, V>>; 257],
}

impl<
    K: Debug + Copy + Send + Sync + FromScalar + Into<Scalar> + 'static,
    V: Debug + Default + Clone + Send + Sync + AsScalar + 'static,
> PhantomNodes<K, V>
{
    fn get(&self, level: usize) -> Arc<dyn Node<K, V>> {
        self.nodes[level].clone()
    }
}

impl<
    K: Debug + Copy + Send + Sync + FromScalar + Into<Scalar> + 'static,
    V: Debug + Default + Clone + Send + Sync + AsScalar + 'static,
> Default for PhantomNodes<K, V>
{
    fn default() -> Self {
        let mut nodes = vec![];
        let mut node: Arc<dyn Node<K, V>> = Arc::new(Leaf::new(V::default()));
        nodes.push(node.clone());
        for level in 1..=256 {
            node = Arc::new(InternalNode::new(level, node.clone(), node.clone()));
            nodes.push(node.clone());
        }
        Self {
            nodes: nodes.try_into().unwrap(),
        }
    }
}

#[derive(Debug, Default)]
struct MonomorphicPhantomNodes {
    map: Mutex<BTreeMap<TypeId, Arc<dyn Any + Send + Sync>>>,
}

impl MonomorphicPhantomNodes {
    fn get<
        K: Debug + Copy + Send + Sync + FromScalar + Into<Scalar> + 'static,
        V: Debug + Default + Clone + Send + Sync + AsScalar + 'static,
    >(
        &self,
        level: usize,
    ) -> Arc<dyn Node<K, V>> {
        let id = TypeId::of::<(K, V)>();
        {
            let map = self.map.lock().unwrap();
            if let Some(nodes) = map.get(&id) {
                return nodes
                    .clone()
                    .downcast::<PhantomNodes<K, V>>()
                    .unwrap()
                    .get(level);
            }
        }
        // The new PhantomNodes instance MUST be constructed outside of the lock because `V` may be
        // a nested Merkle tree whose default construction would again call into here and cause
        // reentrancy.
        //
        // NOTE: we'll be able to simplify this code when Rust provides a reentrant lock
        // implementation (see https://github.com/rust-lang/rust/issues/121440).
        let nodes = Arc::new(PhantomNodes::<K, V>::default());
        {
            let mut map = self.map.lock().unwrap();
            if !map.contains_key(&id) {
                map.insert(id, nodes);
            }
            map.get(&id).unwrap().clone()
        }
        .downcast::<PhantomNodes<K, V>>()
        .unwrap()
        .get(level)
    }
}

static PHANTOM_NODES: LazyLock<MonomorphicPhantomNodes> =
    LazyLock::new(|| MonomorphicPhantomNodes::default());

#[derive(Debug, Clone)]
struct Leaf<
    K: Debug + Copy + Send + Sync + FromScalar + Into<Scalar> + 'static,
    V: Debug + Default + Clone + Send + Sync + AsScalar + 'static,
> {
    value: V,
    hash: Scalar,
    _key: PhantomData<K>,
}

impl<
    K: Debug + Copy + Send + Sync + FromScalar + Into<Scalar> + 'static,
    V: Debug + Default + Clone + Send + Sync + AsScalar + 'static,
> Leaf<K, V>
{
    fn new(value: V) -> Self {
        let hash = utils::poseidon_hash([value.as_scalar()]);
        Self {
            value,
            hash,
            _key: PhantomData {},
        }
    }
}

impl<
    K: Debug + Copy + Send + Sync + FromScalar + Into<Scalar> + 'static,
    V: Debug + Default + Clone + Send + Sync + AsScalar + 'static,
> Node<K, V> for Leaf<K, V>
{
    fn get(&self, _key: K) -> &V {
        &self.value
    }

    fn lookup(&self, _key: K) -> (&V, Vec<(Scalar, Scalar)>) {
        (&self.value, vec![])
    }

    fn put(&self, _key: K, value: V) -> Arc<dyn Node<K, V>> {
        Arc::new(Self::new(value))
    }
}

impl<
    K: Debug + Copy + Send + Sync + FromScalar + Into<Scalar> + 'static,
    V: Debug + Default + Clone + Send + Sync + AsScalar + 'static,
> PoseidonHash for Leaf<K, V>
{
    fn poseidon_hash(&self) -> Scalar {
        self.hash
    }
}

impl<
    K: Debug + Copy + Send + Sync + FromScalar + Into<Scalar> + 'static,
    V: Debug + Default + Clone + Send + Sync + AsScalar + 'static,
> AsScalar for Leaf<K, V>
{
    fn as_scalar(&self) -> Scalar {
        self.hash
    }
}

#[derive(Debug, Clone)]
struct InternalNode<
    K: Debug + Copy + Send + Sync + FromScalar + Into<Scalar> + 'static,
    V: Debug + Default + Clone + Send + Sync + AsScalar + 'static,
> {
    // TODO: convert `level` to a generic const argument when Rust supports generic const argument
    // expressions. See <https://github.com/rust-lang/rust/issues/76560>.
    level: usize,
    left: Arc<dyn Node<K, V>>,
    right: Arc<dyn Node<K, V>>,
    hash: Scalar,
}

impl<
    K: Debug + Copy + Send + Sync + FromScalar + Into<Scalar> + 'static,
    V: Debug + Default + Clone + Send + Sync + AsScalar + 'static,
> InternalNode<K, V>
{
    fn new(level: usize, left: Arc<dyn Node<K, V>>, right: Arc<dyn Node<K, V>>) -> Self {
        let hash = utils::poseidon_hash([left.poseidon_hash(), right.poseidon_hash()]);
        Self {
            level,
            left,
            right,
            hash,
        }
    }

    fn get_bit(&self, key: K) -> bool {
        let count = Scalar::from((self.level - 1) as u64);
        bits::and1(bits::shr(key.into(), count)) != Scalar::ZERO
    }
}

impl<
    K: Debug + Copy + Send + Sync + FromScalar + Into<Scalar> + 'static,
    V: Debug + Default + Clone + Send + Sync + AsScalar + 'static,
> Node<K, V> for InternalNode<K, V>
{
    fn get(&self, key: K) -> &V {
        if self.get_bit(key) {
            self.right.get(key)
        } else {
            self.left.get(key)
        }
    }

    fn lookup(&self, key: K) -> (&V, Vec<(Scalar, Scalar)>) {
        let (value, mut path) = if self.get_bit(key) {
            self.right.lookup(key)
        } else {
            self.left.lookup(key)
        };
        path.push((self.left.poseidon_hash(), self.right.poseidon_hash()));
        (value, path)
    }

    fn put(&self, key: K, value: V) -> Arc<dyn Node<K, V>> {
        let (left, right) = if self.get_bit(key) {
            (self.left.clone(), self.right.put(key, value))
        } else {
            (self.left.put(key, value), self.right.clone())
        };
        Arc::new(Self::new(self.level, left, right))
    }
}

impl<
    K: Debug + Copy + Send + Sync + FromScalar + Into<Scalar> + 'static,
    V: Debug + Default + Clone + Send + Sync + AsScalar + 'static,
> PoseidonHash for InternalNode<K, V>
{
    fn poseidon_hash(&self) -> Scalar {
        self.hash
    }
}

impl<
    K: Debug + Copy + Send + Sync + FromScalar + Into<Scalar> + 'static,
    V: Debug + Default + Clone + Send + Sync + AsScalar + 'static,
> AsScalar for InternalNode<K, V>
{
    fn as_scalar(&self) -> Scalar {
        self.hash
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleProof<K: Debug + Copy + Send + Sync + FromScalar + Into<Scalar> + 'static> {
    key: K,
    value_as_scalar: Scalar,
    path: [(Scalar, Scalar); 256],
    root_hash: Scalar,
}

impl<K: Debug + Copy + Send + Sync + FromScalar + Into<Scalar> + 'static> MerkleProof<K> {
    pub fn key(&self) -> K {
        self.key
    }

    pub fn value_as_scalar(&self) -> Scalar {
        self.value_as_scalar
    }

    pub fn path(&self) -> &[(Scalar, Scalar); 256] {
        &self.path
    }

    pub fn root_hash(&self) -> Scalar {
        self.root_hash
    }

    pub fn verify(&self, root_hash: Scalar) -> Result<()> {
        if root_hash != self.root_hash {
            return Err(anyhow!(
                "root hash mismatch: got {:#x}, want {:#x}",
                utils::pallas_scalar_to_u256(self.root_hash),
                utils::pallas_scalar_to_u256(root_hash)
            ));
        }
        let mut key = self.key.into();
        let mut hash = utils::poseidon_hash([self.value_as_scalar]);
        for (left, right) in self.path {
            let bit = bits::and1(key);
            let not = Scalar::from(1) - bit;
            if bit * (hash - right) + not * (hash - left) != Scalar::ZERO {
                return Err(anyhow!(
                    "hash mismatch: got {:#x} or {:#x}, want {:#x}",
                    utils::pallas_scalar_to_u256(left),
                    utils::pallas_scalar_to_u256(right),
                    utils::pallas_scalar_to_u256(hash),
                ));
            }
            key = bits::shr(key, 1.into());
            hash = utils::poseidon_hash([left, right]);
        }
        if hash != self.root_hash {
            return Err(anyhow!(
                "final hash mismatch: got {:#x}, want {:#x}",
                utils::pallas_scalar_to_u256(self.root_hash),
                utils::pallas_scalar_to_u256(hash),
            ));
        }
        Ok(())
    }
}

impl<K: Debug + Copy + Send + Sync + FromScalar + Into<Scalar> + 'static> MerkleProof<K> {
    /// Encodes this proof into a `MerkleProof` protobuf. Note that the block descriptor must be
    /// provided by the caller.
    pub fn encode(
        &self,
        block_descriptor: dotakon::BlockDescriptor,
    ) -> Result<dotakon::MerkleProof> {
        Ok(dotakon::MerkleProof {
            block_descriptor: Some(block_descriptor),
            key: Some(proto::pallas_scalar_to_bytes32(self.key.into())),
            value: Some(prost_types::Any::from_msg(
                &proto::pallas_scalar_to_bytes32(self.value_as_scalar),
            )?),
            path: self
                .path
                .iter()
                .map(|(left, right)| dotakon::merkle_proof::Node {
                    left_child_hash: Some(proto::pallas_scalar_to_bytes32(*left)),
                    right_child_hash: Some(proto::pallas_scalar_to_bytes32(*right)),
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
        let key = proto::pallas_scalar_from_bytes32(&proto.key.unwrap())?;
        let key = K::from_scalar(key)?;
        if proto.value.is_none() {
            return Err(anyhow!("invalid Merkle proof: the value is missing"));
        }
        let value_as_scalar = proto.value.as_ref().unwrap().to_msg::<dotakon::Bytes32>()?;
        let value_as_scalar = proto::pallas_scalar_from_bytes32(&value_as_scalar)?;
        let path: [(Scalar, Scalar); 256] = proto
            .path
            .iter()
            .map(|node| {
                let left = {
                    if let Some(left_child_hash) = &node.left_child_hash {
                        proto::pallas_scalar_from_bytes32(&left_child_hash)?
                    } else {
                        return Err(anyhow!("invalid Merkle proof: missing left child hash"));
                    }
                };
                let right = {
                    if let Some(right_child_hash) = &node.right_child_hash {
                        proto::pallas_scalar_from_bytes32(&right_child_hash)?
                    } else {
                        return Err(anyhow!("invalid Merkle proof: missing right child hash"));
                    }
                };
                Ok((left, right))
            })
            .collect::<Result<Vec<_>>>()?
            .try_into()
            .map_err(|vec: Vec<(Scalar, Scalar)>| {
                anyhow!(
                    "invalid Merkle proof: incorrect lookup path length (got {}, want 256)",
                    vec.len()
                )
            })?;
        let (left, right) = path[255];
        let root_hash = utils::poseidon_hash([left, right]);
        Ok(Self {
            key,
            value_as_scalar,
            path,
            root_hash,
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

#[derive(Debug, Clone)]
pub struct LookupChipConfig {
    key: plonk::Column<plonk::Advice>,
    left: plonk::Column<plonk::Advice>,
    right: plonk::Column<plonk::Advice>,
    hash: plonk::Column<plonk::Advice>,
    full_bit_decomposer: chips::FullBitDecomposerConfig,
    poseidon: chips::PoseidonConfig,
    step_selector: plonk::Selector,
}

#[derive(Debug)]
pub struct LookupChip {
    config: LookupChipConfig,
}

impl LookupChip {
    pub fn configure(
        cs: &mut plonk::ConstraintSystem<Scalar>,
        full_bit_decomposer: chips::FullBitDecomposerConfig,
        poseidon: chips::PoseidonConfig,
    ) -> LookupChipConfig {
        let key = cs.advice_column();
        cs.enable_equality(key);
        let left = cs.advice_column();
        cs.enable_equality(left);
        let right = cs.advice_column();
        cs.enable_equality(right);
        let hash = cs.advice_column();
        cs.enable_equality(hash);
        let step_selector = cs.selector();
        cs.create_gate("step", |cells| {
            let selector = cells.query_selector(step_selector);
            let bit = cells.query_advice(key, poly::Rotation::cur());
            let left = cells.query_advice(left, poly::Rotation::cur());
            let right = cells.query_advice(right, poly::Rotation::cur());
            let hash = cells.query_advice(hash, poly::Rotation::cur());
            let not = plonk::Expression::Constant(1.into()) - bit.clone();
            vec![selector * (bit * (hash.clone() - right) + not * (hash - left))]
        });
        LookupChipConfig {
            key,
            left,
            right,
            hash,
            full_bit_decomposer,
            poseidon,
            step_selector,
        }
    }

    pub fn construct(config: LookupChipConfig) -> Self {
        Self { config }
    }

    pub fn assign<K: Debug + Copy + Send + Sync + FromScalar + Into<Scalar> + 'static>(
        &self,
        layouter: &mut impl circuit::Layouter<Scalar>,
        root_hash: circuit::AssignedCell<Scalar, Scalar>,
        key: circuit::AssignedCell<Scalar, Scalar>,
        merkle_proof: &MerkleProof<K>,
    ) -> Result<circuit::AssignedCell<Scalar, Scalar>, plonk::Error> {
        let bit_decomposer =
            chips::FullBitDecomposerChip::construct(self.config.full_bit_decomposer.clone());
        let key_bits = bit_decomposer.assign(layouter, key)?;
        let value = layouter.assign_region(
            || "load_value",
            |mut region| {
                region.assign_advice(
                    || "load_value",
                    self.config.left,
                    0,
                    || circuit::Value::known(merkle_proof.value_as_scalar()),
                )
            },
        )?;
        let poseidon = chips::PoseidonChip::<1>::construct(self.config.poseidon.clone());
        let mut hash =
            poseidon.assign(&mut layouter.namespace(|| "hash_value"), [value.clone()])?;
        let poseidon = chips::PoseidonChip::<2>::construct(self.config.poseidon.clone());
        let path = merkle_proof.path();
        for i in 0..256 {
            let (left, right) = layouter.assign_region(
                || "step",
                |mut region| {
                    self.config.step_selector.enable(&mut region, 0)?;
                    let key_bit = region.assign_advice(
                        || format!("key[{}]", i),
                        self.config.key,
                        0,
                        || key_bits[i].value().cloned(),
                    )?;
                    region.constrain_equal(key_bit.cell(), key_bits[i].cell())?;
                    let (left, right) = path[i];
                    let left = region.assign_advice(
                        || format!("left[{}]", i),
                        self.config.left,
                        0,
                        || circuit::Value::known(left),
                    )?;
                    let right = region.assign_advice(
                        || format!("right[{}]", i),
                        self.config.right,
                        0,
                        || circuit::Value::known(right),
                    )?;
                    let hash2 = region.assign_advice(
                        || format!("load_hash[{}]", i),
                        self.config.hash,
                        0,
                        || hash.value().cloned(),
                    )?;
                    region.constrain_equal(hash.cell(), hash2.cell())?;
                    Ok((left, right))
                },
            )?;
            hash = poseidon.assign(
                &mut layouter.namespace(|| format!("hash[{}]", i)),
                [left, right],
            )?;
        }
        layouter.assign_region(
            || "check_root",
            |mut region| region.constrain_equal(hash.cell(), root_hash.cell()),
        )?;
        Ok(value)
    }
}

impl circuit::Chip<Scalar> for LookupChip {
    type Config = LookupChipConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

#[derive(Debug, Clone)]
pub struct MerkleTreeVersion<
    K: Debug + Copy + Send + Sync + FromScalar + Into<Scalar> + 'static,
    V: Debug + Default + Clone + Send + Sync + AsScalar + 'static,
> {
    root: Arc<dyn Node<K, V>>,
}

impl<
    K: Debug + Copy + Send + Sync + FromScalar + Into<Scalar> + 'static,
    V: Debug + Default + Clone + Send + Sync + AsScalar + 'static,
> MerkleTreeVersion<K, V>
{
    pub fn root_hash(&self) -> Scalar {
        self.root.poseidon_hash()
    }

    pub fn get(&self, key: K) -> &V {
        self.root.get(key)
    }

    pub fn get_proof(&self, key: K) -> MerkleProof<K> {
        let (value, path) = self.root.lookup(key);
        MerkleProof {
            key,
            value_as_scalar: value.as_scalar(),
            path: path.try_into().unwrap(),
            root_hash: self.root.poseidon_hash(),
        }
    }

    fn put(&self, key: K, value: V) -> Self {
        Self {
            root: self.root.put(key, value),
        }
    }
}

impl<
    K: Debug + Copy + Send + Sync + FromScalar + Into<Scalar> + 'static,
    V: Debug + Default + Clone + Send + Sync + AsScalar + 'static,
> Default for MerkleTreeVersion<K, V>
{
    fn default() -> Self {
        Self {
            root: PHANTOM_NODES.get(256),
        }
    }
}

impl<
    K: Debug + Copy + Send + Sync + FromScalar + Into<Scalar> + 'static,
    V: Debug + Default + Clone + Send + Sync + AsScalar + 'static,
> AsScalar for MerkleTreeVersion<K, V>
{
    fn as_scalar(&self) -> Scalar {
        self.root_hash()
    }
}

impl<
    K: Debug + Copy + Send + Sync + FromScalar + Into<Scalar> + 'static,
    V: Debug + Default + Clone + Send + Sync + AsScalar + 'static,
> PoseidonHash for MerkleTreeVersion<K, V>
{
    fn poseidon_hash(&self) -> Scalar {
        self.root_hash()
    }
}

#[derive(Debug, Clone)]
pub struct MerkleTree<
    K: Debug + Copy + Send + Sync + FromScalar + Into<Scalar> + 'static,
    V: Debug + Default + Clone + Send + Sync + AsScalar + 'static,
> {
    versions: BTreeMap<u64, MerkleTreeVersion<K, V>>,
}

impl<
    K: Debug + Copy + Send + Sync + FromScalar + Into<Scalar> + 'static,
    V: Debug + Default + Clone + Send + Sync + AsScalar + 'static,
> MerkleTree<K, V>
{
    pub fn get_version(&self, version: u64) -> &MerkleTreeVersion<K, V> {
        let (_, version) = self.versions.range(0..=version).next_back().unwrap();
        version
    }

    pub fn root_hash(&self, version: u64) -> Scalar {
        let (_, version) = self.versions.range(0..=version).next_back().unwrap();
        version.root_hash()
    }

    pub fn get(&self, key: K, version: u64) -> &V {
        let (_, version) = self.versions.range(0..=version).next_back().unwrap();
        version.get(key)
    }

    pub fn get_proof(&self, key: K, version: u64) -> MerkleProof<K> {
        let (_, version) = self.versions.range(0..=version).next_back().unwrap();
        version.get_proof(key)
    }

    pub fn put(&mut self, key: K, value: V, version: u64) {
        let (_, root) = self.versions.range_mut(0..=version).next_back().unwrap();
        let new_root = root.put(key, value);
        if new_root.poseidon_hash() != root.poseidon_hash() {
            self.versions.insert(version, new_root);
        }
    }
}

impl<
    K: Debug + Copy + Send + Sync + FromScalar + Into<Scalar> + 'static,
    V: Debug + Default + Clone + Send + Sync + AsScalar + 'static,
> Default for MerkleTree<K, V>
{
    fn default() -> Self {
        Self {
            versions: BTreeMap::from([(0, MerkleTreeVersion::default())]),
        }
    }
}

pub type AccountBalanceTree = MerkleTree<Scalar, Scalar>;
pub type AccountBalanceProof = MerkleProof<Scalar>;

pub type ProgramStorageTree = MerkleTree<Scalar, MerkleTreeVersion<u64, u64>>;
pub type ProgramStorageProof = MerkleProof<u64>;

#[cfg(test)]
mod tests {
    use crate::utils::testing_keys1;

    use super::*;
    use ff::PrimeField;

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
    fn test_initial_root_hash() {
        let tree = AccountBalanceTree::default();
        let hash = utils::parse_pallas_scalar(
            "0x3eff13934bf9e1844f467dc1fe60c686da504238cfaee6c4e63ada8891727491",
        );
        assert_eq!(tree.root_hash(0), hash);
        assert_eq!(tree.root_hash(1), hash);
        assert_eq!(tree.root_hash(2), hash);
    }

    fn test_initial_state(key: Scalar, version: u64) {
        let tree = AccountBalanceTree::default();
        assert_eq!(*tree.get(key, version), Scalar::ZERO);
        let proof = tree.get_proof(key, version);
        assert_eq!(proof.key(), key);
        assert_eq!(proof.value_as_scalar(), Scalar::ZERO);
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
        assert_eq!(*tree.get(key1, 0), value);
        assert_eq!(*tree.get(key1, 1), value);
        assert_eq!(*tree.get(key1, 2), value);
        let proof1 = tree.get_proof(key1, 0);
        assert_eq!(proof1.key(), key1);
        assert_eq!(proof1.value_as_scalar(), value);
        assert_eq!(proof1.root_hash(), tree.root_hash(0));
        assert_eq!(proof1.root_hash(), tree.root_hash(1));
        assert_eq!(proof1.root_hash(), tree.root_hash(2));
        assert!(proof1.verify(tree.root_hash(0)).is_ok());
        assert_eq!(tree.get_proof(key1, 1), proof1);
        assert_eq!(tree.get_proof(key1, 2), proof1);
        assert_eq!(*tree.get(key2, 0), Scalar::ZERO);
        assert_eq!(*tree.get(key2, 1), Scalar::ZERO);
        assert_eq!(*tree.get(key2, 2), Scalar::ZERO);
        let proof2 = tree.get_proof(key2, 0);
        assert_eq!(proof2.key(), key2);
        assert_eq!(proof2.value_as_scalar(), Scalar::ZERO);
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
        assert_eq!(*tree.get(key1, 0), value1);
        assert_eq!(*tree.get(key1, 1), value1);
        assert_eq!(*tree.get(key1, 2), value1);
        let proof1 = tree.get_proof(key1, 0);
        assert_eq!(proof1.key(), key1);
        assert_eq!(proof1.value_as_scalar(), value1);
        assert_eq!(proof1.root_hash(), tree.root_hash(0));
        assert_eq!(proof1.root_hash(), tree.root_hash(1));
        assert_eq!(proof1.root_hash(), tree.root_hash(2));
        assert!(proof1.verify(tree.root_hash(0)).is_ok());
        assert_eq!(tree.get_proof(key1, 1), proof1);
        assert_eq!(tree.get_proof(key1, 2), proof1);
        assert_eq!(*tree.get(key2, 0), value2);
        assert_eq!(*tree.get(key2, 1), value2);
        assert_eq!(*tree.get(key2, 2), value2);
        let proof2 = tree.get_proof(key2, 0);
        assert_eq!(proof2.key(), key2);
        assert_eq!(proof2.value_as_scalar(), value2);
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
        assert_eq!(*tree.get(key1, 0), value1);
        assert_eq!(*tree.get(key1, 1), value1);
        assert_eq!(*tree.get(key1, 2), value1);
        let proof1 = tree.get_proof(key1, 0);
        assert_eq!(proof1.key(), key1);
        assert_eq!(proof1.value_as_scalar(), value1);
        assert_eq!(proof1.root_hash(), tree.root_hash(0));
        assert_eq!(proof1.root_hash(), tree.root_hash(1));
        assert_eq!(proof1.root_hash(), tree.root_hash(2));
        assert!(proof1.verify(tree.root_hash(0)).is_ok());
        assert_eq!(tree.get_proof(key1, 1), proof1);
        assert_eq!(tree.get_proof(key1, 2), proof1);
        assert_eq!(*tree.get(key2, 0), value2);
        assert_eq!(*tree.get(key2, 1), value2);
        assert_eq!(*tree.get(key2, 2), value2);
        let proof2 = tree.get_proof(key2, 0);
        assert_eq!(proof2.key(), key2);
        assert_eq!(proof2.value_as_scalar(), value2);
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
        assert_eq!(*tree.get(value1, 0), value1);
        assert_eq!(*tree.get(value1, 1), value1);
        assert_eq!(*tree.get(value1, 2), value1);
        let proof1 = tree.get_proof(value1, 0);
        assert_eq!(proof1.key(), value1);
        assert_eq!(proof1.value_as_scalar(), value1);
        assert_eq!(proof1.root_hash(), tree.root_hash(0));
        assert_eq!(proof1.root_hash(), tree.root_hash(1));
        assert_eq!(proof1.root_hash(), tree.root_hash(2));
        assert!(proof1.verify(tree.root_hash(0)).is_ok());
        assert_eq!(tree.get_proof(value1, 1), proof1);
        assert_eq!(tree.get_proof(value1, 2), proof1);
        assert_eq!(*tree.get(value2, 0), value2);
        assert_eq!(*tree.get(value2, 1), value2);
        assert_eq!(*tree.get(value2, 2), value2);
        let proof2 = tree.get_proof(value2, 0);
        assert_eq!(proof2.key(), value2);
        assert_eq!(proof2.value_as_scalar(), value2);
        assert_eq!(proof2.root_hash(), tree.root_hash(0));
        assert_eq!(proof2.root_hash(), tree.root_hash(1));
        assert_eq!(proof2.root_hash(), tree.root_hash(2));
        assert!(proof2.verify(tree.root_hash(0)).is_ok());
        assert_eq!(tree.get_proof(value2, 1), proof2);
        assert_eq!(tree.get_proof(value2, 2), proof2);
        assert_eq!(*tree.get(value3, 0), value3);
        assert_eq!(*tree.get(value3, 1), value3);
        assert_eq!(*tree.get(value3, 2), value3);
        let proof3 = tree.get_proof(value3, 0);
        assert_eq!(proof3.key(), value3);
        assert_eq!(proof3.value_as_scalar(), value3);
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
        assert_eq!(*tree.get(key1, 0), value2);
        assert_eq!(*tree.get(key1, 1), value2);
        assert_eq!(*tree.get(key1, 2), value2);
        let proof1 = tree.get_proof(key1, 0);
        assert_eq!(proof1.key(), key1);
        assert_eq!(proof1.value_as_scalar(), value2);
        assert_eq!(proof1.root_hash(), tree.root_hash(0));
        assert_eq!(proof1.root_hash(), tree.root_hash(1));
        assert_eq!(proof1.root_hash(), tree.root_hash(2));
        assert!(proof1.verify(tree.root_hash(0)).is_ok());
        assert_eq!(tree.get_proof(key1, 1), proof1);
        assert_eq!(tree.get_proof(key1, 2), proof1);
        assert_eq!(*tree.get(key2, 0), Scalar::ZERO);
        assert_eq!(*tree.get(key2, 1), Scalar::ZERO);
        assert_eq!(*tree.get(key2, 2), Scalar::ZERO);
        let proof2 = tree.get_proof(key2, 0);
        assert_eq!(proof2.key(), key2);
        assert_eq!(proof2.value_as_scalar(), Scalar::ZERO);
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
        assert_eq!(*tree.get(key1, 0), value1);
        assert_eq!(*tree.get(key1, 1), value2);
        assert_eq!(*tree.get(key1, 2), value2);
        let proof11 = tree.get_proof(key1, 0);
        assert_eq!(proof11.key(), key1);
        assert_eq!(proof11.value_as_scalar(), value1);
        assert_eq!(proof11.root_hash(), tree.root_hash(0));
        assert_ne!(proof11.root_hash(), tree.root_hash(1));
        assert_ne!(proof11.root_hash(), tree.root_hash(2));
        assert!(proof11.verify(tree.root_hash(0)).is_ok());
        assert!(proof11.verify(tree.root_hash(1)).is_err());
        let proof12 = tree.get_proof(key1, 1);
        assert_eq!(proof12.key(), key1);
        assert_eq!(proof12.value_as_scalar(), value2);
        assert_ne!(proof12.root_hash(), tree.root_hash(0));
        assert_eq!(proof12.root_hash(), tree.root_hash(1));
        assert_eq!(proof12.root_hash(), tree.root_hash(2));
        assert!(proof12.verify(tree.root_hash(0)).is_err());
        assert!(proof12.verify(tree.root_hash(1)).is_ok());
        assert_eq!(tree.get_proof(key1, 2), proof12);
        assert_eq!(*tree.get(key2, 0), Scalar::ZERO);
        assert_eq!(*tree.get(key2, 1), Scalar::ZERO);
        assert_eq!(*tree.get(key2, 2), Scalar::ZERO);
        let proof21 = tree.get_proof(key2, 0);
        assert_eq!(proof21.key(), key2);
        assert_eq!(proof21.value_as_scalar(), Scalar::ZERO);
        assert_eq!(proof21.root_hash(), tree.root_hash(0));
        assert_ne!(proof21.root_hash(), tree.root_hash(1));
        assert_ne!(proof21.root_hash(), tree.root_hash(2));
        assert!(proof21.verify(tree.root_hash(0)).is_ok());
        assert!(proof21.verify(tree.root_hash(1)).is_err());
        let proof22 = tree.get_proof(key2, 1);
        assert_eq!(proof22.key(), key2);
        assert_eq!(proof22.value_as_scalar(), Scalar::ZERO);
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
        assert_eq!(*tree.get(key1, 0), value1);
        assert_eq!(*tree.get(key1, 1), value1);
        assert_eq!(*tree.get(key1, 2), value2);
        let proof11 = tree.get_proof(key1, 0);
        assert_eq!(proof11.key(), key1);
        assert_eq!(proof11.value_as_scalar(), value1);
        assert_eq!(proof11.root_hash(), tree.root_hash(0));
        assert_eq!(proof11.root_hash(), tree.root_hash(1));
        assert_ne!(proof11.root_hash(), tree.root_hash(2));
        assert!(proof11.verify(tree.root_hash(0)).is_ok());
        assert!(proof11.verify(tree.root_hash(1)).is_ok());
        assert!(proof11.verify(tree.root_hash(2)).is_err());
        let proof12 = tree.get_proof(key1, 2);
        assert_eq!(proof12.key(), key1);
        assert_eq!(proof12.value_as_scalar(), value2);
        assert_ne!(proof12.root_hash(), tree.root_hash(0));
        assert_ne!(proof12.root_hash(), tree.root_hash(1));
        assert_eq!(proof12.root_hash(), tree.root_hash(2));
        assert!(proof12.verify(tree.root_hash(0)).is_err());
        assert!(proof12.verify(tree.root_hash(1)).is_err());
        assert!(proof12.verify(tree.root_hash(2)).is_ok());
        assert_eq!(tree.get_proof(key1, 1), proof11);
        assert_eq!(*tree.get(key2, 0), Scalar::ZERO);
        assert_eq!(*tree.get(key2, 1), Scalar::ZERO);
        assert_eq!(*tree.get(key2, 2), Scalar::ZERO);
        let proof21 = tree.get_proof(key2, 0);
        assert_eq!(proof21.key(), key2);
        assert_eq!(proof21.value_as_scalar(), Scalar::ZERO);
        assert_eq!(proof21.root_hash(), tree.root_hash(0));
        assert_eq!(proof21.root_hash(), tree.root_hash(1));
        assert_ne!(proof21.root_hash(), tree.root_hash(2));
        assert!(proof21.verify(tree.root_hash(0)).is_ok());
        assert!(proof21.verify(tree.root_hash(1)).is_ok());
        assert!(proof21.verify(tree.root_hash(2)).is_err());
        let proof22 = tree.get_proof(key2, 2);
        assert_eq!(proof22.key(), key2);
        assert_eq!(proof22.value_as_scalar(), Scalar::ZERO);
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
        assert_eq!(*tree.get(key1, 0), value1);
        assert_eq!(*tree.get(key1, 1), value1);
        assert_eq!(*tree.get(key1, 2), value1);
        let proof11 = tree.get_proof(key1, 0);
        assert_eq!(proof11.key(), key1);
        assert_eq!(proof11.value_as_scalar(), value1.clone());
        assert_eq!(proof11.root_hash(), tree.root_hash(0));
        assert_eq!(proof11.root_hash(), tree.root_hash(1));
        assert_ne!(proof11.root_hash(), tree.root_hash(2));
        assert!(proof11.verify(tree.root_hash(0)).is_ok());
        assert!(proof11.verify(tree.root_hash(1)).is_ok());
        assert!(proof11.verify(tree.root_hash(2)).is_err());
        let proof12 = tree.get_proof(key1, 2);
        assert_eq!(proof12.key(), key1);
        assert_eq!(proof12.value_as_scalar(), value1);
        assert_ne!(proof12.root_hash(), tree.root_hash(0));
        assert_ne!(proof12.root_hash(), tree.root_hash(1));
        assert_eq!(proof12.root_hash(), tree.root_hash(2));
        assert!(proof12.verify(tree.root_hash(0)).is_err());
        assert!(proof12.verify(tree.root_hash(1)).is_err());
        assert!(proof12.verify(tree.root_hash(2)).is_ok());
        assert_eq!(tree.get_proof(key1, 1), proof11);
        assert_eq!(*tree.get(key2, 0), value2);
        assert_eq!(*tree.get(key2, 1), value2);
        assert_eq!(*tree.get(key2, 2), value3);
        let proof21 = tree.get_proof(key2, 0);
        assert_eq!(proof21.key(), key2);
        assert_eq!(proof21.value_as_scalar(), value2);
        assert_eq!(proof21.root_hash(), tree.root_hash(0));
        assert_eq!(proof21.root_hash(), tree.root_hash(1));
        assert_ne!(proof21.root_hash(), tree.root_hash(2));
        assert!(proof21.verify(tree.root_hash(0)).is_ok());
        assert!(proof21.verify(tree.root_hash(1)).is_ok());
        assert!(proof21.verify(tree.root_hash(2)).is_err());
        let proof22 = tree.get_proof(key2, 2);
        assert_eq!(proof22.key(), key2);
        assert_eq!(proof22.value_as_scalar(), value3);
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
        proto.path[123].left_child_hash = Some(proto::pallas_scalar_to_bytes32(Scalar::ZERO));
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
        proto.path[123].left_child_hash = Some(proto::pallas_scalar_to_bytes32(Scalar::ZERO));
        assert!(AccountBalanceProof::decode_and_verify(&proto, tree.root_hash(0)).is_err());
    }

    #[test]
    fn test_decode_invalid_proof() {
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
        assert!(AccountBalanceProof::decode(&proto).is_err());
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
        assert_eq!(*tree.get(key1, 0), value3);
        assert_eq!(*tree.get(key1, 1), value1);
        assert_eq!(*tree.get(key1, 2), value1);
        assert_eq!(*tree.get(key2, 0), Scalar::ZERO);
        assert_eq!(*tree.get(key2, 1), value2);
        assert_eq!(*tree.get(key2, 2), value2);
        assert_eq!(*tree.get(key3, 0), value3);
        assert_eq!(*tree.get(key3, 1), Scalar::ZERO);
        assert_eq!(*tree.get(key3, 2), Scalar::ZERO);
    }

    #[derive(Debug, Clone)]
    struct LookupCircuitConfig {
        root_hash: plonk::Column<plonk::Instance>,
        key: plonk::Column<plonk::Instance>,
        value: plonk::Column<plonk::Instance>,
        chip: LookupChipConfig,
    }

    #[derive(Debug)]
    struct LookupCircuit {
        merkle_proof: MerkleProof<Scalar>,
    }

    impl LookupCircuit {
        fn verify(
            tree: &MerkleTreeVersion<Scalar, Scalar>,
            key: Scalar,
            value: Scalar,
        ) -> Result<()> {
            let merkle_proof = tree.get_proof(key);
            let circuit = LookupCircuit { merkle_proof };
            utils::test::verify_circuit(
                14,
                &circuit,
                vec![vec![tree.root_hash()], vec![key], vec![value]],
            )
        }
    }

    impl Default for LookupCircuit {
        fn default() -> Self {
            Self {
                merkle_proof: MerkleProof {
                    key: Scalar::ZERO,
                    value_as_scalar: Scalar::ZERO,
                    path: [(Scalar::ZERO, Scalar::ZERO); 256],
                    root_hash: Scalar::ZERO,
                },
            }
        }
    }

    impl plonk::Circuit<Scalar> for LookupCircuit {
        type Config = LookupCircuitConfig;
        type FloorPlanner = circuit::floor_planner::V1;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(cs: &mut plonk::ConstraintSystem<Scalar>) -> Self::Config {
            let root_hash = cs.instance_column();
            cs.enable_equality(root_hash);
            let key = cs.instance_column();
            cs.enable_equality(key);
            let value = cs.instance_column();
            cs.enable_equality(value);
            let binary_digits = cs.fixed_column();
            let key_to_decompose = cs.advice_column();
            let bits = std::array::from_fn(|_| cs.advice_column());
            let full_bit_decomposer =
                chips::FullBitDecomposerChip::configure(cs, binary_digits, key_to_decompose, bits);
            let poseidon = chips::configure_poseidon(cs);
            let chip = LookupChip::configure(cs, full_bit_decomposer, poseidon);
            LookupCircuitConfig {
                root_hash,
                key,
                value,
                chip,
            }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl circuit::Layouter<Scalar>,
        ) -> Result<(), plonk::Error> {
            let (root_hash, key) = layouter.assign_region(
                || "load",
                |mut region| {
                    let root_hash = region.assign_advice_from_instance(
                        || "load_root_hash",
                        config.root_hash,
                        0,
                        config.chip.hash,
                        0,
                    )?;
                    let key = region.assign_advice_from_instance(
                        || "load_key",
                        config.key,
                        0,
                        config.chip.key,
                        0,
                    )?;
                    Ok((root_hash, key))
                },
            )?;
            let chip = LookupChip::construct(config.chip.clone());
            let value = chip.assign(
                &mut layouter.namespace(|| "lookup"),
                root_hash,
                key,
                &self.merkle_proof,
            )?;
            layouter.assign_region(
                || "check_value",
                |mut region| {
                    let expected = region.assign_advice_from_instance(
                        || "load_value",
                        config.value,
                        0,
                        config.chip.hash,
                        0,
                    )?;
                    region.constrain_equal(value.cell(), expected.cell())
                },
            )?;
            Ok(())
        }
    }

    #[test]
    fn test_empty_tree_zk_lookup() {
        let tree = AccountBalanceTree::default();
        let key = test_scalar1();
        assert!(LookupCircuit::verify(tree.get_version(0), key, Scalar::ZERO).is_ok());
        assert!(LookupCircuit::verify(tree.get_version(0), key, test_scalar2()).is_err());
    }

    #[test]
    fn test_zk_lookup() {
        let mut tree = AccountBalanceTree::default();
        let key = test_scalar1();
        let value = test_scalar2();
        tree.put(key, value, 0);
        assert!(LookupCircuit::verify(tree.get_version(0), key, Scalar::ZERO).is_err());
        assert!(LookupCircuit::verify(tree.get_version(0), key, test_scalar2()).is_ok());
    }
}
