use anyhow::{Context, Result, anyhow};
use curve25519_dalek::{
    edwards::CompressedEdwardsY, edwards::EdwardsPoint as Point25519, scalar::Scalar as Scalar25519,
};
use ff::{FromUniformBytes, PrimeField};
use halo2_poseidon::{ConstantLength, Hash, P128Pow5T3};
use oid_registry::{Oid, OidEntry, OidRegistry, asn1_rs::oid};
use pasta_curves::{
    group::GroupEncoding, pallas::Point as PointPallas, pallas::Scalar as ScalarPallas,
    vesta::Point as PointVesta, vesta::Scalar as ScalarVesta,
};
use primitive_types::{H256, U256};
use sha3::{self, Digest};

pub const OID_DOTAKON_PALLAS_PUBLIC_KEY: Oid<'_> = oid!(1.3.6.1.4.1.71104.1);
pub const OID_DOTAKON_IDENTITY_SIGNATURE_DUAL_SCHNORR: Oid<'_> = oid!(1.3.6.1.4.1.71104.2);

/// Registers Dotakon's custom OIDs in the OID registry. We use custom OIDs to embed and recover
/// custom fields in X.509 certificates, such as the node's public key on the Pallas curve which we
/// use to authenticate the node.
///
/// Invoke this function only once at startup.
pub fn register_oids(registry: &mut OidRegistry) {
    registry.insert(
        OID_DOTAKON_PALLAS_PUBLIC_KEY,
        OidEntry::new(
            "dotakonPublicKeyOnPallas",
            "Public key of a Dotakon node on the Pallas curve.",
        ),
    );
    registry.insert(
        OID_DOTAKON_IDENTITY_SIGNATURE_DUAL_SCHNORR,
        OidEntry::new(
            "dotakonDualSchnorrIdentitySignature",
            "Authentication algorithm used in the Dotakon network (dual Schnorr signature).",
        ),
    );
}

pub fn pallas_scalar_to_u256(scalar: ScalarPallas) -> U256 {
    U256::from_little_endian(&scalar.to_repr())
}

pub fn vesta_scalar_to_u256(scalar: ScalarVesta) -> U256 {
    U256::from_little_endian(&scalar.to_repr())
}

pub fn c25519_scalar_to_u256(scalar: Scalar25519) -> U256 {
    U256::from_little_endian(&scalar.to_bytes())
}

pub fn pallas_scalar_modulus() -> U256 {
    let max = ScalarPallas::zero() - ScalarPallas::one();
    pallas_scalar_to_u256(max) + 1
}

pub fn vesta_scalar_modulus() -> U256 {
    let max = ScalarVesta::zero() - ScalarVesta::one();
    vesta_scalar_to_u256(max) + 1
}

pub fn c25519_scalar_modulus() -> U256 {
    let max = Scalar25519::ZERO - Scalar25519::ONE;
    c25519_scalar_to_u256(max) + 1
}

pub fn u256_to_pallas_scalar(value: U256) -> Result<ScalarPallas> {
    ScalarPallas::from_repr_vartime(value.to_little_endian()).context("invalid Pallas scalar")
}

pub fn u256_to_vesta_scalar(value: U256) -> Result<ScalarVesta> {
    ScalarVesta::from_repr_vartime(value.to_little_endian()).context("invalid Vesta scalar")
}

pub fn u256_to_c25519_scalar(value: U256) -> Result<Scalar25519> {
    Scalar25519::from_canonical_bytes(value.to_little_endian())
        .into_option()
        .context("invalid Curve25519 scalar")
}

pub fn c25519_scalar_to_pallas_scalar(scalar: Scalar25519) -> ScalarPallas {
    // Here it's okay to unwrap without checking because Pallas's order is greater than
    // Curve25519's, so all canonical 25519 scalars are also canonical in Pallas and
    // `from_repr_vartime` should never error out. If these assumptions don't hold we should
    // definitely panic.
    ScalarPallas::from_repr_vartime(scalar.to_bytes()).unwrap()
}

pub fn c25519_scalar_to_vesta_scalar(scalar: Scalar25519) -> ScalarVesta {
    // The same rationale as `c25519_scalar_to_pallas_scalar` applies here. Vesta's scalar field is
    // smaller than Pallas's but still larger than Curve25519's.
    ScalarVesta::from_repr_vartime(scalar.to_bytes()).unwrap()
}

pub fn pallas_scalar_to_vesta_scalar(scalar: ScalarPallas) -> Result<ScalarVesta> {
    ScalarVesta::from_repr_vartime(scalar.to_repr()).context("invalid Vesta scalar")
}

pub fn vesta_scalar_to_pallas_scalar(scalar: ScalarVesta) -> ScalarPallas {
    // Pallas's scalar field is larger than Vesta's, so we can always unwrap.
    ScalarPallas::from_repr_vartime(scalar.to_repr()).unwrap()
}

pub fn hash_to_c25519_scalar(value: H256) -> Scalar25519 {
    Scalar25519::hash_from_bytes::<sha3::Sha3_512>(&value.to_fixed_bytes())
}

fn hash_to_pasta_scalar<F: PrimeField + FromUniformBytes<64>>(value: H256) -> F {
    let mut hasher = sha3::Sha3_512::new();
    hasher.update(value.to_fixed_bytes());
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(hasher.finalize().as_slice());
    F::from_uniform_bytes(&bytes)
}

pub fn hash_to_pallas_scalar(value: H256) -> ScalarPallas {
    hash_to_pasta_scalar::<ScalarPallas>(value)
}

pub fn hash_to_vesta_scalar(value: H256) -> ScalarVesta {
    hash_to_pasta_scalar::<ScalarVesta>(value)
}

pub fn parse_c25519_scalar(s: &str) -> Scalar25519 {
    u256_to_c25519_scalar(s.parse().unwrap()).unwrap()
}

pub fn parse_pallas_scalar(s: &str) -> ScalarPallas {
    u256_to_pallas_scalar(s.parse().unwrap()).unwrap()
}

pub fn parse_vesta_scalar(s: &str) -> ScalarVesta {
    u256_to_vesta_scalar(s.parse().unwrap()).unwrap()
}

pub fn compress_point_pallas(point: &PointPallas) -> H256 {
    H256::from_slice(&point.to_bytes())
}

pub fn decompress_point_pallas(point: H256) -> Result<PointPallas> {
    PointPallas::from_bytes(&point.to_fixed_bytes())
        .into_option()
        .context("invalid Pallas point")
}

pub fn compress_point_vesta(point: &PointVesta) -> H256 {
    H256::from_slice(&point.to_bytes())
}

pub fn decompress_point_vesta(point: H256) -> Result<PointVesta> {
    PointVesta::from_bytes(&point.to_fixed_bytes())
        .into_option()
        .context("invalid Vesta point")
}

pub fn compress_point_c25519(point: &Point25519) -> H256 {
    H256::from_slice(&point.compress().to_bytes())
}

pub fn decompress_point_c25519(value: H256) -> Result<Point25519> {
    let point = CompressedEdwardsY::from_slice(&value.to_fixed_bytes())?
        .decompress()
        .context("invalid Curve25519 point")?;
    if point.is_small_order() {
        return Err(anyhow!("invalid Ristretto point"));
    }
    Ok(point)
}

/// Converts the (Pallas) public key of an account to the corresponding wallet address.
pub fn public_key_to_wallet_address(public_key: PointPallas) -> ScalarPallas {
    hash_to_pallas_scalar(compress_point_pallas(&public_key))
}

pub fn format_wallet_address(wallet_address: ScalarPallas) -> String {
    format!("{:#x}", pallas_scalar_to_u256(wallet_address))
}

/// Hashes a sequence of scalars with Poseidon (using `P128Pow5T3`).
pub fn poseidon_hash<const L: usize>(inputs: [ScalarPallas; L]) -> ScalarPallas {
    let hasher = Hash::<ScalarPallas, P128Pow5T3, ConstantLength<L>, 3, 2>::init();
    hasher.hash(inputs)
}

/// Makes a type hashable with Poseidon (using `P128Pow5T3`).
///
/// Implementors can use the `poseidon_hash` function above.
pub trait PoseidonHash {
    fn poseidon_hash(&self) -> ScalarPallas;
}

/// Schnorr signature over the Pallas curve.
///
/// The hash algorithm used for the challenge hash is unspecified, and our code does use this struct
/// with different algorithms: protobuf signatures for RPCs use Pasta's hash-to-scalar algorithm
/// over SHA3-512, while all signatures that need to be verified on-chain (and the verification
/// needs to be proven in Halo2) use Poseidon-128.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct SchnorrPallasSignature {
    pub nonce: PointPallas,
    pub signature: ScalarPallas,
}

impl SchnorrPallasSignature {
    pub fn decode(bytes: &[u8; 64]) -> Result<Self> {
        let nonce = decompress_point_pallas(H256::from_slice(&bytes[0..32]))?;
        let signature = u256_to_pallas_scalar(U256::from_little_endian(&bytes[32..64]))?;
        Ok(Self { nonce, signature })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = [0u8; 64];
        bytes[0..32].copy_from_slice(
            compress_point_pallas(&self.nonce)
                .to_fixed_bytes()
                .as_slice(),
        );
        bytes[32..64].copy_from_slice(
            pallas_scalar_to_u256(self.signature)
                .to_little_endian()
                .as_slice(),
        );
        bytes.to_vec()
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct DualSchnorrSignature {
    pub nonce_pallas: PointPallas,
    pub nonce_25519: Point25519,
    pub signature_pallas: ScalarPallas,
    pub signature_25519: Scalar25519,
}

impl DualSchnorrSignature {
    pub const LENGTH: usize = 128;

    pub fn decode(bytes: &[u8; Self::LENGTH]) -> Result<DualSchnorrSignature> {
        Ok(Self {
            nonce_pallas: decompress_point_pallas(H256::from_slice(&bytes[0..32]))?,
            nonce_25519: decompress_point_c25519(H256::from_slice(&bytes[32..64]))?,
            signature_pallas: u256_to_pallas_scalar(U256::from_little_endian(&bytes[64..96]))?,
            signature_25519: u256_to_c25519_scalar(U256::from_little_endian(&bytes[96..128]))?,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = [0u8; Self::LENGTH];
        bytes[0..32].copy_from_slice(&compress_point_pallas(&self.nonce_pallas).to_fixed_bytes());
        bytes[32..64].copy_from_slice(&compress_point_c25519(&self.nonce_25519).to_fixed_bytes());
        bytes[64..96]
            .copy_from_slice(&pallas_scalar_to_u256(self.signature_pallas).to_little_endian());
        bytes[96..128]
            .copy_from_slice(&c25519_scalar_to_u256(self.signature_25519).to_little_endian());
        bytes.to_vec()
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct VerifiableRandomness {
    pub output: PointPallas,
    pub challenge: ScalarPallas,
    pub signature: ScalarPallas,
}

impl VerifiableRandomness {
    pub const LENGTH: usize = 96;

    pub fn decode(bytes: &[u8; Self::LENGTH]) -> Result<VerifiableRandomness> {
        Ok(VerifiableRandomness {
            output: decompress_point_pallas(H256::from_slice(&bytes[0..32]))?,
            challenge: u256_to_pallas_scalar(U256::from_little_endian(&bytes[32..64]))?,
            signature: u256_to_pallas_scalar(U256::from_little_endian(&bytes[64..96]))?,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = [0u8; Self::LENGTH];
        bytes[0..32].copy_from_slice(&compress_point_pallas(&self.output).to_fixed_bytes());
        bytes[32..64].copy_from_slice(&pallas_scalar_to_u256(self.challenge).to_little_endian());
        bytes[64..96].copy_from_slice(&pallas_scalar_to_u256(self.signature).to_little_endian());
        bytes.to_vec()
    }
}

// TODO: make this production code? The same algorithm is employed in `KeyManager::new`.
#[cfg(test)]
fn make_test_keys(secret_key: &str) -> (H256, PointPallas, Point25519) {
    use pasta_curves::group::Group;
    let secret_key = secret_key.parse::<H256>().unwrap();
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret_key.to_fixed_bytes());
    let private_key_25519 = signing_key.to_scalar();
    let public_key_pallas =
        PointPallas::generator() * c25519_scalar_to_pallas_scalar(private_key_25519);
    let public_key_25519 = Point25519::mul_base(&private_key_25519);
    (secret_key, public_key_pallas, public_key_25519)
}

/// WARNING: FOR TESTS ONLY, DO NOT use this key for anything else. They're leaked. If you create a
/// wallet with this, all your funds will be permanently LOST.
///
/// The three returned components are: the secret key, the public Pallas key, and the public
/// Curve25519 key.
#[cfg(test)]
pub fn testing_keys1() -> (H256, PointPallas, Point25519) {
    make_test_keys("0x0b0276914bf0f850d27771adb1abb62b2674e041b63c86c8cd0d7520355ae7c0".into())
}

/// WARNING: FOR TESTS ONLY, DO NOT use this key for anything else. They're leaked. If you create a
/// wallet with this, all your funds will be permanently LOST.
///
/// The three returned components are: the secret key, the public Pallas key, and the public
/// Curve25519 key.
#[cfg(test)]
pub fn testing_keys2() -> (H256, PointPallas, Point25519) {
    make_test_keys("0x0fc56ce55997c46f1ba0bce9a8a4daead405c29edf4066a2cd7d0419f592392b".into())
}

#[cfg(test)]
pub mod test {
    use anyhow::{Result, anyhow};
    use halo2_proofs::{dev::MockProver, plonk::Circuit};
    use pasta_curves::pallas::Scalar;

    pub fn verify_circuit<C: Circuit<Scalar>>(
        k: u32,
        circuit: &C,
        instance: Vec<Vec<Scalar>>,
    ) -> Result<()> {
        let prover_or_error = MockProver::run(k, circuit, instance);
        if let Err(error) = prover_or_error {
            println!("{}", error);
            return Err(anyhow!(error));
        }
        let prover = prover_or_error.unwrap();
        if let Err(errors) = prover.verify() {
            for error in errors {
                println!("{}", error);
            }
            return Err(anyhow!("verification failed"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ff::Field;
    use pasta_curves::group::Group;

    use super::*;

    #[test]
    fn test_custom_oids() {
        let mut registry = OidRegistry::default();
        register_oids(&mut registry);
        assert_eq!(
            registry.get(&OID_DOTAKON_PALLAS_PUBLIC_KEY).unwrap().sn(),
            "dotakonPublicKeyOnPallas"
        );
        assert_eq!(
            registry
                .get(&OID_DOTAKON_IDENTITY_SIGNATURE_DUAL_SCHNORR)
                .unwrap()
                .sn(),
            "dotakonDualSchnorrIdentitySignature"
        );
    }

    #[test]
    fn test_pallas_scalar_to_u256() {
        let scalar = ScalarPallas::from_raw([1u64, 2u64, 3u64, 4u64]);
        let value = pallas_scalar_to_u256(scalar);
        assert_eq!(
            value.to_little_endian(),
            [
                1u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 2u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,
                3u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 4u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8
            ]
        );
    }

    #[test]
    fn test_vesta_scalar_to_u256() {
        let scalar = ScalarVesta::from_raw([1u64, 2u64, 3u64, 4u64]);
        let value = vesta_scalar_to_u256(scalar);
        assert_eq!(
            value.to_little_endian(),
            [
                1u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 2u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,
                3u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 4u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8
            ]
        );
    }

    #[test]
    fn test_c25519_scalar_to_u256() {
        let scalar = Scalar25519::from_canonical_bytes([
            1u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 2u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 3u8,
            0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 4u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,
        ])
        .unwrap();
        let value = c25519_scalar_to_u256(scalar);
        assert_eq!(
            value.to_little_endian(),
            [
                1u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 2u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,
                3u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 4u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8
            ]
        );
    }

    #[test]
    fn test_pallas_scalar_modulus() {
        assert_eq!(
            format!("{:#x}", pallas_scalar_modulus()),
            "0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001"
        );
    }

    #[test]
    fn test_vesta_scalar_modulus() {
        assert_eq!(
            format!("{:#x}", vesta_scalar_modulus()),
            "0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001"
        );
    }

    #[test]
    fn test_c25519_scalar_modulus() {
        assert_eq!(
            format!("{:#x}", c25519_scalar_modulus()),
            "0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed"
        );
    }

    #[test]
    fn test_u256_to_pallas_scalar() {
        let value = U256::from_little_endian(&[
            4u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 3u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 2u8,
            0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 1u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,
        ]);
        let scalar = u256_to_pallas_scalar(value).unwrap();
        assert_eq!(scalar, ScalarPallas::from_raw([4u64, 3u64, 2u64, 1u64]));
    }

    #[test]
    fn test_u256_to_vesta_scalar() {
        let value = U256::from_little_endian(&[
            4u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 3u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 2u8,
            0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 1u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,
        ]);
        let scalar = u256_to_vesta_scalar(value).unwrap();
        assert_eq!(scalar, ScalarVesta::from_raw([4u64, 3u64, 2u64, 1u64]));
    }

    #[test]
    fn test_pallas_range() {
        assert!(u256_to_pallas_scalar(pallas_scalar_modulus() - 2).is_ok());
        assert!(u256_to_pallas_scalar(pallas_scalar_modulus() - 1).is_ok());
        assert!(u256_to_pallas_scalar(pallas_scalar_modulus()).is_err());
        assert!(u256_to_pallas_scalar(pallas_scalar_modulus() + 1).is_err());
        assert!(u256_to_pallas_scalar(pallas_scalar_modulus() + 2).is_err());
    }

    #[test]
    fn test_vesta_range() {
        assert!(u256_to_vesta_scalar(vesta_scalar_modulus() - 2).is_ok());
        assert!(u256_to_vesta_scalar(vesta_scalar_modulus() - 1).is_ok());
        assert!(u256_to_vesta_scalar(vesta_scalar_modulus()).is_err());
        assert!(u256_to_vesta_scalar(vesta_scalar_modulus() + 1).is_err());
        assert!(u256_to_vesta_scalar(vesta_scalar_modulus() + 2).is_err());
    }

    #[test]
    fn test_u256_to_c25519_scalar() {
        let bytes = [
            4u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 3u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 2u8,
            0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 1u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,
        ];
        let value = U256::from_little_endian(&bytes);
        let scalar = u256_to_c25519_scalar(value).unwrap();
        assert_eq!(scalar, Scalar25519::from_canonical_bytes(bytes).unwrap());
    }

    #[test]
    fn test_c25519_range() {
        assert!(u256_to_c25519_scalar(c25519_scalar_modulus() - 2).is_ok());
        assert!(u256_to_c25519_scalar(c25519_scalar_modulus() - 1).is_ok());
        assert!(u256_to_c25519_scalar(c25519_scalar_modulus()).is_err());
        assert!(u256_to_c25519_scalar(c25519_scalar_modulus() + 1).is_err());
        assert!(u256_to_c25519_scalar(c25519_scalar_modulus() + 2).is_err());
    }

    #[test]
    fn test_c25519_scalar_to_pallas_scalar() {
        let bytes = [
            4u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 3u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 2u8,
            0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 1u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,
        ];
        let value = Scalar25519::from_canonical_bytes(bytes).unwrap();
        assert_eq!(
            c25519_scalar_to_pallas_scalar(value),
            ScalarPallas::from_repr_vartime(bytes).unwrap()
        );
    }

    #[test]
    fn test_c25519_scalar_to_vesta_scalar() {
        let bytes = [
            4u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 3u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 2u8,
            0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 1u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,
        ];
        let value = Scalar25519::from_canonical_bytes(bytes).unwrap();
        assert_eq!(
            c25519_scalar_to_vesta_scalar(value),
            ScalarVesta::from_repr_vartime(bytes).unwrap()
        );
    }

    #[test]
    fn test_pallas_scalar_to_vesta_scalar() {
        let bytes = [
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 0, 0,
        ];
        let value = ScalarPallas::from_repr_vartime(bytes).unwrap();
        assert_eq!(
            pallas_scalar_to_vesta_scalar(value).unwrap(),
            ScalarVesta::from_repr_vartime(bytes).unwrap()
        );
    }

    #[test]
    fn test_pallas_scalar_to_invalid_vesta_scalar() {
        let value = ScalarPallas::ZERO - ScalarPallas::ONE;
        assert!(pallas_scalar_to_vesta_scalar(value).is_err());
    }

    #[test]
    fn test_vesta_scalar_to_pallas_scalar() {
        let bytes = [
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 0, 0,
        ];
        let value = ScalarVesta::from_repr_vartime(bytes).unwrap();
        assert_eq!(
            vesta_scalar_to_pallas_scalar(value),
            ScalarPallas::from_repr_vartime(bytes).unwrap()
        );
    }

    #[test]
    fn test_max_scalar() {
        assert!(c25519_scalar_modulus() < vesta_scalar_modulus());
        assert!(vesta_scalar_modulus() < pallas_scalar_modulus());
        assert_eq!(
            u256_to_vesta_scalar(c25519_scalar_modulus() - 1).unwrap(),
            c25519_scalar_to_vesta_scalar(Scalar25519::ZERO - Scalar25519::ONE)
        );
        assert_eq!(
            u256_to_pallas_scalar(c25519_scalar_modulus() - 1).unwrap(),
            c25519_scalar_to_pallas_scalar(Scalar25519::ZERO - Scalar25519::ONE)
        );
        assert_eq!(
            u256_to_pallas_scalar(vesta_scalar_modulus() - 1).unwrap(),
            vesta_scalar_to_pallas_scalar(ScalarVesta::ZERO - ScalarVesta::ONE)
        );
    }

    #[test]
    fn test_hash_to_c25519_scalar() {
        assert_eq!(
            hash_to_c25519_scalar(
                "0x3f75bfd1de06f77cce4d43d38ffac77eac6a8de697cf3b2a798bc19f1cb1c2b2"
                    .parse()
                    .unwrap()
            ),
            u256_to_c25519_scalar(
                "0x01ac55aab30876d319aad8c6bd7c279d0216bcc63acd3259b573baf85c8eb4af"
                    .parse()
                    .unwrap()
            )
            .unwrap()
        );
    }

    #[test]
    fn test_hash_to_pallas_scalar() {
        assert_eq!(
            hash_to_pallas_scalar(
                "0x3f75bfd1de06f77cce4d43d38ffac77eac6a8de697cf3b2a798bc19f1cb1c2b2"
                    .parse()
                    .unwrap()
            ),
            u256_to_pallas_scalar(
                "0x0e2bccf0252642aba9d5723ea773cdbbf5950dbec21b8b0c0c1dfbebfb6f9559"
                    .parse()
                    .unwrap()
            )
            .unwrap()
        );
    }

    #[test]
    fn test_hash_to_vesta_scalar() {
        assert_eq!(
            hash_to_vesta_scalar(
                "0x3f75bfd1de06f77cce4d43d38ffac77eac6a8de697cf3b2a798bc19f1cb1c2b2"
                    .parse()
                    .unwrap()
            ),
            u256_to_vesta_scalar(
                "0x2cc36e89a91a4e6f16e69fd3288c2cbfab5fd021df1d4da762364aa3500b1fbe"
                    .parse()
                    .unwrap()
            )
            .unwrap()
        );
    }

    #[test]
    fn test_parse_c25519_scalar() {
        assert_eq!(
            parse_c25519_scalar(
                "0x01ac55aab30876d319aad8c6bd7c279d0216bcc63acd3259b573baf85c8eb4af"
            ),
            u256_to_c25519_scalar(
                "0x01ac55aab30876d319aad8c6bd7c279d0216bcc63acd3259b573baf85c8eb4af"
                    .parse()
                    .unwrap()
            )
            .unwrap()
        );
    }

    #[test]
    fn test_parse_pallas_scalar() {
        assert_eq!(
            parse_pallas_scalar(
                "0x0e2bccf0252642aba9d5723ea773cdbbf5950dbec21b8b0c0c1dfbebfb6f9559"
            ),
            u256_to_pallas_scalar(
                "0x0e2bccf0252642aba9d5723ea773cdbbf5950dbec21b8b0c0c1dfbebfb6f9559"
                    .parse()
                    .unwrap()
            )
            .unwrap()
        );
    }

    #[test]
    fn test_parse_vesta_scalar() {
        assert_eq!(
            parse_vesta_scalar(
                "0x2cc36e89a91a4e6f16e69fd3288c2cbfab5fd021df1d4da762364aa3500b1fbe"
            ),
            u256_to_vesta_scalar(
                "0x2cc36e89a91a4e6f16e69fd3288c2cbfab5fd021df1d4da762364aa3500b1fbe"
                    .parse()
                    .unwrap()
            )
            .unwrap()
        );
    }

    #[test]
    fn test_compress_point_pallas1() {
        let compressed = compress_point_pallas(&PointPallas::generator());
        assert_eq!(
            PointPallas::generator(),
            decompress_point_pallas(compressed).unwrap()
        );
    }

    #[test]
    fn test_compress_point_pallas2() {
        let scalar = ScalarPallas::from_raw([42u64, 0, 0, 0]);
        let point = PointPallas::generator() * scalar;
        let compressed = compress_point_pallas(&point);
        assert_eq!(point, decompress_point_pallas(compressed).unwrap());
    }

    #[test]
    fn test_compress_point_25519_1() {
        let point = Point25519::mul_base(&Scalar25519::ONE);
        let compressed = compress_point_c25519(&point);
        assert_eq!(point, decompress_point_c25519(compressed).unwrap());
    }

    #[test]
    fn test_compress_point_25519_2() {
        let scalar = Scalar25519::from_canonical_bytes([
            42u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0,
        ])
        .unwrap();
        let point = Point25519::mul_base(&scalar);
        let compressed = compress_point_c25519(&point);
        assert_eq!(point, decompress_point_c25519(compressed).unwrap());
    }

    fn test_reject_non_ristretto_point(point: &Point25519) {
        let compressed = compress_point_c25519(&point);
        assert!(decompress_point_c25519(compressed).is_err());
    }

    #[test]
    fn test_reject_non_ristretto_points() {
        test_reject_non_ristretto_point(&curve25519_dalek::constants::EIGHT_TORSION[0]);
        test_reject_non_ristretto_point(&curve25519_dalek::constants::EIGHT_TORSION[1]);
        test_reject_non_ristretto_point(&curve25519_dalek::constants::EIGHT_TORSION[2]);
        test_reject_non_ristretto_point(&curve25519_dalek::constants::EIGHT_TORSION[3]);
        test_reject_non_ristretto_point(&curve25519_dalek::constants::EIGHT_TORSION[4]);
        test_reject_non_ristretto_point(&curve25519_dalek::constants::EIGHT_TORSION[5]);
        test_reject_non_ristretto_point(&curve25519_dalek::constants::EIGHT_TORSION[6]);
        test_reject_non_ristretto_point(&curve25519_dalek::constants::EIGHT_TORSION[7]);
    }

    #[test]
    fn test_format_wallet_address1() {
        let (_, public_key, _) = testing_keys1();
        let wallet_address = public_key_to_wallet_address(public_key);
        assert_eq!(
            format_wallet_address(wallet_address),
            "0x2b06517349ec30bcff0abeb81ab3ac3d4da3614b031b3f332657a73b0575b958"
        );
    }

    #[test]
    fn test_format_wallet_address2() {
        let (_, public_key, _) = testing_keys2();
        let wallet_address = public_key_to_wallet_address(public_key);
        assert_eq!(
            format_wallet_address(wallet_address),
            "0xfaeebcf2265e3495304715025f968b1ed8350dde25187ba383469571fd50348"
        );
    }

    #[test]
    fn test_poseidon_one_input() {
        assert_eq!(
            poseidon_hash([parse_pallas_scalar(
                "0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
            )]),
            parse_pallas_scalar(
                "0x1a6c849cc37ba32855d46a031f4a460fdb0ebb4ffad67e6466529700f9d1a49d"
            )
        );
        assert_eq!(
            poseidon_hash([parse_pallas_scalar(
                "0x1a6c849cc37ba32855d46a031f4a460fdb0ebb4ffad67e6466529700f9d1a49d"
            )]),
            parse_pallas_scalar(
                "0x0e2f050699b68c307604c2065d89e16f9ffffc5b6121a6c330fbb9fddd45abe0"
            )
        );
    }

    #[test]
    fn test_poseidon_two_inputs() {
        assert_eq!(
            poseidon_hash([
                parse_pallas_scalar(
                    "0x1a6c849cc37ba32855d46a031f4a460fdb0ebb4ffad67e6466529700f9d1a49d"
                ),
                parse_pallas_scalar(
                    "0x0e2f050699b68c307604c2065d89e16f9ffffc5b6121a6c330fbb9fddd45abe0"
                )
            ]),
            parse_pallas_scalar(
                "0x1577d68ba6b7aec999b345a8dda59dab4a68a7b5b491174121a8e60b7d1f69bc"
            )
        );
    }

    #[test]
    fn test_schnorr_signature_encoding() {
        let (secret_key, _, _) = testing_keys1();
        let ed25519_signing_key =
            ed25519_dalek::SigningKey::from_bytes(&secret_key.to_fixed_bytes());
        let private_key_25519 = ed25519_signing_key.to_scalar();
        let private_key = c25519_scalar_to_pallas_scalar(private_key_25519);
        let nonce = hash_to_pallas_scalar(H256::from_slice(&[
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 32,
        ]));
        let nonce_point = PointPallas::generator() * nonce;
        let challenge = hash_to_pallas_scalar(H256::from_slice(&[
            32u8, 31, 30u8, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12,
            11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1,
        ]));
        let scalar = nonce + private_key * challenge;
        let signature = SchnorrPallasSignature {
            nonce: nonce_point,
            signature: scalar,
        };
        let mut bytes = [0u8; 64];
        bytes.copy_from_slice(signature.encode().as_slice());
        assert_eq!(signature, SchnorrPallasSignature::decode(&bytes).unwrap());
    }

    #[test]
    fn test_dual_schnorr_signature_encoding() {
        let (secret_key, _, _) = testing_keys1();
        let ed25519_signing_key =
            ed25519_dalek::SigningKey::from_bytes(&secret_key.to_fixed_bytes());
        let private_key_25519 = ed25519_signing_key.to_scalar();
        let private_key_pallas = c25519_scalar_to_pallas_scalar(private_key_25519);
        let nonce_25519 = Scalar25519::from_canonical_bytes([
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 0, 0,
        ])
        .unwrap();
        let nonce_pallas = c25519_scalar_to_pallas_scalar(nonce_25519);
        let nonce_point_25519 = Point25519::mul_base(&nonce_25519);
        let nonce_point_pallas = PointPallas::generator() * nonce_pallas;
        let challenge_25519 = Scalar25519::from_canonical_bytes([
            30u8, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10,
            9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 0,
        ])
        .unwrap();
        let challenge_pallas = c25519_scalar_to_pallas_scalar(challenge_25519);
        let signature_25519 = nonce_25519 + challenge_25519 * private_key_25519;
        let signature_pallas = nonce_pallas + challenge_pallas * private_key_pallas;
        let signature = DualSchnorrSignature {
            nonce_pallas: nonce_point_pallas,
            nonce_25519: nonce_point_25519,
            signature_pallas,
            signature_25519,
        };
        let mut bytes = [0u8; DualSchnorrSignature::LENGTH];
        bytes.copy_from_slice(signature.encode().as_slice());
        assert_eq!(signature, DualSchnorrSignature::decode(&bytes).unwrap());
    }

    #[test]
    fn test_verifiable_randomness_encoding() {
        let scalar1 = ScalarPallas::from_repr_vartime([
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 0, 0,
        ])
        .unwrap();
        let scalar2 = ScalarPallas::from_repr_vartime([
            30u8, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10,
            9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 0,
        ])
        .unwrap();
        let randomness = VerifiableRandomness {
            output: PointPallas::generator() * scalar1,
            challenge: scalar1,
            signature: scalar2,
        };
        let mut bytes = [0u8; VerifiableRandomness::LENGTH];
        bytes.copy_from_slice(randomness.encode().as_slice());
        assert_eq!(VerifiableRandomness::decode(&bytes).unwrap(), randomness);
    }
}
