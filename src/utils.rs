use anyhow::{Context, Result};
use curve25519_dalek::{
    edwards::CompressedEdwardsY, edwards::EdwardsPoint as Point25519, scalar::Scalar as Scalar25519,
};
use ff::PrimeField;
use oid_registry::{Oid, OidEntry, OidRegistry, asn1_rs::oid};
use pasta_curves::{
    group::GroupEncoding, pallas::Point as PointPallas, pallas::Scalar as ScalarPallas,
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

pub fn c25519_scalar_to_u256(scalar: Scalar25519) -> U256 {
    U256::from_little_endian(&scalar.to_bytes())
}

pub fn pallas_scalar_modulus() -> U256 {
    let max = ScalarPallas::zero() - ScalarPallas::one();
    pallas_scalar_to_u256(max) + 1
}

pub fn c25519_scalar_modulus() -> U256 {
    let max = Scalar25519::ZERO - Scalar25519::ONE;
    c25519_scalar_to_u256(max) + 1
}

pub fn u256_to_pallas_scalar(value: U256) -> Result<ScalarPallas> {
    ScalarPallas::from_repr_vartime(value.to_little_endian()).context("invalid Pallas scalar")
}

pub fn u256_to_clamped_pallas_scalar(value: U256) -> ScalarPallas {
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(value.to_little_endian().as_slice());
    bytes[31] &= 0x0F;
    ScalarPallas::from_repr_vartime(bytes).unwrap()
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

pub fn compress_point_pallas(point: &PointPallas) -> U256 {
    U256::from_big_endian(&point.to_bytes())
}

pub fn decompress_point_pallas(point: U256) -> Result<PointPallas> {
    PointPallas::from_bytes(&point.to_big_endian())
        .into_option()
        .context("invalid Pallas point")
}

pub fn compress_point_c25519(point: &Point25519) -> U256 {
    U256::from_big_endian(&point.compress().to_bytes())
}

pub fn decompress_point_c25519(value: U256) -> Result<Point25519> {
    CompressedEdwardsY::from_slice(&value.to_big_endian())?
        .decompress()
        .context("invalid Curve25519 point")
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct SchnorrPallasSignature {
    pub nonce: PointPallas,
    pub signature: ScalarPallas,
}

impl SchnorrPallasSignature {
    pub fn decode(bytes: &[u8; 64]) -> Result<SchnorrPallasSignature> {
        let nonce = decompress_point_pallas(U256::from_big_endian(&bytes[0..32]))?;
        let signature = u256_to_pallas_scalar(U256::from_little_endian(&bytes[32..64]))?;
        Ok(Self { nonce, signature })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = [0u8; 64];
        bytes[0..32].copy_from_slice(
            compress_point_pallas(&self.nonce)
                .to_big_endian()
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
    pub fn decode(bytes: &[u8; 128]) -> Result<DualSchnorrSignature> {
        let nonce_pallas =
            decompress_point_pallas(U256::from_big_endian(&bytes[0..32])).map_err(|_| {
                rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
            })?;
        let nonce_25519 =
            decompress_point_c25519(U256::from_big_endian(&bytes[32..64])).map_err(|_| {
                rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
            })?;
        let signature_pallas = u256_to_pallas_scalar(U256::from_little_endian(&bytes[64..96]))
            .map_err(|_| {
                rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
            })?;
        let signature_25519 = u256_to_c25519_scalar(U256::from_little_endian(&bytes[96..128]))
            .map_err(|_| {
                rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
            })?;
        Ok(Self {
            nonce_pallas,
            nonce_25519,
            signature_pallas,
            signature_25519,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = [0u8; 128];
        bytes[0..32].copy_from_slice(
            compress_point_pallas(&self.nonce_pallas)
                .to_big_endian()
                .as_slice(),
        );
        bytes[32..64].copy_from_slice(
            compress_point_c25519(&self.nonce_25519)
                .to_big_endian()
                .as_slice(),
        );
        bytes[64..96].copy_from_slice(
            pallas_scalar_to_u256(self.signature_pallas)
                .to_little_endian()
                .as_slice(),
        );
        bytes[96..128].copy_from_slice(
            c25519_scalar_to_u256(self.signature_25519)
                .to_little_endian()
                .as_slice(),
        );
        bytes.to_vec()
    }
}

/// Converts the (Pallas) public key of an account to the corresponding wallet address. Basically
/// just a SHA3 hash.
pub fn public_key_to_wallet_address(public_key: U256) -> H256 {
    let mut hasher = sha3::Sha3_256::new();
    hasher.update(public_key.to_little_endian());
    H256::from_slice(hasher.finalize().as_slice())
}

pub fn format_wallet_address(wallet_address: H256) -> String {
    format!("{:#x}", wallet_address)
}

// TODO: make this production code?
#[cfg(test)]
fn make_test_keys(secret_key: &str) -> (U256, U256, U256) {
    use ed25519_dalek;
    use pasta_curves::group::Group;
    let secret_key = U256::from_str_radix(secret_key, 16).unwrap();
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret_key.to_little_endian());
    let private_key_25519 = signing_key.to_scalar();
    let public_key_pallas =
        PointPallas::generator() * c25519_scalar_to_pallas_scalar(private_key_25519);
    let public_key_25519 = Point25519::mul_base(&private_key_25519);
    let compressed_pallas_key = compress_point_pallas(&public_key_pallas);
    (
        secret_key,
        compressed_pallas_key,
        compress_point_c25519(&public_key_25519),
    )
}

/// WARNING: FOR TESTS ONLY, DO NOT use this key for anything else. They're leaked. If you create a
/// wallet with this, all your funds will be permanently LOST.
///
/// The three returned components are: the secret key, the public Pallas key, and the public
/// Curve25519 key.
#[cfg(test)]
pub fn testing_keys1() -> (U256, U256, U256) {
    make_test_keys("0xb0276914bf0f850d27771adb1abb62b2674e041b63c86c8cd0d7520355ae7c0".into())
}

/// WARNING: FOR TESTS ONLY, DO NOT use this key for anything else. They're leaked. If you create a
/// wallet with this, all your funds will be permanently LOST.
///
/// The three returned components are: the secret key, the public Pallas key, and the public
/// Curve25519 key.
#[cfg(test)]
pub fn testing_keys2() -> (U256, U256, U256) {
    make_test_keys("0xfc56ce55997c46f1ba0bce9a8a4daead405c29edf4066a2cd7d0419f592392b".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek;
    use pasta_curves::group::Group;

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
    fn test_pallas_range() {
        assert!(u256_to_pallas_scalar(pallas_scalar_modulus() - 2).is_ok());
        assert!(u256_to_pallas_scalar(pallas_scalar_modulus() - 1).is_ok());
        assert!(u256_to_pallas_scalar(pallas_scalar_modulus()).is_err());
        assert!(u256_to_pallas_scalar(pallas_scalar_modulus() + 1).is_err());
        assert!(u256_to_pallas_scalar(pallas_scalar_modulus() + 2).is_err());
    }

    #[test]
    fn test_u256_to_clamped_pallas_scalar() {
        let value = U256::from_little_endian(&[
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 255, 255,
        ]);
        assert_eq!(
            u256_to_clamped_pallas_scalar(value),
            ScalarPallas::from_raw([
                0x0807060504030201u64,
                0x100F0E0D0C0B0A09u64,
                0x1817161514131211u64,
                0x0FFF1E1D1C1B1A19u64,
            ])
        );
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
    fn test_max_scalar() {
        assert!(c25519_scalar_modulus() < pallas_scalar_modulus());
        assert_eq!(
            u256_to_pallas_scalar(c25519_scalar_modulus() - 1).unwrap(),
            c25519_scalar_to_pallas_scalar(Scalar25519::ZERO - Scalar25519::ONE)
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

    #[test]
    fn test_format_wallet_address1() {
        let (_, public_key, _) = testing_keys1();
        let wallet_address = public_key_to_wallet_address(public_key);
        assert_eq!(
            format_wallet_address(wallet_address),
            "0x876431d0e6aaa0c15d752f1b73540761e8226aef004fa633f0571435a0786a7d"
        );
    }

    #[test]
    fn test_format_wallet_address2() {
        let (_, public_key, _) = testing_keys2();
        let wallet_address = public_key_to_wallet_address(public_key);
        assert_eq!(
            format_wallet_address(wallet_address),
            "0x20502edb6f0580d8b792a712b8235bc69a5912d6b20c2894e936c9bcf8fd4af7"
        );
    }

    #[test]
    fn test_schnorr_signature_encoding() {
        let (secret_key, _, _) = testing_keys1();
        let ed25519_signing_key =
            ed25519_dalek::SigningKey::from_bytes(&secret_key.to_little_endian());
        let private_key_25519 = ed25519_signing_key.to_scalar();
        let private_key = c25519_scalar_to_pallas_scalar(private_key_25519);
        let nonce = u256_to_clamped_pallas_scalar(U256::from_little_endian(&[
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 32,
        ]));
        let nonce_point = PointPallas::generator() * nonce;
        let challenge = u256_to_clamped_pallas_scalar(U256::from_little_endian(&[
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
            ed25519_dalek::SigningKey::from_bytes(&secret_key.to_little_endian());
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
        let mut bytes = [0u8; 128];
        bytes.copy_from_slice(signature.encode().as_slice());
        assert_eq!(signature, DualSchnorrSignature::decode(&bytes).unwrap());
    }
}
