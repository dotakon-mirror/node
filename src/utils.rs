use anyhow::{Context, Result};
use curve25519_dalek::{
    edwards::CompressedEdwardsY, edwards::EdwardsPoint as Point25519, scalar::Scalar as Scalar25519,
};
use ff::PrimeField;
use oid_registry::{Oid, OidEntry, OidRegistry, asn1_rs::oid};
use pasta_curves::{
    group::GroupEncoding, pallas::Point as PointPallas, pallas::Scalar as ScalarPallas,
};
use primitive_types::U256;

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

pub fn u256_to_c25519_scalar(value: U256) -> Result<Scalar25519> {
    Scalar25519::from_canonical_bytes(value.to_little_endian())
        .into_option()
        .context("invalid Curve25519 scalar")
}

pub fn c25519_scalar_to_pallas_scalar(scalar: Scalar25519) -> ScalarPallas {
    // Here it's okay to unwrap without checking because Pallas's order is greater than
    // Curve25519's, so all canonical 25519 scalars are also canonical in Pallas and
    // `from_repr_vartime` should never panic. If these assumptions don't hold we should definitely
    // panic.
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

/// TODO: make this production code.
#[cfg(test)]
fn make_test_keys(private_key: &str) -> (U256, U256, U256) {
    use pasta_curves::group::Group;
    let private_key = U256::from_str_radix(private_key, 16).unwrap();
    let public_key_pallas = PointPallas::generator() * u256_to_pallas_scalar(private_key).unwrap();
    let public_key_25519 = Point25519::mul_base(&u256_to_c25519_scalar(private_key).unwrap());
    (
        private_key,
        compress_point_pallas(&public_key_pallas),
        compress_point_c25519(&public_key_25519),
    )
}

/// WARNING: FOR TESTS ONLY, DO NOT use these keys for anything else. They're leaked. If you create
/// a wallet with this, all your funds will be permanently LOST.
///
/// The three returned components are: the private key, the public Pallas key, and the public
/// Curve25519 key.
#[cfg(test)]
pub fn testing_keys1() -> (U256, U256, U256) {
    make_test_keys("0xb0276914bf0f850d27771adb1abb62b2674e041b63c86c8cd0d7520355ae7c0".into())
}

/// WARNING: DO NOT use this private key for anything. It's leaked. If you create a wallet with
/// this, all your funds will be permanently LOST.
///
/// The three returned components are: the private key, the public Pallas key, and the public
/// Curve25519 key.
#[cfg(test)]
pub fn testing_keys2() -> (U256, U256, U256) {
    make_test_keys("0xfc56ce55997c46f1ba0bce9a8a4daead405c29edf4066a2cd7d0419f592392b".into())
}

#[cfg(test)]
mod tests {
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
}
