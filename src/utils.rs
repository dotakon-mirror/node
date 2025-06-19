use anyhow::{Context, Result};
use curve25519_dalek::scalar::Scalar as Scalar25519;
use ff::PrimeField;
use pasta_curves::pallas::Scalar as ScalarPallas;
use primitive_types::U256;

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
    Ok(ScalarPallas::from_repr_vartime(value.to_little_endian())
        .context("invalid Pallas scalar")?)
}

pub fn u256_to_c25519_scalar(value: U256) -> Result<Scalar25519> {
    Ok(Scalar25519::from_canonical_bytes(value.to_little_endian())
        .into_option()
        .context("invalid Curve25519 scalar")?)
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
