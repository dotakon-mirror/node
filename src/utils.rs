use anyhow::Context;
use ff::PrimeField;
use pasta_curves::pallas;
use primitive_types::U256;

pub fn pallas_scalar_to_u256(scalar: pallas::Scalar) -> U256 {
    U256::from_little_endian(&scalar.to_repr())
}

pub fn pallas_scalar_modulus() -> U256 {
    let max = pallas::Scalar::zero() - pallas::Scalar::one();
    pallas_scalar_to_u256(max) + 1
}

pub fn u256_to_pallas_scalar(value: U256) -> anyhow::Result<pallas::Scalar> {
    Ok(pallas::Scalar::from_repr_vartime(value.to_little_endian())
        .context("invalid Pallas scalar")?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pallas_scalar_to_u256() {
        let scalar = pallas::Scalar::from_raw([1u64, 2u64, 3u64, 4u64]);
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
    fn test_pallas_scalar_modulus() {
        assert_eq!(
            format!("{:#x}", pallas_scalar_modulus()),
            "0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001"
        );
    }

    #[test]
    fn test_u256_to_pallas_scalar() {
        let value = U256::from_little_endian(&[
            4u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 3u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 2u8,
            0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 1u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,
        ]);
        let scalar = u256_to_pallas_scalar(value).unwrap();
        assert_eq!(scalar, pallas::Scalar::from_raw([4u64, 3u64, 2u64, 1u64]));
    }

    #[test]
    fn test_pallas_range() {
        assert!(u256_to_pallas_scalar(pallas_scalar_modulus() - 1).is_ok());
        assert!(u256_to_pallas_scalar(pallas_scalar_modulus()).is_err());
        assert!(u256_to_pallas_scalar(pallas_scalar_modulus() + 1).is_err());
    }
}
