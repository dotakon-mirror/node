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
    fn test_pallas_scalar_modulus() {
        assert_eq!(
            format!("{:#x}", pallas_scalar_modulus()),
            "0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001"
        );
    }

    // TODO
}
