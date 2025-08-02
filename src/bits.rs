use crate::utils;
use ff::{Field, PrimeField};
use pasta_curves::pallas::Scalar;
use primitive_types::U256;

pub fn and1(value: Scalar) -> Scalar {
    let lsb = value.to_repr()[0];
    Scalar::from((lsb & 1) as u64)
}

pub fn shr(value: Scalar, count: Scalar) -> Scalar {
    utils::u256_to_pallas_scalar(
        utils::pallas_scalar_to_u256(value) >> utils::pallas_scalar_to_u256(count),
    )
    .unwrap()
}

pub fn shr1(value: Scalar) -> Scalar {
    shr(value, 1.into())
}

pub fn decompose_bits<const N: usize>(mut value: U256) -> [Scalar; N] {
    let mut bits = [Scalar::ZERO; N];
    for i in 0..N {
        bits[i] = Scalar::from((value & 1.into()).as_u64());
        value >>= 1;
    }
    assert_eq!(value, U256::zero());
    bits
}

pub fn decompose_scalar<const N: usize>(value: Scalar) -> [Scalar; N] {
    decompose_bits::<N>(utils::pallas_scalar_to_u256(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_and1() {
        assert_eq!(and1(42.into()), 0.into());
        assert_eq!(and1(43.into()), 1.into());
        assert_eq!(
            and1(utils::parse_pallas_scalar(
                "0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
            )),
            0.into()
        );
        assert_eq!(
            and1(utils::parse_pallas_scalar(
                "0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f21"
            )),
            1.into()
        );
    }

    #[test]
    fn test_shr() {
        assert_eq!(
            shr(
                utils::parse_pallas_scalar(
                    "0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
                ),
                4.into()
            ),
            utils::parse_pallas_scalar(
                "0x00102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2"
            )
        );
    }

    #[test]
    fn test_shr1() {
        assert_eq!(
            shr1(utils::parse_pallas_scalar(
                "0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
            )),
            utils::parse_pallas_scalar(
                "0x008101820283038404850586068707880889098a0a8b0b8c0c8d0d8e0e8f0f90"
            )
        );
    }

    #[test]
    fn test_decompose_bits() {
        assert_eq!(decompose_bits::<4>(0.into()), [Scalar::ZERO; 4]);
        assert_eq!(
            decompose_bits::<6>(0b101101u64.into()),
            [1.into(), 0.into(), 1.into(), 1.into(), 0.into(), 1.into()]
        );
        assert_eq!(
            decompose_bits::<64>(0xFFFFFFFFFFFFFFFFu64.into()),
            [1.into(); 64]
        );
    }

    #[test]
    fn test_decompose_scalar() {
        assert_eq!(decompose_scalar::<4>(0.into()), [Scalar::ZERO; 4]);
        assert_eq!(
            decompose_scalar::<6>(0b101101u64.into()),
            [1.into(), 0.into(), 1.into(), 1.into(), 0.into(), 1.into()]
        );
        assert_eq!(
            decompose_scalar::<64>(0xFFFFFFFFFFFFFFFFu64.into()),
            [1.into(); 64]
        );
    }
}
