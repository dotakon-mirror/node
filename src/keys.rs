use anyhow::Result;
use curve25519_dalek::{EdwardsPoint as Point25519, scalar::Scalar as Scalar25519};
use pasta_curves::{group::Group, group::GroupEncoding, pallas::Point as PointPallas};
use primitive_types::U256;
use sha3::{Digest, Sha3_256};

use crate::utils;

#[derive(Debug)]
pub struct KeyManager {
    private_key: Scalar25519,
    public_key_point_pallas: PointPallas,
    public_key_pallas: U256,
    public_key_point_25519: Point25519,
    public_key_25519: U256,
    wallet_address: U256,
}

impl KeyManager {
    pub fn new(private_key: U256) -> Result<Self> {
        let private_key_25519 = utils::u256_to_c25519_scalar(private_key)?;
        let private_key_pallas = utils::u256_to_pallas_scalar(private_key)?;

        let public_key_point_pallas = PointPallas::generator() * private_key_pallas;
        let public_key_pallas = U256::from_big_endian(&public_key_point_pallas.to_bytes());

        let public_key_point_25519 = Point25519::mul_base(&private_key_25519);
        let public_key_25519 = U256::from_big_endian(&public_key_point_25519.compress().to_bytes());

        let mut hasher = Sha3_256::new();
        hasher.update(public_key_pallas.to_little_endian());
        let wallet_address = U256::from_big_endian(hasher.finalize().as_slice());

        Ok(KeyManager {
            private_key: private_key_25519,
            public_key_point_pallas,
            public_key_pallas,
            public_key_point_25519,
            public_key_25519,
            wallet_address,
        })
    }

    pub fn public_key(&self) -> U256 {
        self.public_key_pallas
    }

    pub fn public_key_25519(&self) -> U256 {
        self.public_key_25519
    }

    pub fn wallet_address(&self) -> U256 {
        self.wallet_address
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_manager() {
        let private_key = U256::from_little_endian(&[
            8u8, 7, 6, 5, 4, 3, 2, 1, 16, 15, 14, 13, 12, 11, 10, 9, 24, 23, 22, 21, 20, 19, 18,
            17, 32, 31, 30, 29, 28, 27, 0, 0,
        ]);
        let key_manager = KeyManager::new(private_key).unwrap();
        assert_eq!(
            key_manager.public_key(),
            "0x90C323F014A6CFB5FFFBA046C026536C3FB155CAF14F27E72E0A0C5E9C90D9B8"
                .parse()
                .unwrap()
        );
        assert_eq!(
            key_manager.public_key_25519(),
            "0xCF0CFBE033E23356458ACF01F6D302A372AB8A262184F7E30F8C0521F81AA82A"
                .parse()
                .unwrap()
        );
        assert_eq!(
            key_manager.wallet_address(),
            "0xEC374D50A3F6D2B589C9328C6236B70D393F4EB5966363B8E19C35A1C482AB38"
                .parse()
                .unwrap()
        );
    }
}
