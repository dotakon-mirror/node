use pasta_curves::{group::Group, group::GroupEncoding, pallas};
use primitive_types::U256;
use sha3::{Digest, Sha3_256};

#[derive(Debug)]
pub struct KeyManager {
    _private_key: pallas::Scalar,
    _public_key_point: pallas::Point,
    _public_key: U256,
    _wallet_address: U256,
}

impl KeyManager {
    pub fn new(private_key: pallas::Scalar) -> Self {
        let public_key_point = pallas::Point::generator() * private_key;
        let public_key = U256::from_big_endian(&public_key_point.to_bytes());

        let mut hasher = Sha3_256::new();
        hasher.update(public_key.to_little_endian());
        let wallet_address = U256::from_big_endian(hasher.finalize().as_slice());

        KeyManager {
            _private_key: private_key,
            _public_key_point: public_key_point,
            _public_key: public_key,
            _wallet_address: wallet_address,
        }
    }

    pub fn public_key(&self) -> U256 {
        self._public_key
    }

    pub fn wallet_address(&self) -> U256 {
        self._wallet_address
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_manager() {
        let private_key = pallas::Scalar::from_raw([
            0x0102030405060708u64,
            0x090A0B0C0D0E0F10u64,
            0x1112131415161718u64,
            0x191A1B1C1D1E1F00u64,
        ]);
        let key_manager = KeyManager::new(private_key);
        assert_eq!(
            key_manager.public_key(),
            "0x4463AE19948775AF24B867285CB7A28110259A2335F24449C9C70F5C7E948E36"
                .parse()
                .unwrap()
        );
        assert_eq!(
            key_manager.wallet_address(),
            "0x546E4A775FFAA52E006ADCF0B6864A5F8727AD7CB0996A1FAAD32DFA206AA97A"
                .parse()
                .unwrap()
        );
    }
}
