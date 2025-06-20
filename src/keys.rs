use anyhow::Result;
use curve25519_dalek::{EdwardsPoint as Point25519, scalar::Scalar as Scalar25519};
use pasta_curves::{group::Group, pallas::Point as PointPallas, pallas::Scalar as ScalarPallas};
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
    const SCHNORR_IDENTITY_PROOF_DOMAIN_SEPARATOR: &str = "dotakon/schnorr-identity-v1";

    pub fn new(private_key: U256) -> Result<Self> {
        let private_key_25519 = utils::u256_to_c25519_scalar(private_key)?;
        let private_key_pallas = utils::u256_to_pallas_scalar(private_key)?;

        let public_key_point_pallas = PointPallas::generator() * private_key_pallas;
        let public_key_pallas = utils::compress_point_pallas(&public_key_point_pallas);

        let public_key_point_25519 = Point25519::mul_base(&private_key_25519);
        let public_key_25519 = utils::compress_point_25519(&public_key_point_25519);

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

    fn make_public_key_identity_challenge(
        public_key_pallas: &PointPallas,
        public_key_25519: &Point25519,
        nonce_point_pallas: &PointPallas,
        nonce_point_25519: &Point25519,
    ) -> Scalar25519 {
        let message = format!(
            "{{domain=\"{}\",public_key_pallas=0x{:#x},public_key_c25519=0x{:#x},nonce_pallas=0x{:#x},nonce_c25519=0x{:#x}}}",
            Self::SCHNORR_IDENTITY_PROOF_DOMAIN_SEPARATOR,
            utils::compress_point_pallas(public_key_pallas),
            utils::compress_point_25519(public_key_25519),
            utils::compress_point_pallas(nonce_point_pallas),
            utils::compress_point_25519(nonce_point_25519),
        );
        let mut hasher = Sha3_256::new();
        hasher.update(message.as_bytes());
        Scalar25519::from_bytes_mod_order(hasher.finalize().into())
    }

    fn make_own_public_key_identity_challenge(
        &self,
        nonce_point_pallas: &PointPallas,
        nonce_point_25519: &Point25519,
    ) -> Scalar25519 {
        Self::make_public_key_identity_challenge(
            &self.public_key_point_pallas,
            &self.public_key_point_25519,
            nonce_point_pallas,
            nonce_point_25519,
        )
    }

    pub fn prove_public_key_identity(
        &self,
        secret_nonce: Scalar25519,
    ) -> (PointPallas, Point25519, ScalarPallas, Scalar25519) {
        let nonce_pallas = utils::c25519_scalar_to_pallas_scalar(secret_nonce);
        let nonce_25519 = secret_nonce;
        let nonce_point_pallas = PointPallas::generator() * nonce_pallas;
        let nonce_point_25519 = Point25519::mul_base(&nonce_25519);
        let challenge =
            self.make_own_public_key_identity_challenge(&nonce_point_pallas, &nonce_point_25519);
        let signature_pallas = nonce_pallas
            + utils::c25519_scalar_to_pallas_scalar(self.private_key)
                * utils::c25519_scalar_to_pallas_scalar(challenge);
        let signature_25519 = nonce_25519 + self.private_key * challenge;
        (
            nonce_point_pallas,
            nonce_point_25519,
            signature_pallas,
            signature_25519,
        )
    }

    pub fn verify_public_key_identity(
        public_key_pallas: &PointPallas,
        public_key_25519: &Point25519,
        nonce_pallas: &PointPallas,
        nonce_25519: &Point25519,
        signature_pallas: ScalarPallas,
        signature_25519: Scalar25519,
    ) -> bool {
        let challenge_25519 = Self::make_public_key_identity_challenge(
            &public_key_pallas,
            &public_key_25519,
            &nonce_pallas,
            &nonce_25519,
        );
        let challenge_pallas = utils::c25519_scalar_to_pallas_scalar(challenge_25519);
        (Point25519::mul_base(&signature_25519) == nonce_25519 + public_key_25519 * challenge_25519)
            && (PointPallas::generator() * signature_pallas
                == nonce_pallas + public_key_pallas * challenge_pallas)
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

    #[test]
    fn test_key_identity_proof() {
        let private_key = U256::from_little_endian(&[
            8u8, 7, 6, 5, 4, 3, 2, 1, 16, 15, 14, 13, 12, 11, 10, 9, 24, 23, 22, 21, 20, 19, 18,
            17, 32, 31, 30, 29, 28, 27, 0, 0,
        ]);
        let key_manager = KeyManager::new(private_key).unwrap();
        let (r1, r2, s1, s2) = key_manager.prove_public_key_identity(
            Scalar25519::from_canonical_bytes([
                1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 0, 0,
            ])
            .unwrap(),
        );
        assert!(KeyManager::verify_public_key_identity(
            &key_manager.public_key_point_pallas,
            &key_manager.public_key_point_25519,
            &r1,
            &r2,
            s1,
            s2
        ));
    }
}
