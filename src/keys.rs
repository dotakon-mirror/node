use std::sync::Mutex;

use anyhow::{Result, anyhow};
use curve25519_dalek::{EdwardsPoint as Point25519, scalar::Scalar as Scalar25519};
use ed25519_dalek::{self, ed25519::signature::SignerMut};
use pasta_curves::{group::Group, pallas::Point as PointPallas, pallas::Scalar as ScalarPallas};
use primitive_types::U256;
use rcgen;
use sha3::Digest;

use crate::utils;

#[derive(Debug)]
pub struct RemoteEd25519KeyPair<'a> {
    parent: &'a KeyManager,
    public_key_cache: [u8; ed25519_dalek::PUBLIC_KEY_LENGTH],
}

impl<'a> rcgen::RemoteKeyPair for RemoteEd25519KeyPair<'a> {
    fn public_key(&self) -> &[u8] {
        &self.public_key_cache
    }

    fn sign(&self, message: &[u8]) -> std::result::Result<Vec<u8>, rcgen::Error> {
        Ok(self.parent.sign_ed25519(message))
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ED25519
    }
}

#[derive(Debug)]
pub struct KeyManager {
    ed25519_signing_key: Mutex<ed25519_dalek::SigningKey>,
    private_key: Scalar25519,
    public_key_point_pallas: PointPallas,
    public_key_pallas: U256,
    public_key_point_25519: Point25519,
    public_key_25519: U256,
    wallet_address: U256,
}

impl KeyManager {
    const SCHNORR_IDENTITY_PROOF_DOMAIN_SEPARATOR: &str = "dotakon/schnorr-identity-v1";

    pub fn new(secret_key: U256) -> Result<Self> {
        let ed25519_signing_key =
            ed25519_dalek::SigningKey::from_bytes(&secret_key.to_little_endian());

        let private_key_25519 = ed25519_signing_key.to_scalar();
        let private_key_pallas = utils::c25519_scalar_to_pallas_scalar(private_key_25519);

        let public_key_point_pallas = PointPallas::generator() * private_key_pallas;
        let public_key_pallas = utils::compress_point_pallas(&public_key_point_pallas);

        let public_key_point_25519 = Point25519::mul_base(&private_key_25519);
        let public_key_25519 = utils::compress_point_c25519(&public_key_point_25519);

        let mut hasher = sha3::Sha3_256::new();
        hasher.update(public_key_pallas.to_little_endian());
        let wallet_address = U256::from_big_endian(hasher.finalize().as_slice());

        Ok(KeyManager {
            ed25519_signing_key: Mutex::new(ed25519_signing_key),
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

    pub fn sign_ed25519(&self, message: &[u8]) -> Vec<u8> {
        let mut signing_key = self.ed25519_signing_key.lock().unwrap();
        signing_key.sign(message).to_vec()
    }

    pub fn verify_ed25519(
        public_key_25519: U256,
        message: &[u8],
        signature: &[u8; ed25519_dalek::SIGNATURE_LENGTH],
    ) -> Result<()> {
        let ed25519_signature = ed25519_dalek::Signature::from(signature);
        let mut public_key_bytes = [0u8; ed25519_dalek::PUBLIC_KEY_LENGTH];
        public_key_bytes.copy_from_slice(public_key_25519.to_big_endian().as_slice());
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&public_key_bytes)?;
        verifying_key.verify_strict(message, &ed25519_signature)?;
        Ok(())
    }

    pub fn as_remote_ed25519_key_pair(&self) -> RemoteEd25519KeyPair {
        let mut public_key_bytes = [0u8; ed25519_dalek::PUBLIC_KEY_LENGTH];
        public_key_bytes.copy_from_slice(&self.public_key_25519.to_big_endian());
        RemoteEd25519KeyPair {
            parent: self,
            public_key_cache: public_key_bytes,
        }
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
            utils::compress_point_c25519(public_key_25519),
            utils::compress_point_pallas(nonce_point_pallas),
            utils::compress_point_c25519(nonce_point_25519),
        );
        let mut hasher = sha3::Sha3_256::new();
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
    ) -> Result<()> {
        let challenge_25519 = Self::make_public_key_identity_challenge(
            &public_key_pallas,
            &public_key_25519,
            &nonce_pallas,
            &nonce_25519,
        );
        let challenge_pallas = utils::c25519_scalar_to_pallas_scalar(challenge_25519);
        if (Point25519::mul_base(&signature_25519)
            != nonce_25519 + public_key_25519 * challenge_25519)
            || (PointPallas::generator() * signature_pallas
                != nonce_pallas + public_key_pallas * challenge_pallas)
        {
            return Err(anyhow!("invalid signature"));
        }
        Ok(())
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
            "0xB90F39D546DDDD466A131BECF6BCB23B5ED621BDB08A1DBD719041EA0D61E6BD"
                .parse()
                .unwrap()
        );
        assert_eq!(
            key_manager.public_key_25519(),
            "0xBB5A735BEFDF9DA0DD2998A1A4E972E1CF8F6DF479D11722F81557770E9DFF6"
                .parse()
                .unwrap()
        );
        assert_eq!(
            key_manager.wallet_address(),
            "0xA9FC2D791EA0D28C557788631A69DA04E2497968903295FB586E0915805E69BC"
                .parse()
                .unwrap()
        );
    }

    fn test_ed25519_signature(secret_key: U256) {
        let key_manager = KeyManager::new(secret_key).unwrap();
        let message = "Hello, world!";
        let signature = key_manager.sign_ed25519(message.as_bytes());
        let mut signature_bytes = [0u8; ed25519_dalek::SIGNATURE_LENGTH];
        signature_bytes.copy_from_slice(signature.as_slice());
        assert!(
            KeyManager::verify_ed25519(
                key_manager.public_key_25519(),
                message.as_bytes(),
                &signature_bytes
            )
            .is_ok()
        );
    }

    #[test]
    fn test_ed25519_signature1() {
        let (secret_key, _, _) = utils::testing_keys1();
        test_ed25519_signature(secret_key);
    }

    #[test]
    fn test_ed25519_signature2() {
        let (secret_key, _, _) = utils::testing_keys2();
        test_ed25519_signature(secret_key);
    }

    #[test]
    fn test_ed25519_signature_failure() {
        let (secret_key1, _, _) = utils::testing_keys1();
        let key_manager1 = KeyManager::new(secret_key1).unwrap();
        let (secret_key2, _, _) = utils::testing_keys2();
        let key_manager2 = KeyManager::new(secret_key2).unwrap();
        let message = "Hello, world!";
        let signature = key_manager1.sign_ed25519(message.as_bytes());
        let mut signature_bytes = [0u8; ed25519_dalek::SIGNATURE_LENGTH];
        signature_bytes.copy_from_slice(signature.as_slice());
        assert!(
            !KeyManager::verify_ed25519(
                key_manager2.public_key_25519(),
                message.as_bytes(),
                &signature_bytes
            )
            .is_ok()
        );
    }

    fn test_key_identity_proof(secret_key: U256) {
        let key_manager = KeyManager::new(secret_key).unwrap();
        let (r1, r2, s1, s2) = key_manager.prove_public_key_identity(
            Scalar25519::from_canonical_bytes([
                1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 0, 0,
            ])
            .unwrap(),
        );
        assert!(
            KeyManager::verify_public_key_identity(
                &key_manager.public_key_point_pallas,
                &key_manager.public_key_point_25519,
                &r1,
                &r2,
                s1,
                s2
            )
            .is_ok()
        );
    }

    #[test]
    fn test_key_identity_proof1() {
        let (secret_key, _, _) = utils::testing_keys1();
        test_key_identity_proof(secret_key);
    }

    #[test]
    fn test_key_identity_proof2() {
        let (secret_key, _, _) = utils::testing_keys2();
        test_key_identity_proof(secret_key);
    }

    #[test]
    fn test_key_identity_proof_failure() {
        let (secret_key1, _, _) = utils::testing_keys1();
        let key_manager1 = KeyManager::new(secret_key1).unwrap();
        let (secret_key2, _, _) = utils::testing_keys2();
        let key_manager2 = KeyManager::new(secret_key2).unwrap();
        let nonce = Scalar25519::from_canonical_bytes([
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 0, 0,
        ])
        .unwrap();
        let (r1, r2, s1, s2) = key_manager1.prove_public_key_identity(nonce);
        assert!(
            !KeyManager::verify_public_key_identity(
                &key_manager2.public_key_point_pallas,
                &key_manager2.public_key_point_25519,
                &r1,
                &r2,
                s1,
                s2
            )
            .is_ok()
        );
    }
}
