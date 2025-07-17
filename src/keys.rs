use crate::dotakon;
use crate::proto;
use crate::utils;
use anyhow::{Result, anyhow};
use base64::{Engine, prelude::BASE64_STANDARD};
use curve25519_dalek::{EdwardsPoint as Point25519, scalar::Scalar as Scalar25519};
use ed25519_dalek::{self, ed25519::signature::SignerMut, pkcs8::EncodePrivateKey};
use pasta_curves::{group::Group, pallas::Point as PointPallas, pallas::Scalar as ScalarPallas};
use primitive_types::H256;
use sha3::{self, Digest};
use std::ops::Deref;
use std::sync::Mutex;

#[derive(Debug, Clone)]
pub struct RemoteEd25519KeyPair<R: Deref<Target = KeyManager>> {
    parent: R,
    public_key_cache: [u8; ed25519_dalek::PUBLIC_KEY_LENGTH],
}

impl<R: Deref<Target = KeyManager>> From<R> for RemoteEd25519KeyPair<R> {
    fn from(key_manager: R) -> Self {
        let public_key_cache = key_manager.public_key_25519.to_fixed_bytes();
        Self {
            parent: key_manager,
            public_key_cache,
        }
    }
}

impl<R: Deref<Target = KeyManager>> rcgen::RemoteKeyPair for RemoteEd25519KeyPair<R> {
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
    public_key_pallas: H256,
    public_key_point_25519: Point25519,
    public_key_25519: H256,
    wallet_address: H256,
}

impl KeyManager {
    const SCHNORR_SIGNATURE_DOMAIN_SEPARATOR: &str = "dotakon/schnorr-signature-v1";
    const SCHNORR_IDENTITY_PROOF_DOMAIN_SEPARATOR: &str = "dotakon/schnorr-identity-v1";

    pub fn new(secret_key: H256) -> Self {
        let ed25519_signing_key =
            ed25519_dalek::SigningKey::from_bytes(&secret_key.to_fixed_bytes());

        let private_key_25519 = ed25519_signing_key.to_scalar();
        let private_key_pallas = utils::c25519_scalar_to_pallas_scalar(private_key_25519);

        let public_key_point_pallas = PointPallas::generator() * private_key_pallas;
        let public_key_pallas = utils::compress_point_pallas(&public_key_point_pallas);

        let public_key_point_25519 = Point25519::mul_base(&private_key_25519);
        let public_key_25519 = utils::compress_point_c25519(&public_key_point_25519);

        Self {
            ed25519_signing_key: Mutex::new(ed25519_signing_key),
            private_key: private_key_25519,
            public_key_point_pallas,
            public_key_pallas,
            public_key_point_25519,
            public_key_25519,
            wallet_address: utils::public_key_to_wallet_address(public_key_pallas),
        }
    }

    pub fn export_private_key(&self) -> Result<Vec<u8>> {
        let signing_key = self.ed25519_signing_key.lock().unwrap();
        Ok(signing_key.to_pkcs8_der()?.as_bytes().to_vec())
    }

    pub fn public_key(&self) -> H256 {
        self.public_key_pallas
    }

    pub fn public_key_25519(&self) -> H256 {
        self.public_key_25519
    }

    pub fn wallet_address(&self) -> H256 {
        self.wallet_address
    }

    fn make_signature_challenge(
        public_key: &PointPallas,
        nonce: &PointPallas,
        message: &[u8],
    ) -> ScalarPallas {
        let message = format!(
            "{{domain=\"{}\",public_key={:#x},nonce={:#x},message=\"{}\"}}",
            Self::SCHNORR_SIGNATURE_DOMAIN_SEPARATOR,
            utils::compress_point_pallas(public_key),
            utils::compress_point_pallas(nonce),
            BASE64_STANDARD.encode(message),
        );
        utils::c25519_scalar_to_pallas_scalar(Scalar25519::hash_from_bytes::<sha3::Sha3_512>(
            message.as_bytes(),
        ))
    }

    fn make_own_signature_challenge(&self, nonce: &PointPallas, message: &[u8]) -> ScalarPallas {
        Self::make_signature_challenge(&self.public_key_point_pallas, nonce, message)
    }

    /// WARNING: `secret_nonce` MUST be fresh. Signing two different messages with the same nonce
    /// allows full private key recovery.
    pub fn sign(&self, message: &[u8], secret_nonce: H256) -> utils::SchnorrPallasSignature {
        let nonce = utils::hash_to_pallas_scalar(secret_nonce);
        let nonce_point = PointPallas::generator() * nonce;
        let challenge = self.make_own_signature_challenge(&nonce_point, message);
        let signature = nonce + utils::c25519_scalar_to_pallas_scalar(self.private_key) * challenge;
        utils::SchnorrPallasSignature {
            nonce: nonce_point,
            signature,
        }
    }

    pub fn verify(
        message: &[u8],
        public_key: &PointPallas,
        signature: &utils::SchnorrPallasSignature,
    ) -> Result<()> {
        let challenge = Self::make_signature_challenge(public_key, &signature.nonce, message);
        if PointPallas::generator() * signature.signature
            != signature.nonce + public_key * challenge
        {
            return Err(anyhow!("invalid signature"));
        }
        Ok(())
    }

    /// WARNING: `secret_nonce` MUST be fresh. Signing two different messages with the same nonce
    /// allows full private key recovery.
    pub fn sign_message<M: prost::Message + prost::Name>(
        &self,
        message: &M,
        secret_nonce: H256,
    ) -> Result<(prost_types::Any, dotakon::Signature)> {
        let (payload, bytes) = proto::encode_message_canonical(message)?;
        let signature = self.sign(bytes.as_slice(), secret_nonce).encode();
        Ok((
            payload,
            dotakon::Signature {
                signer: Some(proto::h256_to_bytes32(self.wallet_address())),
                scheme: Some(dotakon::SignatureScheme::SigSchnorrPallasSha3256.into()),
                public_key: Some(self.public_key_pallas.to_fixed_bytes().to_vec()),
                signature: Some(signature),
            },
        ))
    }

    pub fn verify_signed_message(
        payload: &prost_types::Any,
        signature: &dotakon::Signature,
    ) -> Result<()> {
        const SCHNORR_PALLAS_SHA3_256: i32 =
            dotakon::SignatureScheme::SigSchnorrPallasSha3256 as i32;
        match signature.scheme {
            Some(SCHNORR_PALLAS_SHA3_256) => Ok(()),
            Some(_) => Err(anyhow!("unsupported signature scheme")),
            None => Err(anyhow!("invalid signature: missing scheme")),
        }?;
        let (public_key, wallet_address) = match &signature.public_key {
            Some(bytes) => {
                let public_key = H256::from_slice(bytes.as_slice());
                let wallet_address = utils::public_key_to_wallet_address(public_key);
                let public_key = utils::decompress_point_pallas(public_key)?;
                Ok((public_key, wallet_address))
            }
            None => Err(anyhow!("invalid signature: public key is missing")),
        }?;
        match signature.signer {
            Some(bytes32) => {
                let signer = proto::h256_from_bytes32(&bytes32);
                if signer != wallet_address {
                    Err(anyhow!("invalid signature: mismatching signer address"))
                } else {
                    Ok(())
                }
            }
            None => Err(anyhow!("invalid signature: signer address is missing")),
        }?;
        let signature = match &signature.signature {
            Some(byte_vec) => {
                let mut bytes = [0u8; 64];
                bytes.copy_from_slice(byte_vec.as_slice());
                Ok(utils::SchnorrPallasSignature::decode(&bytes)?)
            }
            None => Err(anyhow!("invalid signature: missing signature bytes")),
        }?;
        let message_bytes = proto::encode_any_canonical(payload);
        Self::verify(message_bytes.as_slice(), &public_key, &signature)
    }

    pub fn sign_ed25519(&self, message: &[u8]) -> Vec<u8> {
        let mut signing_key = self.ed25519_signing_key.lock().unwrap();
        signing_key.sign(message).to_vec()
    }

    pub fn verify_ed25519(
        message: &[u8],
        public_key_25519: H256,
        signature: &[u8; ed25519_dalek::SIGNATURE_LENGTH],
    ) -> Result<()> {
        let ed25519_signature = ed25519_dalek::Signature::from(signature);
        let mut public_key_bytes = [0u8; ed25519_dalek::PUBLIC_KEY_LENGTH];
        public_key_bytes.copy_from_slice(public_key_25519.to_fixed_bytes().as_slice());
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&public_key_bytes)?;
        verifying_key.verify_strict(message, &ed25519_signature)?;
        Ok(())
    }

    fn make_public_key_identity_challenge(
        public_key_pallas: &PointPallas,
        public_key_25519: &Point25519,
        nonce_point_pallas: &PointPallas,
        nonce_point_25519: &Point25519,
    ) -> Scalar25519 {
        let message = format!(
            "{{domain=\"{}\",public_key_pallas={:#x},public_key_c25519={:#x},nonce_pallas={:#x},nonce_c25519={:#x}}}",
            Self::SCHNORR_IDENTITY_PROOF_DOMAIN_SEPARATOR,
            utils::compress_point_pallas(public_key_pallas),
            utils::compress_point_c25519(public_key_25519),
            utils::compress_point_pallas(nonce_point_pallas),
            utils::compress_point_c25519(nonce_point_25519),
        );
        Scalar25519::hash_from_bytes::<sha3::Sha3_512>(message.as_bytes())
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

    fn get_nonce_scalars(secret_nonce: H256) -> (ScalarPallas, Scalar25519) {
        let secret_nonce1 = secret_nonce;
        let secret_nonce2 = {
            let mut hasher = sha3::Sha3_256::new();
            hasher.update(secret_nonce1.to_fixed_bytes());
            H256::from_slice(hasher.finalize().as_slice())
        };
        (
            utils::hash_to_pallas_scalar(secret_nonce1),
            utils::hash_to_c25519_scalar(secret_nonce2),
        )
    }

    pub fn prove_public_key_identity(&self, secret_nonce: H256) -> utils::DualSchnorrSignature {
        let (nonce_pallas, nonce_25519) = Self::get_nonce_scalars(secret_nonce);
        let nonce_point_pallas = PointPallas::generator() * nonce_pallas;
        let nonce_point_25519 = Point25519::mul_base(&nonce_25519);
        let challenge =
            self.make_own_public_key_identity_challenge(&nonce_point_pallas, &nonce_point_25519);
        let signature_pallas = nonce_pallas
            + utils::c25519_scalar_to_pallas_scalar(self.private_key)
                * utils::c25519_scalar_to_pallas_scalar(challenge);
        let signature_25519 = nonce_25519 + self.private_key * challenge;
        utils::DualSchnorrSignature {
            nonce_pallas: nonce_point_pallas,
            nonce_25519: nonce_point_25519,
            signature_pallas,
            signature_25519,
        }
    }

    pub fn verify_public_key_identity(
        public_key_pallas: &PointPallas,
        public_key_25519: &Point25519,
        signature: &utils::DualSchnorrSignature,
    ) -> Result<()> {
        let challenge_25519 = Self::make_public_key_identity_challenge(
            public_key_pallas,
            public_key_25519,
            &signature.nonce_pallas,
            &signature.nonce_25519,
        );
        let challenge_pallas = utils::c25519_scalar_to_pallas_scalar(challenge_25519);
        if Point25519::mul_base(&signature.signature_25519)
            != signature.nonce_25519 + public_key_25519 * challenge_25519
        {
            return Err(anyhow!("invalid signature"));
        }
        if PointPallas::generator() * signature.signature_pallas
            != signature.nonce_pallas + public_key_pallas * challenge_pallas
        {
            return Err(anyhow!("invalid signature"));
        }
        Ok(())
    }

    fn hash_to_curve(message: &[u8]) -> Point25519 {
        const DOMAIN_SEPARATOR: &str = "dotakon/vrf-v1";
        Point25519::hash_to_curve::<sha3::Sha3_512>(&[message], &[DOMAIN_SEPARATOR.as_bytes()])
    }

    fn make_verifiable_randomness_challenge(
        h: &Point25519,
        r: &Point25519,
        u: &Point25519,
        v: &Point25519,
    ) -> Scalar25519 {
        const DOMAIN_SEPARATOR: &str = "dotakon/vrf-v1";
        let message = format!(
            "{{domain=\"{}\",h={:#x},r={:#x},u={:#x},v={:#x}}}",
            DOMAIN_SEPARATOR,
            utils::compress_point_c25519(h),
            utils::compress_point_c25519(r),
            utils::compress_point_c25519(u),
            utils::compress_point_c25519(v),
        );
        Scalar25519::hash_from_bytes::<sha3::Sha3_512>(message.as_bytes())
    }

    pub fn get_verifiable_randomness(
        &self,
        message: &[u8],
        secret_nonce: H256,
    ) -> utils::VerifiableRandomness {
        let hash = Self::hash_to_curve(message);
        let randomness = hash * self.private_key;
        let nonce = utils::hash_to_c25519_scalar(secret_nonce);
        let u = Point25519::mul_base(&nonce);
        let v = hash * nonce;
        let challenge = Self::make_verifiable_randomness_challenge(&hash, &randomness, &u, &v);
        let signature = nonce + self.private_key * challenge;
        utils::VerifiableRandomness {
            output: randomness,
            challenge,
            signature,
        }
    }

    pub fn verify_randomness(
        public_key: &Point25519,
        message: &[u8],
        randomness: &utils::VerifiableRandomness,
    ) -> Result<()> {
        let hash = Self::hash_to_curve(message);
        let u = Point25519::mul_base(&randomness.signature) - public_key * randomness.challenge;
        let v = hash * randomness.signature - randomness.output * randomness.challenge;
        let challenge =
            Self::make_verifiable_randomness_challenge(&hash, &randomness.output, &u, &v);
        if challenge != randomness.challenge {
            return Err(anyhow!("invalid VRF proof"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn test_key_manager() {
        let secret_key = H256::from_slice(&[
            8u8, 7, 6, 5, 4, 3, 2, 1, 16, 15, 14, 13, 12, 11, 10, 9, 24, 23, 22, 21, 20, 19, 18,
            17, 32, 31, 30, 29, 28, 27, 0, 0,
        ]);
        let key_manager = KeyManager::new(secret_key);
        assert_eq!(
            key_manager.public_key(),
            "0xb90f39d546dddd466a131becf6bcb23b5ed621bdb08a1dbd719041ea0d61e6bd"
                .parse()
                .unwrap()
        );
        assert_eq!(
            key_manager.public_key_25519(),
            "0x0bb5a735befdf9da0dd2998a1a4e972e1cf8f6df479d11722f81557770e9dff6"
                .parse()
                .unwrap()
        );
        assert_eq!(
            key_manager.wallet_address(),
            "0xc339ee2a90762fbeb97de4c0e2eabd81023e71d0ddec6072d7f4934cd2e4ecc9"
                .parse()
                .unwrap()
        );
    }

    fn test_schnorr_signature(secret_key: H256) {
        let key_manager = KeyManager::new(secret_key);
        let message = "Hello, world!";
        let signature = key_manager.sign(
            message.as_bytes(),
            H256::from_slice(&[
                1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
            ]),
        );
        assert!(
            KeyManager::verify(
                message.as_bytes(),
                &key_manager.public_key_point_pallas,
                &signature
            )
            .is_ok()
        );
    }

    #[test]
    fn test_schnorr_signature1() {
        let (secret_key, _, _) = utils::testing_keys1();
        test_schnorr_signature(secret_key);
    }

    #[test]
    fn test_schnorr_signature2() {
        let (secret_key, _, _) = utils::testing_keys2();
        test_schnorr_signature(secret_key);
    }

    #[test]
    fn test_signature_wrong_message() {
        let (secret_key, _, _) = utils::testing_keys1();
        let key_manager = KeyManager::new(secret_key);
        let nonce = H256::from_slice(&[
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 32,
        ]);
        let signature = key_manager.sign("Hello, world!".as_bytes(), nonce);
        assert!(
            !KeyManager::verify(
                "World, hello!".as_bytes(),
                &key_manager.public_key_point_pallas,
                &signature
            )
            .is_ok()
        );
    }

    #[test]
    fn test_signature_wrong_public_key() {
        let (secret_key1, _, _) = utils::testing_keys1();
        let key_manager1 = KeyManager::new(secret_key1);
        let (secret_key2, _, _) = utils::testing_keys2();
        let key_manager2 = KeyManager::new(secret_key2);
        let message = "Hello, world!";
        let nonce = H256::from_slice(&[
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 32,
        ]);
        let signature = key_manager1.sign(message.as_bytes(), nonce);
        assert!(
            !KeyManager::verify(
                message.as_bytes(),
                &key_manager2.public_key_point_pallas,
                &signature
            )
            .is_ok()
        );
    }

    fn test_message_signature(secret_key: H256) {
        let key_manager = KeyManager::new(secret_key);
        let message = proto::h256_to_bytes32(H256::from_slice(&[
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 32,
        ]));
        let (any, signature) = key_manager
            .sign_message(
                &message,
                H256::from_slice(&[
                    32u8, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14,
                    13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1,
                ]),
            )
            .unwrap();
        assert!(KeyManager::verify_signed_message(&any, &signature).is_ok());
    }

    #[test]
    fn test_message_signature1() {
        let (secret_key, _, _) = utils::testing_keys1();
        test_message_signature(secret_key);
    }

    #[test]
    fn test_message_signature2() {
        let (secret_key, _, _) = utils::testing_keys2();
        test_message_signature(secret_key);
    }

    #[test]
    fn test_message_signature_wrong_message() {
        let (secret_key, _, _) = utils::testing_keys1();
        let key_manager = KeyManager::new(secret_key);
        let message1 = proto::h256_to_bytes32(H256::from_slice(&[
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 32,
        ]));
        let (_, signature) = key_manager
            .sign_message(
                &message1,
                H256::from_slice(&[
                    32u8, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14,
                    13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1,
                ]),
            )
            .unwrap();
        let message2 = proto::h256_to_bytes32(H256::from_slice(&[
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 32, 31, 30,
        ]));
        let any2 = prost_types::Any::from_msg(&message2).unwrap();
        assert!(!KeyManager::verify_signed_message(&any2, &signature).is_ok());
    }

    #[test]
    fn test_message_signature_wrong_public_key() {
        let (secret_key1, _, _) = utils::testing_keys1();
        let key_manager = KeyManager::new(secret_key1);
        let (_, public_key2, _) = utils::testing_keys2();
        let message = proto::h256_to_bytes32(H256::from_slice(&[
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 32,
        ]));
        let (any, mut signature) = key_manager
            .sign_message(
                &message,
                H256::from_slice(&[
                    32u8, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14,
                    13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1,
                ]),
            )
            .unwrap();
        signature.public_key = Some(public_key2.to_fixed_bytes().to_vec());
        signature.signer = Some(proto::h256_to_bytes32(utils::public_key_to_wallet_address(
            public_key2,
        )));
        assert!(!KeyManager::verify_signed_message(&any, &signature).is_ok());
    }

    #[test]
    fn test_message_signature_wrong_signer_address() {
        let (secret_key1, _, _) = utils::testing_keys1();
        let key_manager = KeyManager::new(secret_key1);
        let (_, public_key2, _) = utils::testing_keys2();
        let message = proto::h256_to_bytes32(H256::from_slice(&[
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 32,
        ]));
        let (any, mut signature) = key_manager
            .sign_message(
                &message,
                H256::from_slice(&[
                    32u8, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14,
                    13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1,
                ]),
            )
            .unwrap();
        signature.signer = Some(proto::h256_to_bytes32(utils::public_key_to_wallet_address(
            public_key2,
        )));
        assert!(!KeyManager::verify_signed_message(&any, &signature).is_ok());
    }

    #[test]
    fn test_message_signature_wrong_schema() {
        let (secret_key, _, _) = utils::testing_keys1();
        let key_manager = KeyManager::new(secret_key);
        let message = proto::h256_to_bytes32(H256::from_slice(&[
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 32,
        ]));
        let (any, mut signature) = key_manager
            .sign_message(
                &message,
                H256::from_slice(&[
                    32u8, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14,
                    13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1,
                ]),
            )
            .unwrap();
        signature.scheme = Some(dotakon::SignatureScheme::SigUnknown.into());
        assert!(!KeyManager::verify_signed_message(&any, &signature).is_ok());
    }

    fn test_ed25519_signature(secret_key: H256) {
        let key_manager = KeyManager::new(secret_key);
        let message = "Hello, world!";
        let signature = key_manager.sign_ed25519(message.as_bytes());
        let mut signature_bytes = [0u8; ed25519_dalek::SIGNATURE_LENGTH];
        signature_bytes.copy_from_slice(signature.as_slice());
        assert!(
            KeyManager::verify_ed25519(
                message.as_bytes(),
                key_manager.public_key_25519(),
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
        let key_manager1 = KeyManager::new(secret_key1);
        let (secret_key2, _, _) = utils::testing_keys2();
        let key_manager2 = KeyManager::new(secret_key2);
        let message = "Hello, world!";
        let signature = key_manager1.sign_ed25519(message.as_bytes());
        let mut signature_bytes = [0u8; ed25519_dalek::SIGNATURE_LENGTH];
        signature_bytes.copy_from_slice(signature.as_slice());
        assert!(
            !KeyManager::verify_ed25519(
                message.as_bytes(),
                key_manager2.public_key_25519(),
                &signature_bytes
            )
            .is_ok()
        );
    }

    #[test]
    fn test_remote_key_pair_construction() {
        let (secret_key, _, public_key) = utils::testing_keys1();
        let public_key_vec = public_key.to_fixed_bytes().to_vec();
        let km1 = KeyManager::new(secret_key);
        let km2 = Box::new(KeyManager::new(secret_key));
        let km3 = Arc::new(KeyManager::new(secret_key));
        let kp1: Box<dyn rcgen::RemoteKeyPair> = Box::new(RemoteEd25519KeyPair::from(&km1));
        let kp2: Box<dyn rcgen::RemoteKeyPair> = Box::new(RemoteEd25519KeyPair::from(km2));
        let kp3: Box<dyn rcgen::RemoteKeyPair> = Box::new(RemoteEd25519KeyPair::from(km3));
        assert_eq!(kp1.public_key().to_vec(), public_key_vec);
        assert_eq!(kp2.public_key().to_vec(), public_key_vec);
        assert_eq!(kp3.public_key().to_vec(), public_key_vec);
    }

    #[test]
    fn test_remote_key_pair_algorithm() {
        let (secret_key, _, _) = utils::testing_keys1();
        let key_manager = KeyManager::new(secret_key);
        let remote_key_pair: Box<dyn rcgen::RemoteKeyPair> =
            Box::new(RemoteEd25519KeyPair::from(&key_manager));
        assert_eq!(remote_key_pair.algorithm(), &rcgen::PKCS_ED25519);
    }

    fn test_remote_key_pair_public_key(secret_key: H256, public_key: H256) {
        let key_manager = KeyManager::new(secret_key);
        let remote_key_pair: Box<dyn rcgen::RemoteKeyPair> =
            Box::new(RemoteEd25519KeyPair::from(&key_manager));
        assert_eq!(
            remote_key_pair.public_key().to_vec(),
            public_key.to_fixed_bytes().to_vec(),
        );
    }

    #[test]
    fn test_remote_key_pair_public_key1() {
        let (secret_key, _, public_key) = utils::testing_keys1();
        test_remote_key_pair_public_key(secret_key, public_key);
    }

    #[test]
    fn test_remote_key_pair_public_key2() {
        let (secret_key, _, public_key) = utils::testing_keys2();
        test_remote_key_pair_public_key(secret_key, public_key);
    }

    fn test_remote_key_pair_signature(secret_key: H256, public_key: H256) {
        let key_manager = KeyManager::new(secret_key);
        let remote_key_pair: Box<dyn rcgen::RemoteKeyPair> =
            Box::new(RemoteEd25519KeyPair::from(&key_manager));
        let message = "SATOR AREPO TENET OPERA ROTAS";
        let signature = remote_key_pair.sign(message.as_bytes()).unwrap();
        let mut signature_bytes = [0u8; ed25519_dalek::SIGNATURE_LENGTH];
        signature_bytes.copy_from_slice(signature.as_slice());
        assert!(
            KeyManager::verify_ed25519(message.as_bytes(), public_key, &signature_bytes).is_ok()
        );
    }

    #[test]
    fn test_remote_key_pair_signature1() {
        let (secret_key, _, public_key) = utils::testing_keys1();
        test_remote_key_pair_signature(secret_key, public_key);
    }

    #[test]
    fn test_remote_key_pair_signature2() {
        let (secret_key, _, public_key) = utils::testing_keys2();
        test_remote_key_pair_signature(secret_key, public_key);
    }

    fn test_key_identity_proof(secret_key: H256) {
        let key_manager = KeyManager::new(secret_key);
        let signature = key_manager.prove_public_key_identity(H256::from_slice(&[
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 0, 0,
        ]));
        assert!(
            KeyManager::verify_public_key_identity(
                &key_manager.public_key_point_pallas,
                &key_manager.public_key_point_25519,
                &signature,
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
    fn test_key_identity_proof_determinism() {
        let (secret_key, _, _) = utils::testing_keys1();
        let key_manager = KeyManager::new(secret_key);
        let signature1 = key_manager.prove_public_key_identity(H256::from_slice(&[
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 0, 0,
        ]));
        let signature2 = key_manager.prove_public_key_identity(H256::from_slice(&[
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 0, 0,
        ]));
        let signature3 = key_manager.prove_public_key_identity(H256::from_slice(&[
            30u8, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10,
            9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 0,
        ]));
        assert_eq!(signature1, signature2);
        assert_ne!(signature2, signature3);
    }

    #[test]
    fn test_key_identity_proof_failure() {
        let (secret_key1, _, _) = utils::testing_keys1();
        let key_manager1 = KeyManager::new(secret_key1);
        let (secret_key2, _, _) = utils::testing_keys2();
        let key_manager2 = KeyManager::new(secret_key2);
        let signature = key_manager1.prove_public_key_identity(H256::from_slice(&[
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 0, 0,
        ]));
        assert!(
            !KeyManager::verify_public_key_identity(
                &key_manager2.public_key_point_pallas,
                &key_manager2.public_key_point_25519,
                &signature,
            )
            .is_ok()
        );
    }

    fn test_verifiable_randomness(secret_key: H256) {
        let key_manager = KeyManager::new(secret_key);
        let message = "Hello, world!";
        let nonce = H256::from_slice(&[
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 0, 0,
        ]);
        let randomness = key_manager.get_verifiable_randomness(message.as_bytes(), nonce);
        assert!(
            KeyManager::verify_randomness(
                &utils::decompress_point_c25519(key_manager.public_key_25519()).unwrap(),
                message.as_bytes(),
                &randomness
            )
            .is_ok()
        );
    }

    #[test]
    fn test_verifiable_randomness1() {
        let (secret_key, _, _) = utils::testing_keys1();
        test_verifiable_randomness(secret_key);
    }

    #[test]
    fn test_verifiable_randomness2() {
        let (secret_key, _, _) = utils::testing_keys2();
        test_verifiable_randomness(secret_key);
    }

    #[test]
    fn test_verify_randomness_with_wrong_key() {
        let (secret_key1, _, _) = utils::testing_keys1();
        let (_, _, public_key2) = utils::testing_keys2();
        let key_manager = KeyManager::new(secret_key1);
        let message = "Hello, world!";
        let nonce = H256::from_slice(&[
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 0, 0,
        ]);
        let randomness = key_manager.get_verifiable_randomness(message.as_bytes(), nonce);
        assert!(
            KeyManager::verify_randomness(
                &utils::decompress_point_c25519(public_key2).unwrap(),
                message.as_bytes(),
                &randomness
            )
            .is_err()
        );
    }

    #[test]
    fn test_verify_randomness_with_wrong_message() {
        let (secret_key, _, public_key) = utils::testing_keys1();
        let key_manager = KeyManager::new(secret_key);
        let message1 = "Hello, world!";
        let nonce = H256::from_slice(&[
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 0, 0,
        ]);
        let randomness = key_manager.get_verifiable_randomness(message1.as_bytes(), nonce);
        let message2 = "World, hello!";
        assert!(
            KeyManager::verify_randomness(
                &utils::decompress_point_c25519(public_key).unwrap(),
                message2.as_bytes(),
                &randomness
            )
            .is_err()
        );
    }
}
