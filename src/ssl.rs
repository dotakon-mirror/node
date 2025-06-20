use anyhow::Context;
use curve25519_dalek::{EdwardsPoint as Point25519, Scalar as Scalar25519};
use ed25519_dalek::{self, Verifier};
use pasta_curves::{
    group::GroupEncoding, pallas::Point as PointPallas, pallas::Scalar as ScalarPallas,
};
use primitive_types::U256;
use rustls::{
    SignatureScheme, client::danger::ServerCertVerifier, server::danger::ClientCertVerifier,
};
use x509_parser::{self, prelude::X509Certificate};

use crate::keys;
use crate::utils;

#[derive(Debug)]
struct DualSchnorrSignature {
    nonce_pallas: PointPallas,
    nonce_25519: Point25519,
    signature_pallas: ScalarPallas,
    signature_25519: Scalar25519,
}

#[derive(Debug, Clone)]
struct CertificateVerifier {}

impl CertificateVerifier {
    fn cert_not_before(certificate: &X509Certificate) -> u64 {
        certificate.tbs_certificate.validity.not_before.timestamp() as u64
    }

    fn cert_not_after(certificate: &X509Certificate) -> u64 {
        certificate.tbs_certificate.validity.not_after.timestamp() as u64
    }

    fn recover_c25519_public_key(
        certificate: &X509Certificate,
    ) -> Result<Point25519, rustls::Error> {
        let public_key = certificate
            .tbs_certificate
            .subject_pki
            .parsed()
            .map_err(|_| {
                rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
            })?;
        let ec_point = match public_key {
            x509_parser::public_key::PublicKey::EC(point) => Ok(point),
            _ => Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::UnsupportedSignatureAlgorithm,
            )),
        }?;
        if ec_point.key_size() != 32 {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::BadEncoding,
            ));
        }
        utils::decompress_point_c25519(U256::from_big_endian(ec_point.data()))
            .map_err(|_| rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding))
    }

    fn recover_pallas_public_key(
        certificate: &X509Certificate,
    ) -> Result<PointPallas, rustls::Error> {
        let extensions = certificate.extensions_map().map_err(|_| {
            rustls::Error::General("public Pallas key not found in X.509 certificate".into())
        })?;
        let extension = extensions
            .get(&utils::OID_DOTAKON_PALLAS_PUBLIC_KEY)
            .context("public Pallas key not found in X.509 certificate")
            .map_err(|error| rustls::Error::General(error.to_string()))?;
        if extension.value.len() != 32 {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::BadEncoding,
            ));
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(extension.value);
        match PointPallas::from_bytes(&bytes).into_option() {
            Some(point) => Ok(point),
            None => Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::BadEncoding,
            )),
        }
    }

    fn recover_identity_signature(
        certificate: &X509Certificate,
    ) -> Result<DualSchnorrSignature, rustls::Error> {
        let extensions = certificate.extensions_map().map_err(|_| {
            rustls::Error::General("identity signature not found in X.509 certificate".into())
        })?;
        let extension = extensions
            .get(&utils::OID_DOTAKON_IDENTITY_SIGNATURE_DUAL_SCHNORR)
            .context("identity signature not found in X.509 certificate")
            .map_err(|error| rustls::Error::General(error.to_string()))?;
        if extension.value.len() != 128 {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::BadEncoding,
            ));
        }

        let nonce_pallas =
            utils::decompress_point_pallas(U256::from_big_endian(&extension.value[0..32]))
                .map_err(|_| {
                    rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
                })?;
        let nonce_25519 =
            utils::decompress_point_c25519(U256::from_big_endian(&extension.value[32..64]))
                .map_err(|_| {
                    rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
                })?;
        let signature_pallas =
            utils::u256_to_pallas_scalar(U256::from_little_endian(&extension.value[64..96]))
                .map_err(|_| {
                    rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
                })?;
        let signature_25519 =
            utils::u256_to_c25519_scalar(U256::from_little_endian(&extension.value[96..128]))
                .map_err(|_| {
                    rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
                })?;

        Ok(DualSchnorrSignature {
            nonce_pallas,
            nonce_25519,
            signature_pallas,
            signature_25519,
        })
    }

    pub fn verify_certificate(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        now: rustls::pki_types::UnixTime,
    ) -> Result<(), rustls::Error> {
        let (_, certificate) =
            x509_parser::parse_x509_certificate(end_entity.as_ref()).map_err(|_| {
                rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
            })?;

        if now.as_secs() < Self::cert_not_before(&certificate) {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::NotValidYet,
            ));
        }
        if now.as_secs() > Self::cert_not_after(&certificate) {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::Expired,
            ));
        }

        let public_key_25519 = Self::recover_c25519_public_key(&certificate)?;
        let public_key_pallas = Self::recover_pallas_public_key(&certificate)?;
        let signature = Self::recover_identity_signature(&certificate)?;

        keys::KeyManager::verify_public_key_identity(
            &public_key_pallas,
            &public_key_25519,
            &signature.nonce_pallas,
            &signature.nonce_25519,
            signature.signature_pallas,
            signature.signature_25519,
        )
        .map_err(|_| rustls::Error::InvalidCertificate(rustls::CertificateError::BadSignature))?;

        Ok(())
    }

    fn verify_tls_signature(
        &self,
        message: &[u8],
        certificate: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        if dss.scheme != SignatureScheme::ED25519 {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::UnsupportedSignatureAlgorithm,
            ));
        }

        let (_, parsed_certificate) = x509_parser::parse_x509_certificate(certificate.as_ref())
            .map_err(|_| {
                rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
            })?;

        let public_key = parsed_certificate
            .tbs_certificate
            .subject_pki
            .parsed()
            .map_err(|_| {
                rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
            })?;
        let ec_point = match public_key {
            x509_parser::public_key::PublicKey::EC(point) => Ok(point),
            _ => Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::UnsupportedSignatureAlgorithm,
            )),
        }?;
        if ec_point.key_size() != ed25519_dalek::PUBLIC_KEY_LENGTH {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::BadEncoding,
            ));
        }
        let mut public_key_bytes = [0u8; ed25519_dalek::PUBLIC_KEY_LENGTH];
        public_key_bytes.copy_from_slice(ec_point.data());
        let verifying_key =
            ed25519_dalek::VerifyingKey::from_bytes(&public_key_bytes).map_err(|_| {
                rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
            })?;

        if dss.signature().len() != ed25519_dalek::SIGNATURE_LENGTH {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::BadEncoding,
            ));
        }
        let mut signature_bytes = [0u8; ed25519_dalek::SIGNATURE_LENGTH];
        signature_bytes.copy_from_slice(dss.signature());
        let signature = ed25519_dalek::Signature::from_bytes(&signature_bytes);

        verifying_key.verify(message, &signature).map_err(|_| {
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadSignature)
        })?;

        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
}

#[derive(Debug, Clone)]
pub struct DotakonClientCertVerifier {
    root_hint_subjects: [rustls::DistinguishedName; 0],
    verifier: CertificateVerifier,
}

impl DotakonClientCertVerifier {
    pub fn new() -> Self {
        DotakonClientCertVerifier {
            root_hint_subjects: [],
            verifier: CertificateVerifier {},
        }
    }
}

impl ClientCertVerifier for DotakonClientCertVerifier {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &self.root_hint_subjects
    }

    fn verify_client_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        self.verifier.verify_certificate(end_entity, now)?;
        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.verifier
            .verify_tls_signature(message, certificate, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.verifier
            .verify_tls_signature(message, certificate, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![rustls::SignatureScheme::ED25519]
    }

    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn requires_raw_public_keys(&self) -> bool {
        false
    }
}

#[derive(Debug, Clone)]
pub struct DotakonServerCertVerifier {
    verifier: CertificateVerifier,
}

impl DotakonServerCertVerifier {
    pub fn new() -> Self {
        DotakonServerCertVerifier {
            verifier: CertificateVerifier {},
        }
    }
}

impl ServerCertVerifier for DotakonServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        self.verifier.verify_certificate(end_entity, now)?;
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.verifier
            .verify_tls_signature(message, certificate, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.verifier
            .verify_tls_signature(message, certificate, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![rustls::SignatureScheme::ED25519]
    }

    fn requires_raw_public_keys(&self) -> bool {
        false
    }

    fn root_hint_subjects(&self) -> Option<&[rustls::DistinguishedName]> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_cert_verifier_parameters() {
        let verifier = DotakonClientCertVerifier::new();
        assert_eq!(verifier.root_hint_subjects().len(), 0);
        assert_eq!(
            verifier.supported_verify_schemes(),
            vec![rustls::SignatureScheme::ED25519]
        );
        assert!(verifier.offer_client_auth());
        assert!(verifier.client_auth_mandatory());
        assert!(!verifier.requires_raw_public_keys());
    }

    #[test]
    fn test_server_cert_verifier_parameters() {
        let verifier = DotakonServerCertVerifier::new();
        assert_eq!(
            verifier.supported_verify_schemes(),
            vec![rustls::SignatureScheme::ED25519]
        );
        assert!(!verifier.requires_raw_public_keys());
        assert!(verifier.root_hint_subjects().is_none());
    }

    // TODO
}
