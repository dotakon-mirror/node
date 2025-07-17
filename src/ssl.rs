use anyhow::{self, Context};
use ed25519_dalek::{self, Verifier};
use pasta_curves::{group::GroupEncoding, pallas::Point as PointPallas};
use primitive_types::H256;
use rustls::{
    SignatureScheme, client::danger::ServerCertVerifier, server::danger::ClientCertVerifier,
};
use std::sync::Arc;
use time::{Duration, OffsetDateTime};
use x509_parser::{self, certificate::X509Certificate};

use crate::keys;
use crate::utils;

pub fn generate_certificate(
    key_manager: Arc<keys::KeyManager>,
    canonical_address: String,
    secret_nonce: H256,
) -> anyhow::Result<rcgen::Certificate> {
    let remote_key_pair: Box<dyn rcgen::RemoteKeyPair + Send + Sync> =
        Box::new(keys::RemoteEd25519KeyPair::from(key_manager.clone()));
    let key_pair = rcgen::KeyPair::from_remote(remote_key_pair)?;

    let mut params = rcgen::CertificateParams::new(vec![canonical_address])?;

    let now = OffsetDateTime::now_utc();
    params.not_before = now - Duration::days(1);
    params.not_after = now + Duration::days(365);

    let wallet_address = utils::format_wallet_address(key_manager.wallet_address());
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, wallet_address);

    params.is_ca = rcgen::IsCa::ExplicitNoCa;

    let public_key_oid: Vec<u64> = utils::OID_DOTAKON_PALLAS_PUBLIC_KEY
        .iter()
        .unwrap()
        .collect();
    params
        .custom_extensions
        .push(rcgen::CustomExtension::from_oid_content(
            public_key_oid.as_slice(),
            key_manager.public_key().to_fixed_bytes().to_vec(),
        ));

    let signature = key_manager.prove_public_key_identity(secret_nonce);
    let identity_signature_oid: Vec<u64> = utils::OID_DOTAKON_IDENTITY_SIGNATURE_DUAL_SCHNORR
        .iter()
        .unwrap()
        .collect();
    params
        .custom_extensions
        .push(rcgen::CustomExtension::from_oid_content(
            identity_signature_oid.as_slice(),
            signature.encode(),
        ));

    Ok(params.self_signed(&key_pair)?)
}

fn get_cert_not_before(certificate: &X509Certificate) -> u64 {
    certificate.tbs_certificate.validity.not_before.timestamp() as u64
}

fn get_cert_not_after(certificate: &X509Certificate) -> u64 {
    certificate.tbs_certificate.validity.not_after.timestamp() as u64
}

pub fn recover_c25519_public_key(certificate: &X509Certificate) -> Result<H256, rustls::Error> {
    let public_key = certificate
        .tbs_certificate
        .subject_pki
        .parsed()
        .map_err(|_| rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding))?;
    let bytes = match public_key {
        // NOTE: the x509_parser doesn't handle Ed25519 keys yet, so our Ed25519 keys show up as
        // "unknown".
        x509_parser::public_key::PublicKey::Unknown(bytes) => Ok(bytes),
        _ => Err(rustls::Error::InvalidCertificate(
            rustls::CertificateError::UnsupportedSignatureAlgorithm,
        )),
    }?;
    if bytes.len() != 32 {
        return Err(rustls::Error::InvalidCertificate(
            rustls::CertificateError::BadEncoding,
        ));
    }
    Ok(H256::from_slice(bytes))
}

pub fn recover_pallas_public_key(certificate: &X509Certificate) -> Result<H256, rustls::Error> {
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
    Ok(H256::from_slice(&bytes))
}

#[derive(Debug, Clone)]
struct CertificateVerifier {}

impl CertificateVerifier {
    fn recover_identity_signature(
        certificate: &X509Certificate,
    ) -> Result<utils::DualSchnorrSignature, rustls::Error> {
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
        let mut bytes = [0u8; 128];
        bytes.copy_from_slice(extension.value);
        let signature = utils::DualSchnorrSignature::decode(&bytes).map_err(|_| {
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
        })?;
        Ok(signature)
    }

    fn verify_certificate(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        now: rustls::pki_types::UnixTime,
    ) -> Result<(), rustls::Error> {
        let (_, certificate) = x509_parser::parse_x509_certificate(end_entity).map_err(|_| {
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
        })?;

        if now.as_secs() < get_cert_not_before(&certificate) {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::NotValidYet,
            ));
        }
        if now.as_secs() > get_cert_not_after(&certificate) {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::Expired,
            ));
        }

        let public_key_25519 = recover_c25519_public_key(&certificate)?;
        let public_key_point_25519 =
            utils::decompress_point_c25519(public_key_25519).map_err(|_| {
                rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
            })?;

        let public_key_pallas = recover_pallas_public_key(&certificate)?;
        let public_key_point_pallas =
            match PointPallas::from_bytes(&public_key_pallas.to_fixed_bytes()).into_option() {
                Some(point) => Ok(point),
                None => Err(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::BadEncoding,
                )),
            }?;

        let signature = Self::recover_identity_signature(&certificate)?;

        keys::KeyManager::verify_public_key_identity(
            &public_key_point_pallas,
            &public_key_point_25519,
            &signature,
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

        let public_key = recover_c25519_public_key(&parsed_certificate)?;
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&public_key.to_fixed_bytes())
            .map_err(|_| {
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
        Self {
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
        Self {
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
    use anyhow::anyhow;
    use oid_registry;
    use rustls::CommonState;
    use tokio::{
        self,
        io::{AsyncReadExt, AsyncWriteExt},
    };

    #[test]
    fn test_certificate_generation() {
        let (secret_key, public_key_pallas, public_key_25519) = utils::testing_keys1();
        let key_manager = Arc::new(keys::KeyManager::new(secret_key));
        let nonce = H256::from_slice(&[
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 0, 0,
        ]);
        let certificate =
            generate_certificate(key_manager.clone(), "110.120.130.140".to_string(), nonce)
                .unwrap();
        let (_, parsed) = x509_parser::parse_x509_certificate(certificate.der()).unwrap();
        let common_names: Vec<&x509_parser::x509::AttributeTypeAndValue> =
            parsed.subject().iter_common_name().collect();
        assert_eq!(common_names.len(), 1);
        assert_eq!(
            common_names[0].attr_value().clone().string().unwrap(),
            utils::format_wallet_address(utils::public_key_to_wallet_address(public_key_pallas))
        );
        assert_eq!(
            parsed.tbs_certificate.signature.algorithm,
            oid_registry::OID_SIG_ED25519
        );
        assert_eq!(
            parsed.signature_algorithm.algorithm,
            oid_registry::OID_SIG_ED25519
        );
        assert_eq!(
            parsed.tbs_certificate.subject_pki.parsed().unwrap(),
            x509_parser::public_key::PublicKey::Unknown(
                public_key_25519.to_fixed_bytes().as_slice()
            )
        );
        assert_eq!(
            parsed.public_key().parsed().unwrap(),
            x509_parser::public_key::PublicKey::Unknown(
                public_key_25519.to_fixed_bytes().as_slice()
            )
        );
        assert_eq!(
            parsed
                .get_extension_unique(&utils::OID_DOTAKON_PALLAS_PUBLIC_KEY)
                .unwrap()
                .unwrap()
                .value,
            public_key_pallas.to_fixed_bytes().as_slice()
        );
        let identity_signature_extension = parsed
            .get_extension_unique(&utils::OID_DOTAKON_IDENTITY_SIGNATURE_DUAL_SCHNORR)
            .unwrap()
            .unwrap();
        let mut signature_bytes = [0u8; 128];
        signature_bytes.copy_from_slice(identity_signature_extension.value);
        keys::KeyManager::verify_public_key_identity(
            &utils::decompress_point_pallas(key_manager.public_key()).unwrap(),
            &utils::decompress_point_c25519(key_manager.public_key_25519()).unwrap(),
            &utils::DualSchnorrSignature::decode(&signature_bytes).unwrap(),
        )
        .unwrap();
    }

    fn test_recover_public_keys(secret_key: H256) {
        let key_manager = Arc::new(keys::KeyManager::new(secret_key));
        let nonce = H256::from_slice(&[
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 0, 0,
        ]);
        let certificate =
            generate_certificate(key_manager.clone(), "110.120.130.140".to_string(), nonce)
                .unwrap();
        let (_, parsed_certificate) =
            x509_parser::parse_x509_certificate(certificate.der()).unwrap();
        assert_eq!(
            recover_c25519_public_key(&parsed_certificate).unwrap(),
            key_manager.public_key_25519()
        );
        assert_eq!(
            recover_pallas_public_key(&parsed_certificate).unwrap(),
            key_manager.public_key()
        );
    }

    #[test]
    fn test_recover_public_keys1() {
        let (secret_key, _, _) = utils::testing_keys1();
        test_recover_public_keys(secret_key);
    }

    #[test]
    fn test_recover_public_keys2() {
        let (secret_key, _, _) = utils::testing_keys2();
        test_recover_public_keys(secret_key);
    }

    #[test]
    fn test_certificate_validity() {
        let (secret_key, _, _) = utils::testing_keys1();
        let key_manager = Arc::new(keys::KeyManager::new(secret_key));
        let nonce = H256::from_slice(&[
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 0, 0,
        ]);
        let certificate =
            generate_certificate(key_manager.clone(), "110.120.130.140".to_string(), nonce)
                .unwrap();
        let (_, parsed) = x509_parser::parse_x509_certificate(certificate.der()).unwrap();

        let now = OffsetDateTime::now_utc();
        let expected_not_before = now - Duration::days(1);
        let expected_not_after = now + Duration::days(365);

        let actual_not_before =
            OffsetDateTime::from_unix_timestamp(get_cert_not_before(&parsed) as i64).unwrap();
        let actual_not_after =
            OffsetDateTime::from_unix_timestamp(get_cert_not_after(&parsed) as i64).unwrap();

        assert!(actual_not_before >= expected_not_before - Duration::hours(1));
        assert!(actual_not_before <= expected_not_before + Duration::hours(1));
        assert!(actual_not_after >= expected_not_after - Duration::hours(1));
        assert!(actual_not_after <= expected_not_after + Duration::hours(1));
    }

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

    #[test]
    fn test_client_certificate_verification() {
        let (secret_key, _, _) = utils::testing_keys1();
        let key_manager = Arc::new(keys::KeyManager::new(secret_key));
        let nonce = H256::from_slice(&[
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 0, 0,
        ]);
        let certificate =
            generate_certificate(key_manager, "127.0.0.1".to_string(), nonce).unwrap();
        let verifier = DotakonClientCertVerifier::new();
        assert!(
            verifier
                .verify_client_cert(certificate.der(), &[], rustls::pki_types::UnixTime::now())
                .is_ok()
        );
    }

    #[test]
    fn test_not_yet_valid_client_certificate_verification() {
        let (secret_key, _, _) = utils::testing_keys1();
        let key_manager = Arc::new(keys::KeyManager::new(secret_key));
        let nonce = H256::from_slice(&[
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 0, 0,
        ]);
        let certificate =
            generate_certificate(key_manager, "127.0.0.1".to_string(), nonce).unwrap();
        let verifier = DotakonClientCertVerifier::new();
        assert!(
            !verifier
                .verify_client_cert(
                    certificate.der(),
                    &[],
                    rustls::pki_types::UnixTime::since_unix_epoch(std::time::Duration::from_secs(
                        (OffsetDateTime::now_utc() - Duration::days(2) - OffsetDateTime::UNIX_EPOCH)
                            .whole_seconds() as u64
                    )),
                )
                .is_ok()
        );
    }

    #[test]
    fn test_expired_client_certificate_verification() {
        let (secret_key, _, _) = utils::testing_keys1();
        let key_manager = Arc::new(keys::KeyManager::new(secret_key));
        let nonce = H256::from_slice(&[
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 0, 0,
        ]);
        let certificate =
            generate_certificate(key_manager, "127.0.0.1".to_string(), nonce).unwrap();
        let verifier = DotakonClientCertVerifier::new();
        assert!(
            !verifier
                .verify_client_cert(
                    certificate.der(),
                    &[],
                    rustls::pki_types::UnixTime::since_unix_epoch(std::time::Duration::from_secs(
                        (OffsetDateTime::now_utc() + Duration::days(366)
                            - OffsetDateTime::UNIX_EPOCH)
                            .whole_seconds() as u64
                    )),
                )
                .is_ok()
        );
    }

    fn check_peer(
        connection: &CommonState,
        peer_keys: Arc<keys::KeyManager>,
    ) -> anyhow::Result<()> {
        let certificates = connection
            .peer_certificates()
            .context("certificate not found")?;
        if certificates.len() != 1 {
            return Err(anyhow!(
                "unexpected number of mTLS certificates (expected: 1, got {})",
                certificates.len()
            ));
        }
        let (_, parsed_certificate) = x509_parser::parse_x509_certificate(&certificates[0])?;
        let public_key_25519 = recover_c25519_public_key(&parsed_certificate)?;
        if public_key_25519 != peer_keys.public_key_25519() {
            return Err(anyhow!("the c25519 public key doesn't match"));
        }
        let public_key_pallas = recover_pallas_public_key(&parsed_certificate)?;
        if public_key_pallas != peer_keys.public_key() {
            return Err(anyhow!("the Pallas public key doesn't match"));
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_mutual_tls() {
        let nonce = H256::from_slice(&[
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 0, 0,
        ]);

        let (server_secret_key, _, _) = utils::testing_keys1();
        let server_key_manager = Arc::new(keys::KeyManager::new(server_secret_key));
        let server_certificate =
            generate_certificate(server_key_manager.clone(), "server".to_string(), nonce).unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(
            rustls::ServerConfig::builder()
                .with_client_cert_verifier(Arc::new(DotakonClientCertVerifier::new()))
                .with_single_cert(
                    vec![server_certificate.der().clone()],
                    rustls::pki_types::PrivateKeyDer::Pkcs8(
                        rustls::pki_types::PrivatePkcs8KeyDer::from(
                            server_key_manager.export_private_key().unwrap(),
                        ),
                    ),
                )
                .unwrap(),
        ));

        let (client_secret_key, _, _) = utils::testing_keys2();
        let client_key_manager = Arc::new(keys::KeyManager::new(client_secret_key));
        let client_certificate =
            generate_certificate(client_key_manager.clone(), "client".to_string(), nonce).unwrap();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(DotakonServerCertVerifier::new()))
                .with_client_auth_cert(
                    vec![client_certificate.der().clone()],
                    rustls::pki_types::PrivateKeyDer::Pkcs8(
                        rustls::pki_types::PrivatePkcs8KeyDer::from(
                            client_key_manager.export_private_key().unwrap(),
                        ),
                    ),
                )
                .unwrap(),
        ));

        let (client_stream, server_stream) = tokio::io::duplex(4096);

        let server_task = tokio::task::spawn(async move {
            let mut stream = acceptor.accept(server_stream).await.unwrap();
            let (_, connection) = stream.get_ref();
            assert!(check_peer(connection, client_key_manager).is_ok());
            let mut buffer = [0u8; 4];
            stream.read_exact(&mut buffer).await.unwrap();
            assert_eq!(&buffer, b"ping");
            stream.write_all(b"pong").await.unwrap();
        });
        let client_task = tokio::spawn(async move {
            let mut stream = connector
                .connect("localhost".try_into().unwrap(), client_stream)
                .await
                .unwrap();
            let (_, connection) = stream.get_ref();
            assert!(check_peer(connection, server_key_manager).is_ok());
            stream.write_all(b"ping").await.unwrap();
            let mut buffer = [0u8; 4];
            stream.read_exact(&mut buffer).await.unwrap();
            assert_eq!(&buffer, b"pong");
        });

        let (result1, result2) = tokio::join!(server_task, client_task);
        assert!(result1.is_ok() && result2.is_ok());
    }
}
