use rustls::server::danger::ClientCertVerifier;
use x509_parser::time::ASN1Time;

use crate::keys;

fn asn1time_to_unix_seconds(t: &ASN1Time) -> u64 {
    t.timestamp() as u64
}

#[derive(Debug, Clone)]
pub struct CertVerifier<'a> {
    root_hint_subjects: [rustls::DistinguishedName; 0],
    key_manager: &'a keys::KeyManager,
}

impl<'a> CertVerifier<'a> {
    pub fn new(key_manager: &'a keys::KeyManager) -> Self {
        CertVerifier {
            root_hint_subjects: [],
            key_manager,
        }
    }
}

impl<'a> ClientCertVerifier for CertVerifier<'a> {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &self.root_hint_subjects
    }

    fn verify_client_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        let (_, certificate) = x509_parser::parse_x509_certificate(end_entity.as_ref())
            .map_err(|_| rustls::Error::General("invalid X.509 certificate".into()))?;

        if now.as_secs()
            < asn1time_to_unix_seconds(&certificate.tbs_certificate.validity.not_before)
        {
            return Err(rustls::Error::General("invalid certificate".into()));
        }
        if now.as_secs() > asn1time_to_unix_seconds(&certificate.tbs_certificate.validity.not_after)
        {
            return Err(rustls::Error::General("certificate expired".into()));
        }

        let alg_oid = certificate.signature_algorithm.algorithm;
        if alg_oid != oid_registry::OID_SIG_ED25519 {
            return Err(rustls::Error::General("only Ed25519 is supported".into()));
        }

        let spki = &certificate.tbs_certificate.subject_pki;
        if spki.algorithm.algorithm != oid_registry::OID_KEY_TYPE_EC_PUBLIC_KEY {
            return Err(rustls::Error::General("only Ed25519 is supported".into()));
        }

        todo!()
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        todo!()
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        todo!()
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
        true
    }
}
