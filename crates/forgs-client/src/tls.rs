//! Client TLS trust: the single configuration every connection uses.
//!
//! * `pin = None` — verify the server against the **`WebPKI` roots** compiled
//!   into the binary (`webpki-roots`, not the platform store: a platform store
//!   would add a native dependency on musl and differ between a Pi and a
//!   laptop).
//! * `pin = Some(sha256)` — accept exactly the server leaf whose DER SHA-256
//!   matches: the escape hatch for a self-hosted server with no public DNS
//!   name and therefore no publicly trusted certificate.
//!
//! The `ring` provider is passed explicitly rather than installed as the
//! process default, so this crate neither depends on nor disturbs whatever
//! provider the embedding app chose.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Build the [`ClientConfig`] for connections to a forgs server (and the
/// GitHub Actions token service, which only ever uses `pin = None`).
///
/// Presents no client certificate: callers authenticate with bearer tokens.
///
/// # Panics
///
/// Never in practice: the `ring` provider supports rustls's default protocol
/// versions, which is the only failure `with_safe_default_protocol_versions`
/// can report.
#[must_use]
pub fn client_trust_config(pin: Option<[u8; 32]>) -> ClientConfig {
    let builder = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .expect("the ring provider supports the default protocol versions");
    match pin {
        Some(pin) => builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedServerCertVerifier::new(pin)))
            .with_no_client_auth(),
        None => builder
            .with_root_certificates(RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            })
            .with_no_client_auth(),
    }
}

/// The raw SHA-256 of a certificate's DER bytes.
#[must_use]
pub fn cert_sha256(cert: &CertificateDer<'_>) -> [u8; 32] {
    use sha2::{Digest as _, Sha256};
    Sha256::digest(cert.as_ref()).into()
}

/// The lowercase-hex SHA-256 fingerprint of a certificate — the value an
/// operator passes as a pin. Reproducible with
/// `openssl x509 -noout -fingerprint -sha256` (strip the colons).
#[must_use]
pub fn cert_fingerprint(cert: &CertificateDer<'_>) -> String {
    use std::fmt::Write as _;
    cert_sha256(cert)
        .iter()
        .fold(String::with_capacity(64), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
}

/// Parse a hex SHA-256 fingerprint: 64 hex digits, case-insensitive, with or
/// without `:` separators (as `openssl` prints it).
#[must_use]
pub fn parse_fingerprint(hex: &str) -> Option<[u8; 32]> {
    let digits: String = hex.trim().chars().filter(|c| *c != ':').collect();
    if digits.len() != 64 || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&digits[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// A [`ServerCertVerifier`] that accepts a server leaf **iff** its DER
/// SHA-256 equals the pin.
///
/// Accepts self-signed and leaf-only chains and ignores the server name and
/// intermediates: the pin is the sole check. Handshake signatures are still
/// verified, so the peer must hold the pinned certificate's private key.
#[derive(Debug)]
pub struct PinnedServerCertVerifier {
    pin: [u8; 32],
    provider: Arc<CryptoProvider>,
}

impl PinnedServerCertVerifier {
    /// A verifier accepting the leaf whose DER SHA-256 is `pin`.
    #[must_use]
    pub fn new(pin: [u8; 32]) -> Self {
        Self {
            pin,
            provider: provider(),
        }
    }
}

impl ServerCertVerifier for PinnedServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if cert_sha256(end_entity) == self.pin {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "server certificate does not match the pinned SHA-256".to_owned(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cert() -> CertificateDer<'static> {
        let key = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(vec!["forgs.test".to_owned()]).unwrap();
        params.self_signed(&key).unwrap().der().clone()
    }

    #[test]
    fn pin_matches_only_its_certificate() {
        let good = cert();
        let other = cert();
        let v = PinnedServerCertVerifier::new(cert_sha256(&good));
        let name = ServerName::try_from("anything.example").unwrap();
        let now = UnixTime::now();
        assert!(v.verify_server_cert(&good, &[], &name, &[], now).is_ok());
        assert!(v.verify_server_cert(&other, &[], &name, &[], now).is_err());
    }

    #[test]
    fn fingerprints_round_trip() {
        let c = cert();
        let hex = cert_fingerprint(&c);
        assert_eq!(hex.len(), 64);
        assert_eq!(parse_fingerprint(&hex), Some(cert_sha256(&c)));
        assert_eq!(
            parse_fingerprint(&format!("  {}  ", hex.to_uppercase())),
            Some(cert_sha256(&c))
        );
        let colons: Vec<String> = hex
            .as_bytes()
            .chunks(2)
            .map(|p| String::from_utf8(p.to_vec()).unwrap())
            .collect();
        assert_eq!(parse_fingerprint(&colons.join(":")), Some(cert_sha256(&c)));
    }

    #[test]
    fn bad_fingerprints_are_refused() {
        for bad in [
            "",
            "nope",
            &"a".repeat(63),
            &"a".repeat(65),
            &"g".repeat(64),
            &format!("+{}", "a".repeat(63)),
        ] {
            assert_eq!(parse_fingerprint(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn both_configs_build() {
        let _ = client_trust_config(None);
        let _ = client_trust_config(Some([7; 32]));
    }
}
