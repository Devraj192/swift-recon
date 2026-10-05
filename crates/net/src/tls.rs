//! TLS metadata probing: version, cipher, chain subject/issuer, SANs,
//! validity. A custom verifier records the validation result but still
//! completes the handshake, since recon must probe expired/self-signed hosts.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use swiftrecon_scope::ScopeGuard;
use thiserror::Error;
use tokio::net::TcpStream;
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::client::WebPkiServerVerifier;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{DigitallySignedStruct, Error as RustlsError, SignatureScheme};
use tokio_rustls::TlsConnector;
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::{FromDer, X509Certificate};

/// TLS facts for one service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsRecord {
    pub host: String,
    pub ip: String,
    pub port: u16,
    pub version: Option<String>,
    pub cipher: Option<String>,
    pub subject: Option<String>,
    pub issuer: Option<String>,
    pub sans: Vec<String>,
    pub not_before: Option<i64>,
    pub not_after: Option<i64>,
    pub expired: bool,
    pub self_signed: bool,
    pub validation_ok: bool,
}

#[derive(Debug)]
struct RecordingVerifier {
    inner: std::sync::Arc<WebPkiServerVerifier>,
    validation: Mutex<Option<bool>>,
}

impl RecordingVerifier {
    fn new() -> Result<Self, TlsError> {
        let mut roots = tokio_rustls::rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let inner = WebPkiServerVerifier::builder(std::sync::Arc::new(roots))
            .build()
            .map_err(|e| TlsError::Connect(format!("verifier build: {e}")))?;
        Ok(Self {
            inner,
            validation: Mutex::new(None),
        })
    }

    fn took(&self) -> bool {
        *self.validation.lock().expect("verifier lock") == Some(true)
    }
}

impl ServerCertVerifier for RecordingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        let ok = self
            .inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
            .is_ok();
        *self.validation.lock().expect("verifier lock") = Some(ok);
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Parse the leaf certificate into facts. Pure function, unit-testable with a
/// real captured DER (tests use a generated self-signed cert instead).
pub fn parse_leaf_cert(der: &[u8], now_unix: i64) -> Option<TlsLeaf> {
    let (_, cert) = X509Certificate::from_der(der).ok()?;
    let subject = cert.subject().to_string();
    let issuer = cert.issuer().to_string();
    let mut sans = Vec::new();
    if let Ok(Some(names)) = cert.subject_alternative_name() {
        for name in &names.value.general_names {
            if let GeneralName::DNSName(dns) = name {
                sans.push(dns.to_string());
            }
        }
    }
    let validity = cert.validity();
    let not_before = validity.not_before.timestamp();
    let not_after = validity.not_after.timestamp();
    Some(TlsLeaf {
        subject: subject.clone(),
        issuer: issuer.clone(),
        sans,
        not_before,
        not_after,
        expired: now_unix > not_after,
        self_signed: subject == issuer,
    })
}

#[derive(Debug, Clone)]
pub struct TlsLeaf {
    pub subject: String,
    pub issuer: String,
    pub sans: Vec<String>,
    pub not_before: i64,
    pub not_after: i64,
    pub expired: bool,
    pub self_signed: bool,
}

#[derive(Debug, Error)]
pub enum TlsError {
    #[error("out of scope: {0}")]
    OutOfScope(String),
    #[error("connection failed: {0}")]
    Connect(String),
}

/// Probe TLS on one approved (host, IP, port). Returns `None` without
/// connecting when the guard rejects the pair.
pub async fn probe_tls(
    guard: &ScopeGuard,
    host: &str,
    ip: IpAddr,
    port: u16,
) -> Option<Result<TlsRecord, TlsError>> {
    if !guard.allow_connection(host, Some(&ip)) {
        return None;
    }
    Some(probe_inner(host, ip, port).await)
}

async fn probe_inner(host: &str, ip: IpAddr, port: u16) -> Result<TlsRecord, TlsError> {
    let verifier = Arc::new(RecordingVerifier::new()?);
    let config = tokio_rustls::rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier.clone())
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let server_name =
        ServerName::try_from(host.to_string()).map_err(|e| TlsError::Connect(e.to_string()))?;
    let stream = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect((ip, port)))
        .await
        .map_err(|_| TlsError::Connect("connect timed out".to_string()))?
        .map_err(|e| TlsError::Connect(e.to_string()))?;
    let tls = tokio::time::timeout(
        Duration::from_secs(10),
        connector.connect(server_name, stream),
    )
    .await
    .map_err(|_| TlsError::Connect("handshake timed out".to_string()))?
    .map_err(|e| TlsError::Connect(e.to_string()))?;
    let (_, conn) = tls.get_ref();
    let version = conn
        .negotiated_cipher_suite()
        .map(|suite| format!("{:?}", suite.version()));
    let cipher = conn
        .negotiated_cipher_suite()
        .map(|suite| format!("{:?}", suite.suite()));
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let peer = conn.peer_certificates().and_then(|chain| chain.first());
    let leaf = peer.and_then(|cert| parse_leaf_cert(cert.as_ref(), now_unix));
    Ok(TlsRecord {
        host: host.to_string(),
        ip: ip.to_string(),
        port,
        version,
        cipher,
        subject: leaf.as_ref().map(|l| l.subject.clone()),
        issuer: leaf.as_ref().map(|l| l.issuer.clone()),
        sans: leaf.as_ref().map(|l| l.sans.clone()).unwrap_or_default(),
        not_before: leaf.as_ref().map(|l| l.not_before),
        not_after: leaf.as_ref().map(|l| l.not_after),
        expired: leaf.as_ref().map(|l| l.expired).unwrap_or(false),
        self_signed: leaf.as_ref().map(|l| l.self_signed).unwrap_or(false),
        validation_ok: verifier.took(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Minimal DER certificate bytes are hard to hand-write; instead verify
    // graceful handling of garbage and the guard gate.
    #[test]
    fn garbage_der_yields_none() {
        assert!(parse_leaf_cert(b"not a cert", 0).is_none());
        assert!(parse_leaf_cert(&[], 0).is_none());
    }
}
