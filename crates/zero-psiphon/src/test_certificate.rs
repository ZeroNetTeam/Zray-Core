//! A self-signed certificate for the crate's own TLS test servers.
//!
//! Two transports need a server that speaks TLS: TLS-OSSH, and the
//! TLS-fronted meek carrier. Both reach servers whose certificates are
//! self-signed and regenerated at every restart, so neither client can
//! verify one — which is exactly why the tests can use a certificate
//! generated once and checked in, rather than generating one per run.
//!
//! This certificate is test material and nothing else. It is not a secret:
//! the private key is in this file on purpose, so that the tests are
//! reproducible and need no build-time tooling.

/// A self-signed P-256 certificate, DER, base64.
pub const CERTIFICATE_DER: &str = "\
MIIBqjCCAVGgAwIBAgIUJ/6rwHHd6VFEEy83OETaqFAg9EIwCgYIKoZIzj0EAwIwHDEaMBgGA1UEAwwRemVyby1wc2lwaG9uLXRlc3Qw\
HhcNMjYxMDE5MjI1OTQ1WhcNNDYxMDE0MjI1OTQ1WjAcMRowGAYDVQQDDBF6ZXJvLXBzaXBob24tdGVzdDBZMBMGByqGSM49AgEGCCqG\
SM49AwEHA0IABPtQHXTfakIRvN96m2kSSWNyJNRviPMwbw99S2Sr1oKbkegYS8trqpG2ojuKHq7JQZ5YGB6wce53iZPd9n1aaaWjcTBv\
MB0GA1UdDgQWBBTkD/uttxVN+cMzvbVzCIVTdR7KVTAfBgNVHSMEGDAWgBTkD/uttxVN+cMzvbVzCIVTdR7KVTAPBgNVHRMBAf8EBTAD\
AQH/MBwGA1UdEQQVMBOCEXplcm8tcHNpcGhvbi10ZXN0MAoGCCqGSM49BAMCA0cAMEQCIFpL29nKOTvtnuggWUxFQU0/077fTiwhdQrN\
MS4fBanzAiBOi9Hc3RXImg33yBnRmM95+5nR02Mu5SGAjuDrCCUSKQ==";

/// The PKCS#8 private key for [`CERTIFICATE_DER`], DER, base64.
pub const PRIVATE_KEY_DER: &str = "\
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgIgCOQ8iLigeQN2LNgICI/fH4f+8iftjEil6mYYxVaoyhRANCAAT7UB10\
32pCEbzfeptpEkljciTUb4jzMG8PfUtkq9aCm5HoGEvLa6qRtqI7ih6uyUGeWBgesHHud4mT3fZ9Wmml";

/// The certificate and key as rustls wants them.
pub fn rustls_parts() -> (
    rustls::pki_types::CertificateDer<'static>,
    rustls::pki_types::PrivateKeyDer<'static>,
) {
    use base64::Engine as _;
    let certificate = rustls::pki_types::CertificateDer::from(
        base64::engine::general_purpose::STANDARD
            .decode(CERTIFICATE_DER)
            .expect("the test certificate is base64"),
    );
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
        base64::engine::general_purpose::STANDARD
            .decode(PRIVATE_KEY_DER)
            .expect("the test key is base64"),
    ));
    (certificate, key)
}

/// A TLS 1.3 server configuration using them.
pub fn tls_server_config() -> std::sync::Arc<rustls::ServerConfig> {
    let (certificate, key) = rustls_parts();
    std::sync::Arc::new(
        rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 is supported")
        .with_no_client_auth()
        .with_single_cert(vec![certificate], key)
        .expect("the test certificate and key match"),
    )
}
