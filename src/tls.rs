use std::sync::OnceLock;

/// rustls 0.23 no longer picks a process-wide crypto backend in this build,
/// so WebSocket TLS callers must install one explicitly before connecting.
pub fn ensure_rustls_crypto_provider() -> Result<(), String> {
    static INIT: OnceLock<Result<(), String>> = OnceLock::new();

    INIT.get_or_init(|| {
        if rustls::crypto::CryptoProvider::get_default().is_some() {
            return Ok(());
        }

        match rustls::crypto::ring::default_provider().install_default() {
            Ok(()) => Ok(()),
            Err(_) if rustls::crypto::CryptoProvider::get_default().is_some() => Ok(()),
            Err(_) => Err("failed to install rustls ring CryptoProvider".to_string()),
        }
    })
    .clone()
}

#[cfg(test)]
mod tests {
    #[test]
    fn ensure_rustls_crypto_provider_is_idempotent() {
        super::ensure_rustls_crypto_provider().expect("install rustls provider");
        super::ensure_rustls_crypto_provider().expect("reuse rustls provider");
        assert!(rustls::crypto::CryptoProvider::get_default().is_some());
    }
}
