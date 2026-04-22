//! Integration tests for multimedia tool HTTP plumbing. Full end-to-end
//! verification with live OpenAI-compatible endpoints is left to operator
//! smoke-tests; these tests exercise the bits that don't need real API
//! credentials.

use microclaw_tools::media_client::MediaClient;

#[test]
fn media_client_rejects_loopback_base_url() {
    // The SSRF guard on the configured base URL prevents an operator from
    // accidentally aiming multimedia traffic at loopback / metadata / private
    // addresses.
    let err = MediaClient::new("http://127.0.0.1/v1".into(), "k".into(), 5).unwrap_err();
    assert!(err.contains("blocked"), "expected SSRF block, got: {err}");
}

#[test]
fn media_client_rejects_private_host_base_url() {
    let err = MediaClient::new("http://10.0.0.1/v1".into(), "k".into(), 5).unwrap_err();
    assert!(err.contains("blocked"));
}

#[test]
fn media_client_rejects_cloud_metadata_base_url() {
    let err =
        MediaClient::new("http://169.254.169.254/".into(), "k".into(), 5).unwrap_err();
    assert!(err.contains("blocked") || err.contains("metadata"));
}

#[test]
fn media_client_rejects_non_http_base_url() {
    let err = MediaClient::new("ftp://api.openai.com/v1".into(), "k".into(), 5).unwrap_err();
    assert!(err.contains("invalid media base_url"));
}

#[test]
fn media_client_accepts_public_https() {
    // Public hostname should pass the SSRF guard. DNS must resolve to a
    // public IP in the test env — if CI's network is offline this will fail
    // closed, which is the desired behavior.
    let client = MediaClient::new("https://api.openai.com/v1".into(), "k".into(), 10);
    assert!(
        client.is_ok(),
        "expected public https URL to pass, got: {:?}",
        client.err()
    );
}
