//! SSRF (Server-Side Request Forgery) protection for URL-fetching tools.
//!
//! Resolves each URL's hostname to its IPs and blocks targets that point at
//! private/internal/cloud-metadata addresses. Inspired by the Python
//! `url_safety.py` in nousresearch/hermes-agent, with Rust-native resolution
//! semantics.
//!
//! Limitations:
//! - DNS rebinding (TOCTOU): an attacker-controlled DNS server with TTL=0 can
//!   return a public IP for the pre-flight check and then a private IP on the
//!   actual connect. Mitigating this requires connection-level validation
//!   (e.g. a socket-bound resolver or an egress proxy). This module performs
//!   pre-flight checks only.
//! - Redirect-based bypass is caller-responsibility — callers that follow
//!   redirects themselves should re-validate each hop.

use std::net::{IpAddr, ToSocketAddrs};
use std::time::Duration;

use reqwest::Url;

/// Hostnames that are always blocked regardless of IP resolution.
///
/// These reach cloud-metadata endpoints even when DNS resolves to a public
/// address (because the cloud platform does local routing).
const BLOCKED_HOSTNAMES: &[&str] = &["metadata.google.internal", "metadata.goog", "metadata"];

/// CGNAT / Shared Address Space (RFC 6598, 100.64.0.0/10) is not flagged by
/// `IpAddr::is_private`, so we check it explicitly. Used by carrier-grade
/// NAT, Tailscale/WireGuard VPNs, and some cloud internal networks.
fn is_cgnat(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            octets[0] == 100 && (octets[1] & 0xC0) == 64
        }
        IpAddr::V6(_) => false,
    }
}

/// Link-local IPv4 169.254.0.0/16 (covers AWS/Azure/GCP IMDSv1 169.254.169.254)
/// is marked as link-local by the stdlib but for clarity we assert it.
fn is_link_local(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_link_local(),
        IpAddr::V6(v6) => {
            let segments = v6.segments();
            (segments[0] & 0xFFC0) == 0xFE80
        }
    }
}

/// Returns true if the IP address belongs to a range that SSRF guards should
/// reject. Combines stdlib predicates with explicit CGNAT + extra-safe
/// link-local handling.
pub fn is_blocked_ip(ip: &IpAddr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return true;
    }
    if is_link_local(ip) {
        return true;
    }
    if is_cgnat(ip) {
        return true;
    }
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_private() {
                return true;
            }
            if v4.is_broadcast() {
                return true;
            }
            // IETF Protocol Assignments 192.0.0.0/24, documentation ranges,
            // and the benchmarking 198.18.0.0/15 range.
            let octets = v4.octets();
            if octets[0] == 192 && octets[1] == 0 && octets[2] == 0 {
                return true;
            }
            if octets[0] == 198 && (octets[1] == 18 || octets[1] == 19) {
                return true;
            }
            false
        }
        IpAddr::V6(v6) => {
            // Unique local fc00::/7 and IPv4-mapped forms of private ranges.
            let segs = v6.segments();
            if (segs[0] & 0xFE00) == 0xFC00 {
                return true;
            }
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_blocked_ip(&IpAddr::V4(v4));
            }
            false
        }
    }
}

/// Resolve `hostname` via the system resolver with a short timeout and
/// return all IP addresses. DNS failures return `None` (caller should fail
/// closed).
fn resolve_hostname(hostname: &str, timeout: Duration) -> Option<Vec<IpAddr>> {
    let host = hostname.to_string();
    let handle = std::thread::spawn(move || {
        (host.as_str(), 0u16)
            .to_socket_addrs()
            .ok()
            .map(|iter| iter.map(|sa| sa.ip()).collect::<Vec<_>>())
    });

    let start = std::time::Instant::now();
    loop {
        if handle.is_finished() {
            return handle.join().ok().flatten();
        }
        if start.elapsed() >= timeout {
            // Leak the resolver thread rather than block; fail closed.
            return None;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Pre-flight SSRF check for an already-parsed URL. Returns `Err(message)`
/// when the URL targets an address that should be blocked.
pub fn check_url_private_ip(url: &Url) -> Result<(), String> {
    let Some(host) = url.host_str() else {
        return Err("URL has no host".to_string());
    };

    let host_lower = host.to_ascii_lowercase();
    let hostname = host_lower.trim_end_matches('.');

    if BLOCKED_HOSTNAMES.contains(&hostname) {
        return Err(format!(
            "URL host '{host}' points at an internal metadata endpoint"
        ));
    }

    // If host is already an IP literal, validate it directly. Bracketed
    // IPv6 forms (e.g. "[::1]") come through `Url::host_str()` without
    // brackets in most parsers, but strip them defensively.
    let ip_candidate = hostname.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = ip_candidate.parse::<IpAddr>() {
        if is_blocked_ip(&ip) {
            return Err(format!(
                "URL host '{host}' resolves to a blocked address ({ip})"
            ));
        }
        return Ok(());
    }

    let Some(ips) = resolve_hostname(hostname, Duration::from_secs(3)) else {
        return Err(format!(
            "URL host '{host}' failed DNS resolution (SSRF check fails closed)"
        ));
    };

    if ips.is_empty() {
        return Err(format!("URL host '{host}' has no resolved IPs"));
    }

    for ip in &ips {
        if is_blocked_ip(ip) {
            return Err(format!(
                "URL host '{host}' resolves to a blocked private/internal address ({ip})"
            ));
        }
    }
    Ok(())
}

/// Pre-flight SSRF check for a raw URL string. Convenience wrapper that
/// parses the URL first.
pub fn check_raw_url_private_ip(raw_url: &str) -> Result<(), String> {
    let parsed = Url::parse(raw_url).map_err(|e| format!("invalid URL: {e}"))?;
    check_url_private_ip(&parsed)
}

/// A reqwest redirect policy that re-validates each hop against the SSRF
/// guard. Use with `reqwest::ClientBuilder::redirect(policy)` to catch
/// redirects inside third-party SDKs or forwarded requests that would
/// otherwise bypass the manual redirect loop in `web_fetch`.
///
/// Stops the redirect chain (returning an error that the caller sees as
/// a request failure) when a hop targets a blocked address. Follows up
/// to `max_redirects` hops when every hop passes.
pub fn ssrf_redirect_policy(max_redirects: usize) -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(move |attempt| {
        if attempt.previous().len() >= max_redirects {
            return attempt.error(format!("too many redirects (>{max_redirects})"));
        }
        if let Err(e) = check_url_private_ip(attempt.url()) {
            return attempt.error(format!("SSRF guard blocked redirect: {e}"));
        }
        attempt.follow()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_loopback_literal() {
        let err = check_raw_url_private_ip("http://127.0.0.1/").unwrap_err();
        assert!(err.contains("blocked"));
    }

    #[test]
    fn blocks_cloud_metadata_literal() {
        let err = check_raw_url_private_ip("http://169.254.169.254/latest/meta-data/").unwrap_err();
        assert!(err.contains("blocked"));
    }

    #[test]
    fn blocks_cloud_metadata_hostname() {
        let err = check_raw_url_private_ip("http://metadata.google.internal/").unwrap_err();
        assert!(err.contains("metadata"));
    }

    #[test]
    fn blocks_private_range_literal() {
        let err = check_raw_url_private_ip("http://10.0.0.1/").unwrap_err();
        assert!(err.contains("blocked"));
        let err = check_raw_url_private_ip("http://192.168.1.1/").unwrap_err();
        assert!(err.contains("blocked"));
        let err = check_raw_url_private_ip("http://172.16.0.1/").unwrap_err();
        assert!(err.contains("blocked"));
    }

    #[test]
    fn blocks_cgnat_literal() {
        let err = check_raw_url_private_ip("http://100.64.1.2/").unwrap_err();
        assert!(err.contains("blocked"));
    }

    #[test]
    fn blocks_ipv6_loopback() {
        let err = check_raw_url_private_ip("http://[::1]/").unwrap_err();
        assert!(err.contains("blocked"));
    }

    #[test]
    fn blocks_unique_local_ipv6() {
        let err = check_raw_url_private_ip("http://[fc00::1]/").unwrap_err();
        assert!(err.contains("blocked"));
    }

    #[test]
    fn allows_public_ipv4_literal() {
        assert!(check_raw_url_private_ip("https://1.1.1.1/").is_ok());
    }

    #[test]
    fn rejects_missing_host() {
        // reqwest parses file: URLs but they have no host.
        let err = check_raw_url_private_ip("file:///etc/passwd").unwrap_err();
        assert!(err.contains("no host") || err.contains("invalid URL"));
    }
}
