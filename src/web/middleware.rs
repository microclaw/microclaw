use super::*;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use sha2::{Digest, Sha256};
use std::net::IpAddr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub(super) enum AuthScope {
    Read,
    Write,
    Admin,
    Approvals,
}

#[derive(Clone, Debug)]
pub(super) struct AuthIdentity {
    pub(super) scopes: Vec<String>,
    pub(super) actor: String,
}

impl AuthIdentity {
    pub(super) fn allows(&self, required: AuthScope) -> bool {
        let want = match required {
            AuthScope::Read => "operator.read",
            AuthScope::Write => "operator.write",
            AuthScope::Admin => "operator.admin",
            AuthScope::Approvals => "operator.approvals",
        };
        self.scopes
            .iter()
            .any(|s| s == "operator.admin" || s == want)
    }
}

pub(super) fn auth_token_from_headers(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get("authorization")?.to_str().ok()?.trim();
    let mut parts = raw.splitn(2, char::is_whitespace);
    let scheme = parts.next()?.trim();
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = parts.next()?.trim();
    if token.is_empty() {
        return None;
    }
    Some(token.to_string())
}

pub(super) fn bootstrap_token_from_headers(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-bootstrap-token")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

pub(super) fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    format!("{:x}", hasher.finalize())
}

pub(super) fn parse_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get("cookie")?.to_str().ok()?;
    for part in raw.split(';') {
        let mut kv = part.trim().splitn(2, '=');
        let k = kv.next()?.trim();
        let v = kv.next().unwrap_or("").trim();
        if k == name && !v.is_empty() {
            return Some(v.to_string());
        }
    }
    None
}

pub(super) fn session_cookie_header(session_id: &str, expires_at: &str, secure: bool) -> String {
    let mut header =
        format!("mc_session={session_id}; Path=/; HttpOnly; SameSite=Strict; Expires={expires_at}");
    if secure {
        header.push_str("; Secure");
    }
    header
}

pub(super) fn csrf_cookie_header(csrf_token: &str, expires_at: &str, secure: bool) -> String {
    let mut header = format!("mc_csrf={csrf_token}; Path=/; SameSite=Strict; Expires={expires_at}");
    if secure {
        header.push_str("; Secure");
    }
    header
}

pub(super) fn clear_session_cookie_header() -> String {
    "mc_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0".to_string()
}

pub(super) fn clear_csrf_cookie_header() -> String {
    "mc_csrf=; Path=/; SameSite=Strict; Max-Age=0".to_string()
}

pub(super) fn make_password_hash(password: &str) -> String {
    let salt = SaltString::encode_b64(uuid::Uuid::new_v4().as_bytes())
        .unwrap_or_else(|_| SaltString::from_b64("AAAAAAAAAAAAAAAAAAAAAA").unwrap());
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .unwrap_or_default()
}

pub(super) fn verify_password_hash(stored: &str, password: &str) -> bool {
    if let Ok(parsed) = PasswordHash::new(stored) {
        return Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok();
    }
    let mut parts = stored.split('$');
    let Some(ver) = parts.next() else {
        return false;
    };
    if ver != "v1" {
        return false;
    }
    let Some(salt) = parts.next() else {
        return false;
    };
    let Some(hash) = parts.next() else {
        return false;
    };
    sha256_hex(&format!("{salt}:{password}")) == hash
}

pub(super) fn client_key_from_headers_with_config(headers: &HeaderMap, config: &Config) -> String {
    let trust_xff = config
        .channels
        .get("web")
        .and_then(|v| v.as_mapping())
        .and_then(|map| {
            map.get(serde_yaml::Value::String(
                "trust_x_forwarded_for".to_string(),
            ))
        })
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if !trust_xff {
        return "global".to_string();
    }
    parse_forwarded_client_ip(headers).unwrap_or_else(|| "global".to_string())
}

fn parse_forwarded_client_ip(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get("x-forwarded-for")?.to_str().ok()?;
    raw.split(',')
        .find_map(|part| normalize_forwarded_ip(part.trim()))
}

fn normalize_forwarded_ip(value: &str) -> Option<String> {
    if value.is_empty() {
        return None;
    }
    if let Ok(ip) = value.parse::<IpAddr>() {
        return Some(ip.to_string());
    }

    if let Some(rest) = value.strip_prefix('[') {
        let (host, _) = rest.split_once("]:")?;
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Some(ip.to_string());
        }
        return None;
    }

    if let Some((host, port)) = value.rsplit_once(':') {
        if !host.contains(':') && port.chars().all(|c| c.is_ascii_digit()) {
            if let Ok(ip) = host.parse::<IpAddr>() {
                return Some(ip.to_string());
            }
        }
    }
    None
}

async fn audit_auth_event(
    state: &WebState,
    actor: &str,
    action: &str,
    target: Option<&str>,
    status: &str,
    detail: Option<&str>,
) {
    let actor = actor.to_string();
    let action = action.to_string();
    let target = target.map(str::to_string);
    let status = status.to_string();
    let detail = detail.map(str::to_string);
    let _ = call_blocking(state.app_state.db.clone(), move |db| {
        db.log_audit_event(
            "auth",
            &actor,
            &action,
            target.as_deref(),
            &status,
            detail.as_deref(),
        )
        .map(|_| ())
    })
    .await;
}

fn api_key_limits(config: &Config) -> (usize, Duration) {
    if let Some(map) = config.channels.get("web").and_then(|v| v.as_mapping()) {
        let max = map
            .get(serde_yaml::Value::String(
                "api_key_max_requests_per_window".to_string(),
            ))
            .and_then(|v| v.as_u64())
            .map(|v| v.clamp(10, 10_000) as usize)
            .unwrap_or(240);
        let secs = map
            .get(serde_yaml::Value::String(
                "api_key_rate_window_seconds".to_string(),
            ))
            .and_then(|v| v.as_u64())
            .map(|v| v.clamp(1, 3600))
            .unwrap_or(60);
        return (max, Duration::from_secs(secs));
    }
    (240, Duration::from_secs(60))
}

pub(super) async fn require_scope(
    state: &WebState,
    headers: &HeaderMap,
    required: AuthScope,
) -> Result<AuthIdentity, (StatusCode, String)> {
    let needs_csrf = matches!(
        required,
        AuthScope::Write | AuthScope::Admin | AuthScope::Approvals
    );
    let has_password = call_blocking(state.app_state.db.clone(), |db| db.get_auth_password_hash())
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .is_some();
    if state.legacy_auth_token.is_none() && !has_password {
        #[cfg(test)]
        {
            let id = AuthIdentity {
                scopes: vec![
                    "operator.read".to_string(),
                    "operator.write".to_string(),
                    "operator.admin".to_string(),
                    "operator.approvals".to_string(),
                ],
                actor: "bootstrap-test".to_string(),
            };
            if id.allows(required) {
                return Ok(id);
            }
            return Err((StatusCode::FORBIDDEN, "forbidden".into()));
        }
        #[cfg(not(test))]
        return Err((StatusCode::UNAUTHORIZED, "unauthorized".into()));
    }

    if let Some(provided) = auth_token_from_headers(headers) {
        if let Some(expected) = state.legacy_auth_token.as_deref() {
            if provided == expected {
                let id = AuthIdentity {
                    scopes: vec![
                        "operator.read".to_string(),
                        "operator.write".to_string(),
                        "operator.admin".to_string(),
                        "operator.approvals".to_string(),
                    ],
                    actor: "legacy-token".to_string(),
                };
                if id.allows(required) {
                    return Ok(id);
                }
            }
        }

        let key_hash = sha256_hex(&provided);
        if let Some((key_id, scopes)) = call_blocking(state.app_state.db.clone(), move |db| {
            db.validate_api_key_hash(&key_hash)
        })
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        {
            let (max_requests, window) = api_key_limits(&state.app_state.config);
            let allowed = state
                .auth_hub
                .allow_api_key_request(&format!("api-key:{key_id}"), max_requests, window)
                .await;
            if !allowed {
                audit_auth_event(
                    state,
                    &format!("api-key:{key_id}"),
                    "api_key.rate_limited",
                    None,
                    "deny",
                    Some("api_key_rate_limit_exceeded"),
                )
                .await;
                return Err((StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded".into()));
            }

            let id = AuthIdentity {
                scopes,
                actor: format!("api-key:{key_id}"),
            };
            if id.allows(required) {
                return Ok(id);
            }
            audit_auth_event(
                state,
                &format!("api-key:{key_id}"),
                "api_key.scope_denied",
                None,
                "deny",
                Some("insufficient_scope"),
            )
            .await;
            return Err((StatusCode::FORBIDDEN, "forbidden".into()));
        }
    }

    if let Some(session_id) = parse_cookie(headers, "mc_session") {
        let session_id_for_validate = session_id.clone();
        let valid = call_blocking(state.app_state.db.clone(), move |db| {
            db.validate_auth_session(&session_id_for_validate)
        })
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        if valid {
            if needs_csrf {
                let cookie_csrf = parse_cookie(headers, "mc_csrf");
                let header_csrf = headers
                    .get("x-csrf-token")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());
                if cookie_csrf.is_none() || header_csrf.is_none() || cookie_csrf != header_csrf {
                    return Err((
                        StatusCode::FORBIDDEN,
                        "missing or invalid csrf token".into(),
                    ));
                }
            }
            let id = AuthIdentity {
                scopes: vec![
                    "operator.read".to_string(),
                    "operator.write".to_string(),
                    "operator.admin".to_string(),
                    "operator.approvals".to_string(),
                ],
                actor: format!("session:{session_id}"),
            };
            if id.allows(required) {
                return Ok(id);
            }
            return Err((StatusCode::FORBIDDEN, "forbidden".into()));
        }
    }

    audit_auth_event(
        state,
        "anonymous",
        "auth.unauthorized",
        None,
        "deny",
        Some("missing_or_invalid_credentials"),
    )
    .await;
    Err((StatusCode::UNAUTHORIZED, "unauthorized".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn xff_enabled_config() -> Config {
        let mut config = Config::test_defaults();
        let mut web = serde_yaml::Mapping::new();
        web.insert(
            serde_yaml::Value::String("trust_x_forwarded_for".to_string()),
            serde_yaml::Value::Bool(true),
        );
        config
            .channels
            .insert("web".to_string(), serde_yaml::Value::Mapping(web));
        config
    }

    #[test]
    fn test_auth_token_from_headers_accepts_case_insensitive_bearer() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "bearer test-key".parse().unwrap());
        assert_eq!(
            auth_token_from_headers(&headers).as_deref(),
            Some("test-key")
        );
    }

    #[test]
    fn test_auth_token_from_headers_rejects_non_bearer() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Basic abc".parse().unwrap());
        assert!(auth_token_from_headers(&headers).is_none());
    }

    #[test]
    fn test_client_key_from_headers_uses_valid_xff_ip() {
        let cfg = xff_enabled_config();
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            " 198.51.100.12:443, 10.0.0.1".parse().unwrap(),
        );
        assert_eq!(
            client_key_from_headers_with_config(&headers, &cfg),
            "198.51.100.12"
        );
    }

    #[test]
    fn test_client_key_from_headers_falls_back_for_invalid_xff() {
        let cfg = xff_enabled_config();
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "unknown, also-bad".parse().unwrap());
        assert_eq!(
            client_key_from_headers_with_config(&headers, &cfg),
            "global"
        );
    }
}
