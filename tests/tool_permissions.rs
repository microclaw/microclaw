//! Integration tests for the tool permission model.
//!
//! Tests the ToolAuthContext and authorization logic across various scenarios.

use microclaw::tools::{auth_context_from_input, authorize_chat_access, ToolAuthContext};
use serde_json::json;

// -----------------------------------------------------------------------
// ToolAuthContext
// -----------------------------------------------------------------------

#[test]
fn test_auth_context_control_chat() {
    let auth = ToolAuthContext {
        caller_channel: "telegram".into(),
        caller_chat_id: 100,
        control_chat_ids: vec![100, 200],
        env_files: vec![],
    };
    assert!(auth.is_control_chat());
    assert!(auth.can_access_chat(999)); // control can access any chat
}

#[test]
fn test_auth_context_regular_chat() {
    let auth = ToolAuthContext {
        caller_channel: "telegram".into(),
        caller_chat_id: 300,
        control_chat_ids: vec![100, 200],
        env_files: vec![],
    };
    assert!(!auth.is_control_chat());
    assert!(auth.can_access_chat(300)); // can access own chat
    assert!(!auth.can_access_chat(999)); // cannot access other chats
}

#[test]
fn test_auth_context_empty_control_list() {
    let auth = ToolAuthContext {
        caller_channel: "telegram".into(),
        caller_chat_id: 100,
        control_chat_ids: vec![],
        env_files: vec![],
    };
    assert!(!auth.is_control_chat());
    assert!(auth.can_access_chat(100)); // can access own
    assert!(!auth.can_access_chat(200)); // cannot access other
}

// -----------------------------------------------------------------------
// auth_context_from_input
// -----------------------------------------------------------------------

#[test]
fn test_auth_context_from_input_valid() {
    let input = json!({
        "some_param": "value",
        "__microclaw_auth": {
            "caller_chat_id": 42,
            "control_chat_ids": [42, 100]
        }
    });
    let auth = auth_context_from_input(&input).unwrap();
    assert_eq!(auth.caller_chat_id, 42);
    assert_eq!(auth.control_chat_ids, vec![42, 100]);
    assert!(auth.is_control_chat());
}

#[test]
fn test_auth_context_from_input_missing() {
    let input = json!({"some_param": "value"});
    assert!(auth_context_from_input(&input).is_none());
}

#[test]
fn test_auth_context_from_input_missing_caller_id() {
    let input = json!({
        "__microclaw_auth": {
            "control_chat_ids": [100]
        }
    });
    assert!(auth_context_from_input(&input).is_none());
}

#[test]
fn test_auth_context_from_input_empty_control_ids() {
    let input = json!({
        "__microclaw_auth": {
            "caller_chat_id": 42,
            "control_chat_ids": []
        }
    });
    let auth = auth_context_from_input(&input).unwrap();
    assert_eq!(auth.caller_chat_id, 42);
    assert!(auth.control_chat_ids.is_empty());
    assert!(!auth.is_control_chat());
}

#[test]
fn test_auth_context_from_input_no_control_ids_key() {
    let input = json!({
        "__microclaw_auth": {
            "caller_chat_id": 42
        }
    });
    let auth = auth_context_from_input(&input).unwrap();
    assert_eq!(auth.caller_chat_id, 42);
    assert!(auth.control_chat_ids.is_empty());
}

// -----------------------------------------------------------------------
// authorize_chat_access
// -----------------------------------------------------------------------

#[test]
fn test_authorize_same_chat_allowed() {
    let input = json!({
        "__microclaw_auth": {
            "caller_chat_id": 100,
            "control_chat_ids": []
        }
    });
    assert!(authorize_chat_access(&input, 100).is_ok());
}

#[test]
fn test_authorize_different_chat_denied() {
    let input = json!({
        "__microclaw_auth": {
            "caller_chat_id": 100,
            "control_chat_ids": []
        }
    });
    let err = authorize_chat_access(&input, 200).unwrap_err();
    assert!(err.contains("Permission denied"));
    assert!(err.contains("100"));
    assert!(err.contains("200"));
}

#[test]
fn test_authorize_control_chat_cross_access_allowed() {
    let input = json!({
        "__microclaw_auth": {
            "caller_chat_id": 100,
            "control_chat_ids": [100]
        }
    });
    // Control chat can access any chat
    assert!(authorize_chat_access(&input, 200).is_ok());
    assert!(authorize_chat_access(&input, 300).is_ok());
    assert!(authorize_chat_access(&input, 100).is_ok());
}

#[test]
fn test_authorize_no_auth_context_allows() {
    // When no auth context is present, access is allowed (backward compat)
    let input = json!({"chat_id": 200});
    assert!(authorize_chat_access(&input, 200).is_ok());
    assert!(authorize_chat_access(&input, 999).is_ok());
}

// -----------------------------------------------------------------------
// Permission matrix: all tool-relevant scenarios
// -----------------------------------------------------------------------

/// Regular user → own chat: ALLOW
#[test]
fn test_permission_matrix_regular_own() {
    let input = json!({
        "__microclaw_auth": {
            "caller_chat_id": 100,
            "control_chat_ids": []
        }
    });
    assert!(authorize_chat_access(&input, 100).is_ok());
}

/// Regular user → other chat: DENY
#[test]
fn test_permission_matrix_regular_other() {
    let input = json!({
        "__microclaw_auth": {
            "caller_chat_id": 100,
            "control_chat_ids": []
        }
    });
    assert!(authorize_chat_access(&input, 200).is_err());
}

/// Control user → own chat: ALLOW
#[test]
fn test_permission_matrix_control_own() {
    let input = json!({
        "__microclaw_auth": {
            "caller_chat_id": 100,
            "control_chat_ids": [100, 200]
        }
    });
    assert!(authorize_chat_access(&input, 100).is_ok());
}

/// Control user → other chat: ALLOW
#[test]
fn test_permission_matrix_control_other() {
    let input = json!({
        "__microclaw_auth": {
            "caller_chat_id": 100,
            "control_chat_ids": [100, 200]
        }
    });
    assert!(authorize_chat_access(&input, 999).is_ok());
}

/// Multiple control chats - only listed chats are control
#[test]
fn test_permission_matrix_multiple_control() {
    // Chat 100 is NOT in control list
    let input = json!({
        "__microclaw_auth": {
            "caller_chat_id": 100,
            "control_chat_ids": [200, 300]
        }
    });
    assert!(!auth_context_from_input(&input).unwrap().is_control_chat());
    assert!(authorize_chat_access(&input, 100).is_ok()); // own chat
    assert!(authorize_chat_access(&input, 200).is_err()); // not control, can't access other
}
