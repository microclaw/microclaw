use super::*;

pub(crate) async fn api_learning_observability(
    headers: HeaderMap,
    State(state): State<WebState>,
    Query(query): Query<UsageQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    metrics_http_inc(&state).await;
    require_scope(&state, &headers, AuthScope::Read).await?;

    let session_key = normalize_session_key(query.session_key.as_deref());
    let chat_id = resolve_chat_id_for_session_key_read(&state, &session_key).await?;
    let (
        goal,
        experience_summary,
        recent_runs,
        skills,
        task_utilities,
        failure_patterns,
        comparisons,
        claims,
        candidates,
        shadow_evaluations,
        journal,
        policy,
        learning_tracks,
        learning_epochs,
        learning_track_candidates,
        learning_candidate_evaluations,
    ) = call_blocking(state.app_state.db.clone(), move |db| {
        Ok((
            db.get_active_goal_state(chat_id)?,
            db.get_experience_summary(Some(chat_id))?,
            db.get_recent_experience_runs(Some(chat_id), 50)?,
            db.get_skill_learning_summaries()?,
            db.get_skill_task_utility_summaries(None)?,
            db.get_skill_failure_patterns(None)?,
            db.get_experience_comparisons(Some(chat_id), 100)?,
            db.get_learning_claims(Some(chat_id), 100)?,
            db.get_skill_candidates(Some(chat_id), 100)?,
            db.get_shadow_evaluations(Some(chat_id))?,
            db.get_learning_journal(Some(chat_id), 200)?,
            db.get_skill_governance_policy()?,
            db.list_learning_tracks(Some(chat_id))?,
            db.list_learning_epochs(chat_id, 100)?,
            db.list_learning_track_candidates(chat_id, 100)?,
            db.list_learning_candidate_evaluations(chat_id, 100)?,
        ))
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(json!({
        "ok": true,
        "session_key": session_key,
        "chat_id": chat_id,
        "active_goal": goal,
        "experience_summary": experience_summary,
        "recent_runs": recent_runs,
        "skills": skills,
        "skill_task_utilities": task_utilities,
        "skill_failure_patterns": failure_patterns,
        "comparisons": comparisons,
        "learning_claims": claims,
        "skill_candidates": candidates,
        "shadow_evaluations": shadow_evaluations,
        "learning_journal": journal,
        "governance_policy": policy,
        "learning_tracks": learning_tracks,
        "learning_epochs": learning_epochs,
        "learning_track_candidates": learning_track_candidates,
        "learning_candidate_evaluations": learning_candidate_evaluations,
    })))
}

pub(crate) async fn api_learning_evaluate_track_candidate(
    headers: HeaderMap,
    State(state): State<WebState>,
    Json(body): Json<LearningTrackCandidateActionRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    metrics_http_inc(&state).await;
    let actor = require_scope(&state, &headers, AuthScope::Admin)
        .await?
        .actor;
    let session_key = normalize_session_key(body.session_key.as_deref());
    let chat_id = resolve_chat_id_for_session_key_read(&state, &session_key).await?;
    let evaluation = crate::learning_foundry::evaluate_learning_candidate(
        &state.app_state,
        chat_id,
        &body.candidate_id,
    )
    .await
    .map_err(|error| (StatusCode::BAD_REQUEST, error))?;
    audit_log(
        &state,
        "learning",
        &actor,
        "evaluate_learning_track_candidate",
        Some(&body.candidate_id),
        "ok",
        Some(&evaluation.status),
    )
    .await;
    Ok(Json(json!({
        "ok": true,
        "candidate_id": body.candidate_id,
        "evaluation": evaluation
    })))
}

pub(crate) async fn api_learning_promote_track_candidate(
    headers: HeaderMap,
    State(state): State<WebState>,
    Json(body): Json<LearningTrackCandidateActionRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    metrics_http_inc(&state).await;
    let actor = require_scope(&state, &headers, AuthScope::Admin)
        .await?
        .actor;
    let session_key = normalize_session_key(body.session_key.as_deref());
    let chat_id = resolve_chat_id_for_session_key_read(&state, &session_key).await?;
    let skill_name = crate::learning_foundry::promote_learning_candidate(
        &state.app_state,
        chat_id,
        &body.candidate_id,
    )
    .await
    .map_err(|error| (StatusCode::BAD_REQUEST, error))?;
    audit_log(
        &state,
        "learning",
        &actor,
        "promote_learning_track_candidate",
        Some(&body.candidate_id),
        "ok",
        Some(&skill_name),
    )
    .await;
    Ok(Json(json!({
        "ok": true,
        "candidate_id": body.candidate_id,
        "skill_name": skill_name
    })))
}

pub(crate) async fn api_learning_feedback(
    headers: HeaderMap,
    State(state): State<WebState>,
    Json(body): Json<LearningFeedbackRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    metrics_http_inc(&state).await;
    let actor = require_scope(&state, &headers, AuthScope::Write)
        .await?
        .actor;
    if !matches!(body.verdict.as_str(), "passed" | "failed") {
        return Err((
            StatusCode::BAD_REQUEST,
            "verdict must be `passed` or `failed`".into(),
        ));
    }
    if body.run_id.is_empty() || body.run_id.len() > 128 {
        return Err((
            StatusCode::BAD_REQUEST,
            "run_id must be between 1 and 128 bytes".into(),
        ));
    }
    if body
        .evidence
        .as_ref()
        .is_some_and(|evidence| evidence.len() > 16 * 1024)
    {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            "evidence must not exceed 16384 bytes".into(),
        ));
    }
    if body.scope.as_ref().is_some_and(|scope| scope.len() > 256) {
        return Err((
            StatusCode::BAD_REQUEST,
            "scope must not exceed 256 bytes".into(),
        ));
    }
    if body.feedback_id.as_ref().is_some_and(|id| {
        id.is_empty()
            || id.len() > 64
            || !id
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_'))
    }) {
        return Err((
            StatusCode::BAD_REQUEST,
            "feedback_id must be 1-64 ASCII letters, digits, `-`, or `_`".into(),
        ));
    }
    if let Some(valid_until) = body.valid_until.as_deref() {
        let parsed = chrono::DateTime::parse_from_rfc3339(valid_until).map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                "valid_until must be an RFC3339 timestamp".to_string(),
            )
        })?;
        if parsed <= chrono::Utc::now() {
            return Err((
                StatusCode::BAD_REQUEST,
                "valid_until must be in the future".into(),
            ));
        }
    }
    let confidence = body.confidence.unwrap_or(1.0);
    if !(0.0..=1.0).contains(&confidence) {
        return Err((
            StatusCode::BAD_REQUEST,
            "confidence must be between 0 and 1".into(),
        ));
    }
    let session_key = normalize_session_key(body.session_key.as_deref());
    let chat_id = resolve_chat_id_for_session_key_read(&state, &session_key).await?;
    let run_id = body.run_id.clone();
    let belongs = call_blocking(state.app_state.db.clone(), move |db| {
        db.experience_run_belongs_to_chat(&run_id, chat_id)
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if !belongs {
        return Err((StatusCode::NOT_FOUND, "experience run not found".into()));
    }
    let run_id = body.run_id.clone();
    let verdict = body.verdict.clone();
    let evidence = body.evidence.clone();
    let scope = body.scope.clone();
    let feedback_id = body
        .feedback_id
        .clone()
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let verifier_name = format!("user_feedback:{actor}:{feedback_id}");
    let valid_until = body.valid_until.clone();
    let feedback_actor = actor.clone();
    let envelope_id = format!("feedback:{run_id}:{feedback_actor}:{feedback_id}");
    let response_feedback_id = feedback_id.clone();
    call_blocking(state.app_state.db.clone(), move |db| {
        db.ingest_outcome_envelope(&microclaw_engine::storage::db::OutcomeEnvelopeV1 {
            envelope_id,
            run_id,
            source_kind: "human".into(),
            source_name: verifier_name,
            verdict,
            confidence,
            evidence,
            scope,
            valid_until,
            payload: json!({"origin": "web_feedback"}),
            feedback: Some(microclaw_engine::storage::db::ExperienceFeedbackInput {
                feedback_id: feedback_id.clone(),
                actor: feedback_actor,
            }),
        })
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    audit_log(
        &state,
        "learning",
        &actor,
        "record_feedback",
        Some(&body.run_id),
        "ok",
        body.evidence.as_deref(),
    )
    .await;
    Ok(Json(json!({
        "ok": true,
        "run_id": body.run_id,
        "feedback_id": response_feedback_id,
        "verdict": body.verdict,
    })))
}

pub(crate) async fn api_learning_experiences(
    headers: HeaderMap,
    State(state): State<WebState>,
    Query(query): Query<LearningExperienceQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    metrics_http_inc(&state).await;
    require_scope(&state, &headers, AuthScope::Read).await?;
    let search = query.query.trim();
    if search.is_empty() || search.len() > 500 {
        return Err((
            StatusCode::BAD_REQUEST,
            "query must be between 1 and 500 bytes".into(),
        ));
    }
    if query
        .environment
        .as_ref()
        .is_some_and(|environment| environment.len() > 500)
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "environment must not exceed 500 bytes".into(),
        ));
    }
    let session_key = normalize_session_key(query.session_key.as_deref());
    let chat_id = resolve_chat_id_for_session_key_read(&state, &session_key).await?;
    let search = search.to_string();
    let environment = query.environment.clone();
    let limit = query.limit.unwrap_or(10).clamp(1, 20);
    let experiences = call_blocking(state.app_state.db.clone(), move |db| {
        db.search_verified_experiences(chat_id, &search, environment.as_deref(), limit)
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(json!({
        "ok": true,
        "session_key": session_key,
        "chat_id": chat_id,
        "experiences": experiences,
    })))
}

pub(crate) async fn api_learning_recovery_trial(
    headers: HeaderMap,
    State(state): State<WebState>,
    Json(body): Json<LearningRecoveryRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    metrics_http_inc(&state).await;
    let actor = require_scope(&state, &headers, AuthScope::Write)
        .await?
        .actor;
    let skill_name = body.skill_name.trim().to_string();
    let changed = call_blocking(state.app_state.db.clone(), {
        let skill_name = skill_name.clone();
        move |db| db.begin_skill_recovery_trial(&skill_name)
    })
    .await
    .map_err(|error| (StatusCode::BAD_REQUEST, error.to_string()))?;
    audit_log(
        &state,
        "learning",
        &actor,
        "begin_recovery_trial",
        Some(&skill_name),
        if changed { "ok" } else { "not_ready" },
        None,
    )
    .await;
    Ok(Json(
        json!({"ok": true, "changed": changed, "skill_name": skill_name}),
    ))
}

pub(crate) async fn api_learning_create_candidate(
    headers: HeaderMap,
    State(state): State<WebState>,
    Json(body): Json<LearningCandidateRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    metrics_http_inc(&state).await;
    let actor = require_scope(&state, &headers, AuthScope::Write)
        .await?
        .actor;
    let session_key = normalize_session_key(body.session_key.as_deref());
    let chat_id = resolve_chat_id_for_session_key_read(&state, &session_key).await?;
    let claim_id = body.claim_id.clone();
    let candidate = call_blocking(state.app_state.db.clone(), move |db| {
        db.create_skill_candidate_from_claim(&claim_id, chat_id)
    })
    .await
    .map_err(|error| (StatusCode::BAD_REQUEST, error.to_string()))?;
    audit_log(
        &state,
        "learning",
        &actor,
        "create_candidate",
        Some(&candidate.candidate_id),
        "ok",
        Some(&body.claim_id),
    )
    .await;
    Ok(Json(json!({"ok": true, "candidate": candidate})))
}

pub(crate) async fn api_learning_shadow_observation(
    headers: HeaderMap,
    State(state): State<WebState>,
    Json(body): Json<LearningShadowObservationRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    metrics_http_inc(&state).await;
    let actor = require_scope(&state, &headers, AuthScope::Write)
        .await?
        .actor;
    let session_key = normalize_session_key(body.session_key.as_deref());
    let chat_id = resolve_chat_id_for_session_key_read(&state, &session_key).await?;
    let input = body;
    let candidate_id = input.candidate_id.clone();
    let audit_candidate_id = candidate_id.clone();
    let evaluation = call_blocking(state.app_state.db.clone(), move |db| {
        db.record_shadow_observation(
            &candidate_id,
            chat_id,
            &input.pair_key,
            &input.arm,
            &input.run_id,
            &input.verdict,
            input.cost_usd,
            input.duration_ms,
            input.evidence.as_deref(),
        )
    })
    .await
    .map_err(|error| (StatusCode::BAD_REQUEST, error.to_string()))?;
    audit_log(
        &state,
        "learning",
        &actor,
        "record_shadow_observation",
        Some(&audit_candidate_id),
        "ok",
        Some(&evaluation.reason),
    )
    .await;
    Ok(Json(json!({"ok": true, "evaluation": evaluation})))
}

pub(crate) async fn api_learning_promote_candidate(
    headers: HeaderMap,
    State(state): State<WebState>,
    Json(body): Json<LearningCandidateActionRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    metrics_http_inc(&state).await;
    let actor = require_scope(&state, &headers, AuthScope::Admin)
        .await?
        .actor;
    let session_key = normalize_session_key(body.session_key.as_deref());
    let chat_id = resolve_chat_id_for_session_key_read(&state, &session_key).await?;
    let candidate_id = body.candidate_id.clone();
    let promoted = call_blocking(state.app_state.db.clone(), move |db| {
        db.promote_shadow_candidate(&candidate_id, chat_id)
    })
    .await
    .map_err(|error| (StatusCode::BAD_REQUEST, error.to_string()))?;
    audit_log(
        &state,
        "learning",
        &actor,
        "promote_candidate",
        Some(&body.candidate_id),
        "ok",
        Some(&format!("{} v{}", promoted.0, promoted.1)),
    )
    .await;
    Ok(Json(json!({
        "ok": true,
        "skill_name": promoted.0,
        "version": promoted.1
    })))
}

pub(crate) async fn api_learning_archive_entity(
    headers: HeaderMap,
    State(state): State<WebState>,
    Json(body): Json<LearningArchiveRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    metrics_http_inc(&state).await;
    let actor = require_scope(&state, &headers, AuthScope::Write)
        .await?
        .actor;
    let session_key = normalize_session_key(body.session_key.as_deref());
    let chat_id = resolve_chat_id_for_session_key_read(&state, &session_key).await?;
    let entity_type = body.entity_type.clone();
    let entity_id = body.entity_id.clone();
    let changed = call_blocking(state.app_state.db.clone(), move |db| {
        db.archive_learning_entity(&entity_type, &entity_id, chat_id)
    })
    .await
    .map_err(|error| (StatusCode::BAD_REQUEST, error.to_string()))?;
    audit_log(
        &state,
        "learning",
        &actor,
        "archive_learning_entity",
        Some(&body.entity_id),
        if changed { "ok" } else { "unchanged" },
        Some(&body.entity_type),
    )
    .await;
    Ok(Json(json!({"ok": true, "changed": changed})))
}

pub(crate) async fn api_learning_rollback_skill(
    headers: HeaderMap,
    State(state): State<WebState>,
    Json(body): Json<LearningRollbackRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    metrics_http_inc(&state).await;
    let actor = require_scope(&state, &headers, AuthScope::Admin)
        .await?
        .actor;
    let skill_name = body.skill_name.clone();
    let target_version = body.target_version;
    let rolled_back = call_blocking(state.app_state.db.clone(), move |db| {
        db.rollback_skill(
            &skill_name,
            target_version,
            "operator rollback via Learning Journal",
        )
    })
    .await
    .map_err(|error| (StatusCode::BAD_REQUEST, error.to_string()))?
    .ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            "no rollback version available".into(),
        )
    })?;
    audit_log(
        &state,
        "learning",
        &actor,
        "rollback_skill",
        Some(&body.skill_name),
        "ok",
        Some(&format!("restored v{}", rolled_back.0)),
    )
    .await;
    Ok(Json(json!({
        "ok": true,
        "skill_name": body.skill_name,
        "version": rolled_back.0
    })))
}

pub(crate) async fn api_learning_run_detail(
    headers: HeaderMap,
    State(state): State<WebState>,
    Path(run_id): Path<String>,
    Query(query): Query<LearningRunDetailQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    metrics_http_inc(&state).await;
    require_scope(&state, &headers, AuthScope::Read).await?;
    if run_id.is_empty() || run_id.len() > 128 {
        return Err((StatusCode::BAD_REQUEST, "invalid run_id".into()));
    }
    let session_key = normalize_session_key(query.session_key.as_deref());
    let chat_id = resolve_chat_id_for_session_key_read(&state, &session_key).await?;
    let detail = call_blocking(state.app_state.db.clone(), move |db| {
        let detail = db.get_experience_run_detail(&run_id)?;
        Ok(detail.filter(|detail| detail.run.chat_id == chat_id))
    })
    .await
    .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "experience run not found".into()))?;
    Ok(Json(json!({
        "ok": true,
        "session_key": session_key,
        "detail": detail
    })))
}

pub(crate) async fn api_learning_policy(
    headers: HeaderMap,
    State(state): State<WebState>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    metrics_http_inc(&state).await;
    require_scope(&state, &headers, AuthScope::Read).await?;
    let policy = call_blocking(state.app_state.db.clone(), |db| {
        db.get_skill_governance_policy()
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(json!({"ok": true, "policy": policy})))
}

pub(crate) async fn api_update_learning_policy(
    headers: HeaderMap,
    State(state): State<WebState>,
    Json(policy): Json<microclaw_engine::storage::db::SkillGovernancePolicy>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    metrics_http_inc(&state).await;
    let actor = require_scope(&state, &headers, AuthScope::Admin)
        .await?
        .actor;
    let saved = policy.clone();
    call_blocking(state.app_state.db.clone(), move |db| {
        db.update_skill_governance_policy(&saved)
    })
    .await
    .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    audit_log(
        &state,
        "learning",
        &actor,
        "update_governance_policy",
        None,
        "ok",
        None,
    )
    .await;
    Ok(Json(json!({"ok": true, "policy": policy})))
}
