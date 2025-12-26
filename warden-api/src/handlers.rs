use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use chrono::Duration;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use warden_core::{
    validate_name, AddressEntry, ApprovalRequest, ApprovalRequirements, EvaluationResult, Policy,
    TransactionRequest,
};

use crate::state::AppState;

#[derive(Serialize)]
pub struct ApiError {
    pub error: String,
    pub code: String,
}

impl ApiError {
    fn new(error: impl Into<String>, code: impl Into<String>) -> Self {
        Self {
            error: error.into(),
            code: code.into(),
        }
    }
}

type ApiResult<T> = Result<Json<T>, (StatusCode, Json<ApiError>)>;

fn to_api_error(e: warden_core::Error) -> (StatusCode, Json<ApiError>) {
    let (status, code, message) = match &e {
        warden_core::Error::NoPolicyFound(id) => (
            StatusCode::NOT_FOUND,
            "POLICY_NOT_FOUND",
            format!("Policy not found: {}", id),
        ),
        warden_core::Error::PolicyValidation(msg) => (
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            format!("Validation error: {}", msg),
        ),
        warden_core::Error::PolicyParse(msg) => (
            StatusCode::BAD_REQUEST,
            "PARSE_ERROR",
            format!("Parse error: {}", msg),
        ),
        warden_core::Error::AddressListNotFound(name) => (
            StatusCode::NOT_FOUND,
            "LIST_NOT_FOUND",
            format!("Address list not found: {}", name),
        ),
        warden_core::Error::SessionNotFound(_) => (
            StatusCode::NOT_FOUND,
            "SESSION_NOT_FOUND",
            "Session not found".to_string(),
        ),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "An internal error occurred".to_string(),
        ),
    };
    (status, Json(ApiError::new(message, code)))
}

#[derive(Serialize)]
pub struct PolicySummary {
    pub id: Uuid,
    pub name: String,
    pub version: String,
    pub is_active: bool,
    pub rules_count: usize,
}

impl From<&Policy> for PolicySummary {
    fn from(p: &Policy) -> Self {
        Self {
            id: p.id,
            name: p.name.clone(),
            version: p.version.clone(),
            is_active: p.is_active,
            rules_count: p.rules.len(),
        }
    }
}

pub async fn list_policies(State(state): State<AppState>) -> ApiResult<Vec<PolicySummary>> {
    let policies = state.policy_store.list().await.map_err(to_api_error)?;
    Ok(Json(policies.iter().map(PolicySummary::from).collect()))
}

#[derive(Deserialize)]
pub struct CreatePolicyRequest {
    pub yaml: Option<String>,
    pub json: Option<serde_json::Value>,
}

pub async fn create_policy(
    State(state): State<AppState>,
    Json(req): Json<CreatePolicyRequest>,
) -> Result<(StatusCode, Json<Policy>), (StatusCode, Json<ApiError>)> {
    let policy = if let Some(yaml) = req.yaml {
        Policy::from_yaml(&yaml).map_err(to_api_error)?
    } else if let Some(json) = req.json {
        let json_str = serde_json::to_string(&json).map_err(|e| to_api_error(e.into()))?;
        Policy::from_json(&json_str).map_err(to_api_error)?
    } else {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ApiError::new(
                "Either yaml or json field required",
                "MISSING_FIELD",
            )),
        ));
    };

    let created = state
        .policy_store
        .create(policy)
        .await
        .map_err(to_api_error)?;
    Ok((StatusCode::CREATED, Json(created)))
}

pub async fn get_policy(State(state): State<AppState>, Path(id): Path<Uuid>) -> ApiResult<Policy> {
    let policy = state
        .policy_store
        .get(&id)
        .await
        .map_err(to_api_error)?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(ApiError::new(
                    format!("Policy {} not found", id),
                    "POLICY_NOT_FOUND",
                )),
            )
        })?;
    Ok(Json(policy))
}

pub async fn update_policy(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(req): Json<CreatePolicyRequest>,
) -> ApiResult<Policy> {
    state
        .policy_store
        .get(&id)
        .await
        .map_err(to_api_error)?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(ApiError::new(
                    format!("Policy {} not found", id),
                    "POLICY_NOT_FOUND",
                )),
            )
        })?;

    let mut policy = if let Some(yaml) = req.yaml {
        Policy::from_yaml(&yaml).map_err(to_api_error)?
    } else if let Some(json) = req.json {
        let json_str = serde_json::to_string(&json).map_err(|e| to_api_error(e.into()))?;
        Policy::from_json(&json_str).map_err(to_api_error)?
    } else {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ApiError::new(
                "Either yaml or json field required",
                "MISSING_FIELD",
            )),
        ));
    };

    policy.id = id;
    let updated = state
        .policy_store
        .update(policy)
        .await
        .map_err(to_api_error)?;
    Ok(Json(updated))
}

pub async fn delete_policy(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    state.policy_store.delete(&id).await.map_err(to_api_error)?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn activate_policy(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    state
        .policy_store
        .activate(&id)
        .await
        .map_err(to_api_error)?;
    Ok(StatusCode::OK)
}

pub async fn deactivate_policy(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    state
        .policy_store
        .deactivate(&id)
        .await
        .map_err(to_api_error)?;
    Ok(StatusCode::OK)
}

pub async fn evaluate_policy(
    State(state): State<AppState>,
    Json(req): Json<TransactionRequest>,
) -> ApiResult<EvaluationResult> {
    let result = state.evaluator.evaluate(&req).await.map_err(to_api_error)?;
    Ok(Json(result))
}

#[derive(Serialize)]
pub struct AuthorizationResult {
    pub transaction_id: Uuid,
    pub status: String,
    pub decision: warden_core::PolicyDecisionSerde,
    pub workflow_id: Option<Uuid>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

pub async fn authorize_transaction(
    State(state): State<AppState>,
    Json(req): Json<TransactionRequest>,
) -> ApiResult<AuthorizationResult> {
    let eval_result = state.evaluator.evaluate(&req).await.map_err(to_api_error)?;

    let (status, workflow_id, expires_at) = match &eval_result.decision {
        warden_core::PolicyDecisionSerde::Allow { .. } => ("APPROVED".to_string(), None, None),
        warden_core::PolicyDecisionSerde::Deny { .. } => ("DENIED".to_string(), None, None),
        warden_core::PolicyDecisionSerde::RequireApproval {
            approval_config, ..
        } => {
            let timeout = Duration::hours(approval_config.timeout_hours as i64);
            let requirements = ApprovalRequirements::simple(
                approval_config.quorum,
                approval_config.from_groups.clone(),
            );
            let approval_request =
                ApprovalRequest::new(req.id, eval_result.policy_id, requirements, timeout);

            let workflow_id = approval_request.id;
            let expires = approval_request.expires_at;

            state
                .approval_store
                .create(approval_request)
                .await
                .map_err(to_api_error)?;

            (
                "PENDING_APPROVAL".to_string(),
                Some(workflow_id),
                Some(expires),
            )
        }
    };

    Ok(Json(AuthorizationResult {
        transaction_id: req.id,
        status,
        decision: eval_result.decision,
        workflow_id,
        expires_at,
    }))
}

#[derive(Serialize)]
pub struct AddressList {
    pub name: String,
    pub entries: Vec<AddressEntry>,
}

pub async fn list_whitelists(State(state): State<AppState>) -> ApiResult<Vec<String>> {
    let names = state
        .whitelist_store
        .list_names()
        .await
        .map_err(to_api_error)?;
    Ok(Json(names))
}

#[derive(Deserialize)]
pub struct CreateListRequest {
    pub name: String,
}

pub async fn create_whitelist(
    State(state): State<AppState>,
    Json(req): Json<CreateListRequest>,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    validate_name(&req.name).map_err(to_api_error)?;
    state
        .whitelist_store
        .create_list(&req.name)
        .await
        .map_err(to_api_error)?;
    Ok(StatusCode::CREATED)
}

pub async fn get_whitelist(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> ApiResult<AddressList> {
    let entries = state
        .whitelist_store
        .list_addresses(&name)
        .await
        .map_err(to_api_error)?;
    Ok(Json(AddressList { name, entries }))
}

#[derive(Deserialize)]
pub struct AddAddressRequest {
    pub address: String,
    pub label: Option<String>,
}

pub async fn add_whitelist_address(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(req): Json<AddAddressRequest>,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    state
        .whitelist_store
        .add_address(&name, &req.address, req.label.as_deref())
        .await
        .map_err(to_api_error)?;
    Ok(StatusCode::CREATED)
}

pub async fn remove_whitelist_address(
    State(state): State<AppState>,
    Path((name, address)): Path<(String, String)>,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    state
        .whitelist_store
        .remove_address(&name, &address)
        .await
        .map_err(to_api_error)?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn list_blacklists(State(state): State<AppState>) -> ApiResult<Vec<String>> {
    let names = state
        .blacklist_store
        .list_names()
        .await
        .map_err(to_api_error)?;
    Ok(Json(names))
}

pub async fn create_blacklist(
    State(state): State<AppState>,
    Json(req): Json<CreateListRequest>,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    validate_name(&req.name).map_err(to_api_error)?;
    state
        .blacklist_store
        .create_list(&req.name)
        .await
        .map_err(to_api_error)?;
    Ok(StatusCode::CREATED)
}

pub async fn get_blacklist(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> ApiResult<AddressList> {
    let entries = state
        .blacklist_store
        .list_addresses(&name)
        .await
        .map_err(to_api_error)?;
    Ok(Json(AddressList { name, entries }))
}

pub async fn add_blacklist_address(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(req): Json<AddAddressRequest>,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    state
        .blacklist_store
        .add_address(&name, &req.address, req.label.as_deref())
        .await
        .map_err(to_api_error)?;
    Ok(StatusCode::CREATED)
}

pub async fn remove_blacklist_address(
    State(state): State<AppState>,
    Path((name, address)): Path<(String, String)>,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    state
        .blacklist_store
        .remove_address(&name, &address)
        .await
        .map_err(to_api_error)?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub backends: Vec<BackendHealth>,
}

#[derive(Serialize)]
pub struct BackendHealth {
    pub id: String,
    pub status: warden_core::HealthStatus,
}

pub async fn health_check(State(state): State<AppState>) -> (StatusCode, Json<HealthResponse>) {
    let mut backends = Vec::new();

    for id in state.backend_registry.list() {
        if let Some(backend) = state.backend_registry.get(&id) {
            let status =
                backend
                    .health_check()
                    .await
                    .unwrap_or(warden_core::HealthStatus::Unavailable {
                        reason: "Health check failed".into(),
                    });
            backends.push(BackendHealth { id, status });
        }
    }

    let (status_code, overall) = if backends
        .iter()
        .all(|b| matches!(b.status, warden_core::HealthStatus::Healthy))
    {
        (StatusCode::OK, "healthy")
    } else if backends
        .iter()
        .any(|b| matches!(b.status, warden_core::HealthStatus::Healthy))
    {
        (StatusCode::OK, "degraded")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "unhealthy")
    };

    (
        status_code,
        Json(HealthResponse {
            status: overall.into(),
            backends,
        }),
    )
}
