use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use warden_core::{EvaluationResult, Policy, TransactionRequest};

use super::{to_api_error, ApiError, ApiResult};
use crate::auth::{AdminUser, ViewerUser};
use crate::state::AppState;

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

#[derive(Deserialize)]
pub struct CreatePolicyRequest {
    pub yaml: Option<String>,
    pub json: Option<serde_json::Value>,
}

pub async fn list_policies(
    _user: ViewerUser,
    State(state): State<AppState>,
) -> ApiResult<Vec<PolicySummary>> {
    let policies = state.policy_store.list().await.map_err(to_api_error)?;
    Ok(Json(policies.iter().map(PolicySummary::from).collect()))
}

pub async fn create_policy(
    _user: AdminUser,
    State(state): State<AppState>,
    Json(req): Json<CreatePolicyRequest>,
) -> Result<(StatusCode, Json<Policy>), (StatusCode, Json<ApiError>)> {
    let policy = parse_policy_request(&req)?;
    let created = state
        .policy_store
        .create(policy)
        .await
        .map_err(to_api_error)?;
    Ok((StatusCode::CREATED, Json(created)))
}

pub async fn get_policy(
    _user: ViewerUser,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<Policy> {
    let policy = state
        .policy_store
        .get(&id)
        .await
        .map_err(to_api_error)?
        .ok_or_else(|| not_found_error("Policy", id))?;
    Ok(Json(policy))
}

pub async fn update_policy(
    _user: AdminUser,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(req): Json<CreatePolicyRequest>,
) -> ApiResult<Policy> {
    state
        .policy_store
        .get(&id)
        .await
        .map_err(to_api_error)?
        .ok_or_else(|| not_found_error("Policy", id))?;

    let mut policy = parse_policy_request(&req)?;
    policy.id = id;
    let updated = state
        .policy_store
        .update(policy)
        .await
        .map_err(to_api_error)?;
    Ok(Json(updated))
}

pub async fn delete_policy(
    _user: AdminUser,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    state.policy_store.delete(&id).await.map_err(to_api_error)?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn activate_policy(
    _user: AdminUser,
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
    _user: AdminUser,
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
    _user: ViewerUser,
    State(state): State<AppState>,
    Json(req): Json<TransactionRequest>,
) -> ApiResult<EvaluationResult> {
    let result = state.evaluator.evaluate(&req).await.map_err(to_api_error)?;
    Ok(Json(result))
}

fn parse_policy_request(req: &CreatePolicyRequest) -> Result<Policy, (StatusCode, Json<ApiError>)> {
    if let Some(yaml) = &req.yaml {
        Policy::from_yaml(yaml).map_err(to_api_error)
    } else if let Some(json) = &req.json {
        let json_str = serde_json::to_string(json).map_err(|e| to_api_error(e.into()))?;
        Policy::from_json(&json_str).map_err(to_api_error)
    } else {
        Err((
            StatusCode::BAD_REQUEST,
            Json(ApiError::new(
                "Either yaml or json field required",
                "MISSING_FIELD",
            )),
        ))
    }
}

fn not_found_error(resource: &str, id: Uuid) -> (StatusCode, Json<ApiError>) {
    (
        StatusCode::NOT_FOUND,
        Json(ApiError::new(
            format!("{} {} not found", resource, id),
            format!("{}_NOT_FOUND", resource.to_uppercase()),
        )),
    )
}
