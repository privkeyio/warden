use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use chrono::Duration;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use warden_core::{
    validate_approver_id, validate_name, AddressEntry, Approval, ApprovalDecision, ApprovalRequest,
    ApprovalRequirements, ApprovalWorkflow, EvaluationResult, GroupMember, Policy, QuorumStatus,
    TransactionDetails, TransactionRequest, WorkflowStatus,
};

use crate::auth::AuthorizedUser;
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
        warden_core::Error::WorkflowNotFound(id) => (
            StatusCode::NOT_FOUND,
            "WORKFLOW_NOT_FOUND",
            format!("Workflow not found: {}", id),
        ),
        warden_core::Error::WorkflowNotPending(id) => (
            StatusCode::CONFLICT,
            "WORKFLOW_NOT_PENDING",
            format!("Workflow is not pending: {}", id),
        ),
        warden_core::Error::ApproverNotAuthorized(msg) => (
            StatusCode::FORBIDDEN,
            "APPROVER_NOT_AUTHORIZED",
            format!("Approver not authorized: {}", msg),
        ),
        warden_core::Error::AlreadyApproved(msg) => (
            StatusCode::CONFLICT,
            "ALREADY_APPROVED",
            format!("Already approved: {}", msg),
        ),
        warden_core::Error::GroupNotFound(name) => (
            StatusCode::NOT_FOUND,
            "GROUP_NOT_FOUND",
            format!("Group not found: {}", name),
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

pub async fn list_policies(
    _user: AuthorizedUser<2>,
    State(state): State<AppState>,
) -> ApiResult<Vec<PolicySummary>> {
    let policies = state.policy_store.list().await.map_err(to_api_error)?;
    Ok(Json(policies.iter().map(PolicySummary::from).collect()))
}

#[derive(Deserialize)]
pub struct CreatePolicyRequest {
    pub yaml: Option<String>,
    pub json: Option<serde_json::Value>,
}

pub async fn create_policy(
    _user: AuthorizedUser<0>,
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

pub async fn get_policy(
    _user: AuthorizedUser<2>,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<Policy> {
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
    _user: AuthorizedUser<0>,
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
    _user: AuthorizedUser<0>,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    state.policy_store.delete(&id).await.map_err(to_api_error)?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn activate_policy(
    _user: AuthorizedUser<0>,
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
    _user: AuthorizedUser<0>,
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
    _user: AuthorizedUser<2>,
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
    _user: AuthorizedUser<1>,
    State(state): State<AppState>,
    Json(req): Json<TransactionRequest>,
) -> ApiResult<AuthorizationResult> {
    let eval_result = state.evaluator.evaluate(&req).await.map_err(to_api_error)?;

    let (status, workflow_id, expires_at) = match &eval_result.decision {
        warden_core::PolicyDecisionSerde::Allow { .. } => ("APPROVED".to_string(), None, None),
        warden_core::PolicyDecisionSerde::Deny { .. } => ("DENIED".to_string(), None, None),
        warden_core::PolicyDecisionSerde::RequireApproval {
            rule_id,
            approval_config,
        } => {
            let transaction_details = TransactionDetails {
                source_wallet: req.source_wallet.clone(),
                destination: req.destination.clone(),
                amount_sats: req.amount_sats,
                memo: req
                    .metadata
                    .get("memo")
                    .and_then(|v| v.as_str())
                    .map(String::from),
                metadata: req.metadata.clone(),
            };

            let requester_id = req
                .metadata
                .get("requester_id")
                .and_then(|v| v.as_str())
                .map(String::from);

            let workflow = ApprovalWorkflow::from_config(
                req.id,
                eval_result.policy_id,
                rule_id.clone(),
                requester_id,
                approval_config,
                transaction_details,
            );

            let workflow_id = workflow.id;
            let expires = workflow.expires_at;

            state
                .workflow_store
                .create_workflow(workflow)
                .await
                .map_err(to_api_error)?;

            let timeout = Duration::hours(approval_config.timeout_hours as i64);
            let requirements = ApprovalRequirements::simple(
                approval_config.quorum,
                approval_config.from_groups.clone(),
            );
            let approval_request =
                ApprovalRequest::new(req.id, eval_result.policy_id, requirements, timeout);

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

pub async fn list_whitelists(
    _user: AuthorizedUser<2>,
    State(state): State<AppState>,
) -> ApiResult<Vec<String>> {
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
    _user: AuthorizedUser<0>,
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
    _user: AuthorizedUser<2>,
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
    _user: AuthorizedUser<0>,
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
    _user: AuthorizedUser<0>,
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

pub async fn list_blacklists(
    _user: AuthorizedUser<2>,
    State(state): State<AppState>,
) -> ApiResult<Vec<String>> {
    let names = state
        .blacklist_store
        .list_names()
        .await
        .map_err(to_api_error)?;
    Ok(Json(names))
}

pub async fn create_blacklist(
    _user: AuthorizedUser<0>,
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
    _user: AuthorizedUser<2>,
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
    _user: AuthorizedUser<0>,
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
    _user: AuthorizedUser<0>,
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

#[derive(Deserialize)]
pub struct SubmitApprovalRequest {
    pub approver_id: String,
    pub comment: Option<String>,
}

#[derive(Serialize)]
pub struct ApprovalResponse {
    pub workflow_id: Uuid,
    pub transaction_id: Uuid,
    pub status: WorkflowStatus,
    pub quorum_status: QuorumStatus,
    pub message: String,
}

pub async fn submit_approval(
    _user: AuthorizedUser<1>,
    State(state): State<AppState>,
    Path(workflow_id): Path<Uuid>,
    Json(req): Json<SubmitApprovalRequest>,
) -> ApiResult<ApprovalResponse> {
    submit_approval_internal(&state, workflow_id, req).await
}

pub async fn submit_rejection(
    _user: AuthorizedUser<1>,
    State(state): State<AppState>,
    Path(workflow_id): Path<Uuid>,
    Json(req): Json<SubmitApprovalRequest>,
) -> ApiResult<ApprovalResponse> {
    submit_rejection_internal(&state, workflow_id, req).await
}

#[derive(Serialize)]
pub struct WorkflowStatusResponse {
    pub workflow_id: Uuid,
    pub transaction_id: Uuid,
    pub status: WorkflowStatus,
    pub approvals: Vec<ApprovalRecord>,
    pub quorum_status: QuorumStatus,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Serialize)]
pub struct ApprovalRecord {
    pub approver_id: String,
    pub group: String,
    pub decision: String,
    pub comment: Option<String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

pub async fn get_workflow_status(
    _user: AuthorizedUser<2>,
    State(state): State<AppState>,
    Path(workflow_id): Path<Uuid>,
) -> ApiResult<WorkflowStatusResponse> {
    let workflow = state
        .workflow_store
        .get_workflow(&workflow_id)
        .await
        .map_err(to_api_error)?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(ApiError::new(
                    format!("Workflow {} not found", workflow_id),
                    "WORKFLOW_NOT_FOUND",
                )),
            )
        })?;

    let approvals: Vec<ApprovalRecord> = workflow
        .approvals
        .iter()
        .map(|a| ApprovalRecord {
            approver_id: a.approver_id.clone(),
            group: a.approver_role.clone(),
            decision: match a.decision {
                ApprovalDecision::Approve => "APPROVE".to_string(),
                ApprovalDecision::Reject => "REJECT".to_string(),
            },
            comment: a.comment.clone(),
            timestamp: a.created_at,
        })
        .collect();

    let quorum_status = workflow.quorum_status();
    Ok(Json(WorkflowStatusResponse {
        workflow_id: workflow.id,
        transaction_id: workflow.transaction_id,
        status: workflow.status,
        approvals,
        quorum_status,
        expires_at: workflow.expires_at,
        created_at: workflow.created_at,
        completed_at: workflow.completed_at,
    }))
}

#[derive(Deserialize)]
pub struct PendingApprovalsQuery {
    pub approver_id: Option<String>,
    pub group: Option<String>,
    pub limit: Option<usize>,
}

#[derive(Serialize)]
pub struct PendingApproval {
    pub workflow_id: Uuid,
    pub transaction_id: Uuid,
    pub transaction_details: TransactionDetails,
    pub requested_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub your_groups: Vec<String>,
    pub quorum_status: QuorumStatus,
}

pub async fn list_pending_approvals(
    _user: AuthorizedUser<2>,
    State(state): State<AppState>,
    Query(query): Query<PendingApprovalsQuery>,
) -> ApiResult<Vec<PendingApproval>> {
    let approver_groups: Vec<String> = if let Some(approver_id) = &query.approver_id {
        let groups = state
            .group_store
            .get_groups_for_approver(approver_id)
            .await
            .map_err(to_api_error)?;
        groups.iter().map(|g| g.name.clone()).collect()
    } else {
        vec![]
    };

    let workflows = if let Some(approver_id) = &query.approver_id {
        state
            .workflow_store
            .list_pending_for_approver(approver_id, &approver_groups)
            .await
            .map_err(to_api_error)?
    } else {
        state
            .workflow_store
            .list_pending_workflows()
            .await
            .map_err(to_api_error)?
    };

    let limit = query.limit.unwrap_or(50);
    let pending: Vec<PendingApproval> = workflows
        .into_iter()
        .filter(|w| {
            if let Some(ref group) = query.group {
                w.requirement.all_groups().contains(group)
            } else {
                true
            }
        })
        .take(limit)
        .map(|w| {
            let your_groups: Vec<String> = if !approver_groups.is_empty() {
                let required = w.requirement.all_groups();
                approver_groups
                    .iter()
                    .filter(|g| required.contains(*g))
                    .cloned()
                    .collect()
            } else {
                vec![]
            };

            let quorum_status = w.quorum_status();
            PendingApproval {
                workflow_id: w.id,
                transaction_id: w.transaction_id,
                transaction_details: w.transaction_details,
                requested_at: w.created_at,
                expires_at: w.expires_at,
                your_groups,
                quorum_status,
            }
        })
        .collect();

    Ok(Json(pending))
}

#[derive(Serialize)]
pub struct GroupResponse {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub member_count: usize,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

pub async fn list_groups(
    _user: AuthorizedUser<2>,
    State(state): State<AppState>,
) -> ApiResult<Vec<GroupResponse>> {
    let groups = state.group_store.list().await.map_err(to_api_error)?;
    Ok(Json(
        groups
            .into_iter()
            .map(|g| GroupResponse {
                id: g.id,
                name: g.name,
                description: g.description,
                member_count: g.members.len(),
                created_at: g.created_at,
            })
            .collect(),
    ))
}

#[derive(Deserialize)]
pub struct CreateGroupRequest {
    pub name: String,
    pub description: Option<String>,
}

pub async fn create_group(
    _user: AuthorizedUser<0>,
    State(state): State<AppState>,
    Json(req): Json<CreateGroupRequest>,
) -> Result<(StatusCode, Json<GroupResponse>), (StatusCode, Json<ApiError>)> {
    validate_name(&req.name).map_err(to_api_error)?;

    let mut group = warden_core::ApproverGroup::new(&req.name);
    if let Some(desc) = req.description {
        group = group.with_description(desc);
    }

    let created = state
        .group_store
        .create(group)
        .await
        .map_err(to_api_error)?;

    Ok((
        StatusCode::CREATED,
        Json(GroupResponse {
            id: created.id,
            name: created.name,
            description: created.description,
            member_count: created.members.len(),
            created_at: created.created_at,
        }),
    ))
}

pub async fn get_group(
    _user: AuthorizedUser<2>,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<warden_core::ApproverGroup> {
    let group = state
        .group_store
        .get(&id)
        .await
        .map_err(to_api_error)?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(ApiError::new(
                    format!("Group {} not found", id),
                    "GROUP_NOT_FOUND",
                )),
            )
        })?;
    Ok(Json(group))
}

#[derive(Deserialize)]
pub struct AddMemberRequest {
    pub approver_id: String,
    pub display_name: Option<String>,
}

pub async fn add_group_member(
    _user: AuthorizedUser<0>,
    State(state): State<AppState>,
    Path(group_id): Path<Uuid>,
    Json(req): Json<AddMemberRequest>,
) -> ApiResult<warden_core::ApproverGroup> {
    validate_approver_id(&req.approver_id).map_err(to_api_error)?;

    let mut member = GroupMember::new(&req.approver_id);
    if let Some(name) = req.display_name {
        member = member.with_display_name(name);
    }

    let updated = state
        .group_store
        .add_member(&group_id, member)
        .await
        .map_err(to_api_error)?;

    Ok(Json(updated))
}

pub async fn remove_group_member(
    _user: AuthorizedUser<0>,
    State(state): State<AppState>,
    Path((group_id, approver_id)): Path<(Uuid, String)>,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    state
        .group_store
        .remove_member(&group_id, &approver_id)
        .await
        .map_err(to_api_error)?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct CancelWorkflowRequest {
    pub reason: Option<String>,
}

pub async fn cancel_workflow(
    _user: AuthorizedUser<1>,
    State(state): State<AppState>,
    Path(workflow_id): Path<Uuid>,
    Json(req): Json<CancelWorkflowRequest>,
) -> ApiResult<ApprovalResponse> {
    let workflow = state
        .workflow_store
        .get_workflow(&workflow_id)
        .await
        .map_err(to_api_error)?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(ApiError::new(
                    format!("Workflow {} not found", workflow_id),
                    "WORKFLOW_NOT_FOUND",
                )),
            )
        })?;

    if workflow.status != WorkflowStatus::Pending {
        return Err((
            StatusCode::CONFLICT,
            Json(ApiError::new(
                format!("Workflow {} is not pending", workflow_id),
                "WORKFLOW_NOT_PENDING",
            )),
        ));
    }

    let mut cancelled = workflow;
    cancelled.status = WorkflowStatus::Cancelled;
    cancelled.completed_at = Some(chrono::Utc::now());
    cancelled.rejection_reason = req.reason.clone();

    let updated = state
        .workflow_store
        .update_workflow(cancelled)
        .await
        .map_err(to_api_error)?;

    let quorum_status = updated.quorum_status();
    Ok(Json(ApprovalResponse {
        workflow_id: updated.id,
        transaction_id: updated.transaction_id,
        status: updated.status,
        quorum_status,
        message: "Workflow cancelled.".to_string(),
    }))
}

pub async fn approve_transaction(
    _user: AuthorizedUser<1>,
    State(state): State<AppState>,
    Path(transaction_id): Path<Uuid>,
    Json(req): Json<SubmitApprovalRequest>,
) -> ApiResult<ApprovalResponse> {
    let workflow = state
        .workflow_store
        .get_workflow_by_transaction(&transaction_id)
        .await
        .map_err(to_api_error)?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(ApiError::new(
                    format!("No workflow found for transaction {}", transaction_id),
                    "WORKFLOW_NOT_FOUND",
                )),
            )
        })?;

    submit_approval_internal(&state, workflow.id, req).await
}

pub async fn reject_transaction(
    _user: AuthorizedUser<1>,
    State(state): State<AppState>,
    Path(transaction_id): Path<Uuid>,
    Json(req): Json<SubmitApprovalRequest>,
) -> ApiResult<ApprovalResponse> {
    let workflow = state
        .workflow_store
        .get_workflow_by_transaction(&transaction_id)
        .await
        .map_err(to_api_error)?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(ApiError::new(
                    format!("No workflow found for transaction {}", transaction_id),
                    "WORKFLOW_NOT_FOUND",
                )),
            )
        })?;

    submit_rejection_internal(&state, workflow.id, req).await
}

async fn submit_approval_internal(
    state: &AppState,
    workflow_id: Uuid,
    req: SubmitApprovalRequest,
) -> ApiResult<ApprovalResponse> {
    validate_approver_id(&req.approver_id).map_err(to_api_error)?;

    let mut workflow = state
        .workflow_store
        .get_workflow(&workflow_id)
        .await
        .map_err(to_api_error)?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(ApiError::new(
                    format!("Workflow {} not found", workflow_id),
                    "WORKFLOW_NOT_FOUND",
                )),
            )
        })?;

    if workflow.status != WorkflowStatus::Pending {
        return Err((
            StatusCode::CONFLICT,
            Json(ApiError::new(
                format!("Workflow {} is not pending", workflow_id),
                "WORKFLOW_NOT_PENDING",
            )),
        ));
    }

    if workflow.is_expired() {
        workflow.check_expiration();
        state
            .workflow_store
            .update_workflow(workflow.clone())
            .await
            .map_err(to_api_error)?;
        return Err((
            StatusCode::GONE,
            Json(ApiError::new("Workflow has expired", "WORKFLOW_EXPIRED")),
        ));
    }

    let groups = state
        .group_store
        .get_groups_for_approver(&req.approver_id)
        .await
        .map_err(to_api_error)?;
    let group_names: Vec<String> = groups.iter().map(|g| g.name.clone()).collect();

    if !workflow.can_approve(&req.approver_id, &group_names) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ApiError::new(
                "Approver not authorized or already approved",
                "NOT_AUTHORIZED",
            )),
        ));
    }

    let required_groups = workflow.requirement.all_groups();
    let valid_group = group_names
        .iter()
        .find(|g| required_groups.contains(*g))
        .cloned()
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(ApiError::new(
                    "Approver has no valid group for this workflow",
                    "NO_VALID_GROUP",
                )),
            )
        })?;

    let approval = Approval::new(
        req.approver_id.clone(),
        valid_group,
        ApprovalDecision::Approve,
        0,
    );
    let approval = if let Some(comment) = req.comment {
        approval.with_comment(comment)
    } else {
        approval
    };

    let updated = state
        .workflow_store
        .add_approval_to_workflow(&workflow_id, approval)
        .await
        .map_err(to_api_error)?;

    let message = match updated.status {
        WorkflowStatus::Approved => "Approval complete. Transaction approved.".to_string(),
        WorkflowStatus::Pending => {
            let status = updated.quorum_status();
            match status {
                QuorumStatus::Pending {
                    collected,
                    required,
                    ..
                } => {
                    format!(
                        "Approval recorded. {} of {} approvals collected.",
                        collected, required
                    )
                }
                _ => "Approval recorded.".to_string(),
            }
        }
        _ => "Approval recorded.".to_string(),
    };

    let quorum_status = updated.quorum_status();
    Ok(Json(ApprovalResponse {
        workflow_id: updated.id,
        transaction_id: updated.transaction_id,
        status: updated.status,
        quorum_status,
        message,
    }))
}

async fn submit_rejection_internal(
    state: &AppState,
    workflow_id: Uuid,
    req: SubmitApprovalRequest,
) -> ApiResult<ApprovalResponse> {
    validate_approver_id(&req.approver_id).map_err(to_api_error)?;

    let mut workflow = state
        .workflow_store
        .get_workflow(&workflow_id)
        .await
        .map_err(to_api_error)?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(ApiError::new(
                    format!("Workflow {} not found", workflow_id),
                    "WORKFLOW_NOT_FOUND",
                )),
            )
        })?;

    if workflow.status != WorkflowStatus::Pending {
        return Err((
            StatusCode::CONFLICT,
            Json(ApiError::new(
                format!("Workflow {} is not pending", workflow_id),
                "WORKFLOW_NOT_PENDING",
            )),
        ));
    }

    if workflow.is_expired() {
        workflow.check_expiration();
        state
            .workflow_store
            .update_workflow(workflow.clone())
            .await
            .map_err(to_api_error)?;
        return Err((
            StatusCode::GONE,
            Json(ApiError::new(
                format!("Workflow {} has expired", workflow_id),
                "WORKFLOW_EXPIRED",
            )),
        ));
    }

    let groups = state
        .group_store
        .get_groups_for_approver(&req.approver_id)
        .await
        .map_err(to_api_error)?;
    let group_names: Vec<String> = groups.iter().map(|g| g.name.clone()).collect();

    if !workflow.can_approve(&req.approver_id, &group_names) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ApiError::new("Approver not authorized", "NOT_AUTHORIZED")),
        ));
    }

    let required_groups = workflow.requirement.all_groups();
    let valid_group = group_names
        .iter()
        .find(|g| required_groups.contains(*g))
        .cloned()
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(ApiError::new(
                    "Approver has no valid group for this workflow",
                    "NO_VALID_GROUP",
                )),
            )
        })?;

    let approval = Approval::new(req.approver_id, valid_group, ApprovalDecision::Reject, 0);
    let approval = if let Some(comment) = req.comment {
        approval.with_comment(comment)
    } else {
        approval
    };

    let updated = state
        .workflow_store
        .add_approval_to_workflow(&workflow_id, approval)
        .await
        .map_err(to_api_error)?;

    let quorum_status = updated.quorum_status();
    Ok(Json(ApprovalResponse {
        workflow_id: updated.id,
        transaction_id: updated.transaction_id,
        status: updated.status,
        quorum_status,
        message: "Transaction rejected.".to_string(),
    }))
}

pub async fn get_transaction_approval_status(
    _user: AuthorizedUser<2>,
    State(state): State<AppState>,
    Path(transaction_id): Path<Uuid>,
) -> ApiResult<WorkflowStatusResponse> {
    let workflow = state
        .workflow_store
        .get_workflow_by_transaction(&transaction_id)
        .await
        .map_err(to_api_error)?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(ApiError::new(
                    format!("No workflow found for transaction {}", transaction_id),
                    "WORKFLOW_NOT_FOUND",
                )),
            )
        })?;

    let approvals: Vec<ApprovalRecord> = workflow
        .approvals
        .iter()
        .map(|a| ApprovalRecord {
            approver_id: a.approver_id.clone(),
            group: a.approver_role.clone(),
            decision: match a.decision {
                ApprovalDecision::Approve => "APPROVE".to_string(),
                ApprovalDecision::Reject => "REJECT".to_string(),
            },
            comment: a.comment.clone(),
            timestamp: a.created_at,
        })
        .collect();

    let quorum_status = workflow.quorum_status();
    Ok(Json(WorkflowStatusResponse {
        workflow_id: workflow.id,
        transaction_id: workflow.transaction_id,
        status: workflow.status,
        approvals,
        quorum_status,
        expires_at: workflow.expires_at,
        created_at: workflow.created_at,
        completed_at: workflow.completed_at,
    }))
}
