use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use chrono::Duration;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use warden_core::{
    validate_approver_id, Approval, ApprovalDecision, ApprovalRequest, ApprovalRequirements,
    ApprovalWorkflow, QuorumStatus, TransactionDetails, TransactionRequest, WorkflowStatus,
};

use super::{to_api_error, ApiError, ApiResult};
use crate::auth::{ApproverUser, ViewerUser};
use crate::state::AppState;

#[derive(Serialize)]
pub struct AuthorizationResult {
    pub transaction_id: Uuid,
    pub status: String,
    pub decision: warden_core::PolicyDecisionSerde,
    pub workflow_id: Option<Uuid>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Deserialize)]
pub struct SubmitApprovalRequest {
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

#[derive(Deserialize)]
pub struct CancelWorkflowRequest {
    pub reason: Option<String>,
}

pub async fn authorize_transaction(
    user: ApproverUser,
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

            let workflow = ApprovalWorkflow::from_config(
                req.id,
                eval_result.policy_id,
                rule_id.clone(),
                Some(user.subject.clone()),
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

pub async fn submit_approval(
    user: ApproverUser,
    State(state): State<AppState>,
    Path(workflow_id): Path<Uuid>,
    Json(req): Json<SubmitApprovalRequest>,
) -> ApiResult<ApprovalResponse> {
    submit_decision(
        &state,
        workflow_id,
        &user.subject,
        ApprovalDecision::Approve,
        req.comment,
    )
    .await
}

pub async fn submit_rejection(
    user: ApproverUser,
    State(state): State<AppState>,
    Path(workflow_id): Path<Uuid>,
    Json(req): Json<SubmitApprovalRequest>,
) -> ApiResult<ApprovalResponse> {
    submit_decision(
        &state,
        workflow_id,
        &user.subject,
        ApprovalDecision::Reject,
        req.comment,
    )
    .await
}

pub async fn approve_transaction(
    user: ApproverUser,
    State(state): State<AppState>,
    Path(transaction_id): Path<Uuid>,
    Json(req): Json<SubmitApprovalRequest>,
) -> ApiResult<ApprovalResponse> {
    let workflow = get_workflow_by_transaction(&state, &transaction_id).await?;
    submit_decision(
        &state,
        workflow.id,
        &user.subject,
        ApprovalDecision::Approve,
        req.comment,
    )
    .await
}

pub async fn reject_transaction(
    user: ApproverUser,
    State(state): State<AppState>,
    Path(transaction_id): Path<Uuid>,
    Json(req): Json<SubmitApprovalRequest>,
) -> ApiResult<ApprovalResponse> {
    let workflow = get_workflow_by_transaction(&state, &transaction_id).await?;
    submit_decision(
        &state,
        workflow.id,
        &user.subject,
        ApprovalDecision::Reject,
        req.comment,
    )
    .await
}

pub async fn get_workflow_status(
    _user: ViewerUser,
    State(state): State<AppState>,
    Path(workflow_id): Path<Uuid>,
) -> ApiResult<WorkflowStatusResponse> {
    let workflow = state
        .workflow_store
        .get_workflow(&workflow_id)
        .await
        .map_err(to_api_error)?
        .ok_or_else(|| workflow_not_found(workflow_id))?;

    Ok(Json(build_workflow_status_response(&workflow)))
}

pub async fn get_transaction_approval_status(
    _user: ViewerUser,
    State(state): State<AppState>,
    Path(transaction_id): Path<Uuid>,
) -> ApiResult<WorkflowStatusResponse> {
    let workflow = get_workflow_by_transaction(&state, &transaction_id).await?;
    Ok(Json(build_workflow_status_response(&workflow)))
}

pub async fn list_pending_approvals(
    _user: ViewerUser,
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
            query
                .group
                .as_ref()
                .map(|g| w.requirement.all_groups().contains(g))
                .unwrap_or(true)
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

pub async fn cancel_workflow(
    _user: ApproverUser,
    State(state): State<AppState>,
    Path(workflow_id): Path<Uuid>,
    Json(req): Json<CancelWorkflowRequest>,
) -> ApiResult<ApprovalResponse> {
    let workflow = state
        .workflow_store
        .get_workflow(&workflow_id)
        .await
        .map_err(to_api_error)?
        .ok_or_else(|| workflow_not_found(workflow_id))?;

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
    cancelled.rejection_reason = req.reason;

    let updated = state
        .workflow_store
        .update_workflow(cancelled)
        .await
        .map_err(to_api_error)?;

    Ok(Json(ApprovalResponse {
        workflow_id: updated.id,
        transaction_id: updated.transaction_id,
        status: updated.status,
        quorum_status: updated.quorum_status(),
        message: "Workflow cancelled.".to_string(),
    }))
}

async fn submit_decision(
    state: &AppState,
    workflow_id: Uuid,
    approver_id: &str,
    decision: ApprovalDecision,
    comment: Option<String>,
) -> ApiResult<ApprovalResponse> {
    validate_approver_id(approver_id).map_err(to_api_error)?;

    let mut workflow = state
        .workflow_store
        .get_workflow(&workflow_id)
        .await
        .map_err(to_api_error)?
        .ok_or_else(|| workflow_not_found(workflow_id))?;

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
            .update_workflow(workflow)
            .await
            .map_err(to_api_error)?;
        return Err((
            StatusCode::GONE,
            Json(ApiError::new("Workflow has expired", "WORKFLOW_EXPIRED")),
        ));
    }

    let groups = state
        .group_store
        .get_groups_for_approver(approver_id)
        .await
        .map_err(to_api_error)?;
    let group_names: Vec<String> = groups.iter().map(|g| g.name.clone()).collect();

    if !workflow.can_approve(approver_id, &group_names) {
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

    let mut approval = Approval::new(approver_id.to_string(), valid_group, decision.clone(), 0);
    if let Some(c) = comment {
        approval = approval.with_comment(c);
    }

    let updated = state
        .workflow_store
        .add_approval_to_workflow(&workflow_id, approval)
        .await
        .map_err(to_api_error)?;

    let message = match (&decision, &updated.status) {
        (ApprovalDecision::Reject, _) => "Transaction rejected.".to_string(),
        (ApprovalDecision::Approve, WorkflowStatus::Approved) => {
            "Approval complete. Transaction approved.".to_string()
        }
        (ApprovalDecision::Approve, WorkflowStatus::Pending) => {
            if let QuorumStatus::Pending {
                collected,
                required,
                ..
            } = updated.quorum_status()
            {
                format!(
                    "Approval recorded. {} of {} approvals collected.",
                    collected, required
                )
            } else {
                "Approval recorded.".to_string()
            }
        }
        _ => "Decision recorded.".to_string(),
    };

    Ok(Json(ApprovalResponse {
        workflow_id: updated.id,
        transaction_id: updated.transaction_id,
        status: updated.status,
        quorum_status: updated.quorum_status(),
        message,
    }))
}

async fn get_workflow_by_transaction(
    state: &AppState,
    transaction_id: &Uuid,
) -> Result<ApprovalWorkflow, (StatusCode, Json<ApiError>)> {
    state
        .workflow_store
        .get_workflow_by_transaction(transaction_id)
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
        })
}

fn workflow_not_found(id: Uuid) -> (StatusCode, Json<ApiError>) {
    (
        StatusCode::NOT_FOUND,
        Json(ApiError::new(
            format!("Workflow {} not found", id),
            "WORKFLOW_NOT_FOUND",
        )),
    )
}

fn build_workflow_status_response(workflow: &ApprovalWorkflow) -> WorkflowStatusResponse {
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

    WorkflowStatusResponse {
        workflow_id: workflow.id,
        transaction_id: workflow.transaction_id,
        status: workflow.status,
        approvals,
        quorum_status: workflow.quorum_status(),
        expires_at: workflow.expires_at,
        created_at: workflow.created_at,
        completed_at: workflow.completed_at,
    }
}
