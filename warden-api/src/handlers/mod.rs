//! HTTP handlers for the Warden API.

mod address_list;
mod approval;
mod group;
mod health;
mod policy;
mod token;

pub use address_list::{
    add_blacklist_address, add_whitelist_address, create_blacklist, create_whitelist,
    get_blacklist, get_whitelist, list_blacklists, list_whitelists, remove_blacklist_address,
    remove_whitelist_address,
};
pub use approval::{
    approve_transaction, authorize_transaction, cancel_workflow, get_transaction_approval_status,
    get_workflow_status, list_pending_approvals, reject_transaction, submit_approval,
    submit_rejection,
};
pub use group::{add_group_member, create_group, get_group, list_groups, remove_group_member};
pub use health::health_check;
pub use policy::{
    activate_policy, create_policy, deactivate_policy, delete_policy, evaluate_policy, get_policy,
    list_policies, update_policy,
};
pub use token::{cleanup_blacklist, get_blacklist_stats, revoke_token};

use axum::{http::StatusCode, Json};
use serde::Serialize;

#[derive(Serialize)]
pub struct ApiError {
    pub error: String,
    pub code: String,
}

impl ApiError {
    pub fn new(error: impl Into<String>, code: impl Into<String>) -> Self {
        Self {
            error: error.into(),
            code: code.into(),
        }
    }
}

pub type ApiResult<T> = Result<Json<T>, (StatusCode, Json<ApiError>)>;

pub fn to_api_error(e: warden_core::Error) -> (StatusCode, Json<ApiError>) {
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
