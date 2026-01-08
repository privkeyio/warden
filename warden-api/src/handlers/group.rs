use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use warden_core::{validate_approver_id, validate_name, ApproverGroup, GroupMember};

use super::{to_api_error, ApiError, ApiResult};
use crate::auth::{AdminUser, ViewerUser};
use crate::state::AppState;

#[derive(Serialize)]
pub struct GroupResponse {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub member_count: usize,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl From<ApproverGroup> for GroupResponse {
    fn from(g: ApproverGroup) -> Self {
        Self {
            id: g.id,
            name: g.name,
            description: g.description,
            member_count: g.members.len(),
            created_at: g.created_at,
        }
    }
}

#[derive(Deserialize)]
pub struct CreateGroupRequest {
    pub name: String,
    pub description: Option<String>,
}

#[derive(Deserialize)]
pub struct AddMemberRequest {
    pub approver_id: String,
    pub display_name: Option<String>,
}

pub async fn list_groups(
    _user: ViewerUser,
    State(state): State<AppState>,
) -> ApiResult<Vec<GroupResponse>> {
    let groups = state.group_store.list().await.map_err(to_api_error)?;
    Ok(Json(groups.into_iter().map(GroupResponse::from).collect()))
}

pub async fn create_group(
    _user: AdminUser,
    State(state): State<AppState>,
    Json(req): Json<CreateGroupRequest>,
) -> Result<(StatusCode, Json<GroupResponse>), (StatusCode, Json<ApiError>)> {
    validate_name(&req.name).map_err(to_api_error)?;

    let mut group = ApproverGroup::new(&req.name);
    if let Some(desc) = req.description {
        group = group.with_description(desc);
    }

    let created = state
        .group_store
        .create(group)
        .await
        .map_err(to_api_error)?;

    Ok((StatusCode::CREATED, Json(GroupResponse::from(created))))
}

pub async fn get_group(
    _user: ViewerUser,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<ApproverGroup> {
    let group = state
        .group_store
        .get(&id)
        .await
        .map_err(to_api_error)?
        .ok_or_else(|| group_not_found(id))?;
    Ok(Json(group))
}

pub async fn add_group_member(
    _user: AdminUser,
    State(state): State<AppState>,
    Path(group_id): Path<Uuid>,
    Json(req): Json<AddMemberRequest>,
) -> ApiResult<ApproverGroup> {
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
    _user: AdminUser,
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

fn group_not_found(id: Uuid) -> (StatusCode, Json<ApiError>) {
    (
        StatusCode::NOT_FOUND,
        Json(ApiError::new(
            format!("Group {} not found", id),
            "GROUP_NOT_FOUND",
        )),
    )
}
