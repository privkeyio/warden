use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};

use super::ApiResult;
use crate::auth::AdminUser;
use crate::state::AppState;

#[derive(Deserialize)]
pub struct RevokeTokenRequest {
    pub jti: String,
    pub exp: u64,
}

#[derive(Serialize)]
pub struct RevokeTokenResponse {
    pub revoked: bool,
}

#[derive(Serialize)]
pub struct BlacklistStatsResponse {
    pub count: usize,
}

pub async fn revoke_token(
    State(state): State<AppState>,
    _admin: AdminUser,
    Json(req): Json<RevokeTokenRequest>,
) -> ApiResult<RevokeTokenResponse> {
    state.auth_state.revoke_token(req.jti, req.exp);
    Ok(Json(RevokeTokenResponse { revoked: true }))
}

pub async fn cleanup_blacklist(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> ApiResult<BlacklistStatsResponse> {
    state.auth_state.cleanup_blacklist();
    let count = state.auth_state.token_blacklist.len();
    Ok(Json(BlacklistStatsResponse { count }))
}

pub async fn get_blacklist_stats(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> ApiResult<BlacklistStatsResponse> {
    let count = state.auth_state.token_blacklist.len();
    Ok(Json(BlacklistStatsResponse { count }))
}
