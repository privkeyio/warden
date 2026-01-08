use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use warden_core::{validate_name, AddressEntry, AddressListStore};

use super::{to_api_error, ApiError, ApiResult};
use crate::auth::{AdminUser, ViewerUser};
use crate::state::AppState;

#[derive(Serialize)]
pub struct AddressList {
    pub name: String,
    pub entries: Vec<AddressEntry>,
}

#[derive(Deserialize)]
pub struct CreateListRequest {
    pub name: String,
}

#[derive(Deserialize)]
pub struct AddAddressRequest {
    pub address: String,
    pub label: Option<String>,
}

pub async fn list_whitelists(
    _user: ViewerUser,
    State(state): State<AppState>,
) -> ApiResult<Vec<String>> {
    list_names(&state.whitelist_store).await
}

pub async fn create_whitelist(
    _user: AdminUser,
    State(state): State<AppState>,
    Json(req): Json<CreateListRequest>,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    create_list(&state.whitelist_store, &req.name).await
}

pub async fn get_whitelist(
    _user: ViewerUser,
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> ApiResult<AddressList> {
    get_list(&state.whitelist_store, &name).await
}

pub async fn add_whitelist_address(
    _user: AdminUser,
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(req): Json<AddAddressRequest>,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    add_address(
        &state.whitelist_store,
        &name,
        &req.address,
        req.label.as_deref(),
    )
    .await
}

pub async fn remove_whitelist_address(
    _user: AdminUser,
    State(state): State<AppState>,
    Path((name, address)): Path<(String, String)>,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    remove_address(&state.whitelist_store, &name, &address).await
}

pub async fn list_blacklists(
    _user: ViewerUser,
    State(state): State<AppState>,
) -> ApiResult<Vec<String>> {
    list_names(&state.blacklist_store).await
}

pub async fn create_blacklist(
    _user: AdminUser,
    State(state): State<AppState>,
    Json(req): Json<CreateListRequest>,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    create_list(&state.blacklist_store, &req.name).await
}

pub async fn get_blacklist(
    _user: ViewerUser,
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> ApiResult<AddressList> {
    get_list(&state.blacklist_store, &name).await
}

pub async fn add_blacklist_address(
    _user: AdminUser,
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(req): Json<AddAddressRequest>,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    add_address(
        &state.blacklist_store,
        &name,
        &req.address,
        req.label.as_deref(),
    )
    .await
}

pub async fn remove_blacklist_address(
    _user: AdminUser,
    State(state): State<AppState>,
    Path((name, address)): Path<(String, String)>,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    remove_address(&state.blacklist_store, &name, &address).await
}

async fn list_names(store: &Arc<dyn AddressListStore>) -> ApiResult<Vec<String>> {
    let names = store.list_names().await.map_err(to_api_error)?;
    Ok(Json(names))
}

async fn create_list(
    store: &Arc<dyn AddressListStore>,
    name: &str,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    validate_name(name).map_err(to_api_error)?;
    store.create_list(name).await.map_err(to_api_error)?;
    Ok(StatusCode::CREATED)
}

async fn get_list(store: &Arc<dyn AddressListStore>, name: &str) -> ApiResult<AddressList> {
    let entries = store.list_addresses(name).await.map_err(to_api_error)?;
    Ok(Json(AddressList {
        name: name.to_string(),
        entries,
    }))
}

async fn add_address(
    store: &Arc<dyn AddressListStore>,
    name: &str,
    address: &str,
    label: Option<&str>,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    store
        .add_address(name, address, label)
        .await
        .map_err(to_api_error)?;
    Ok(StatusCode::CREATED)
}

async fn remove_address(
    store: &Arc<dyn AddressListStore>,
    name: &str,
    address: &str,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    store
        .remove_address(name, address)
        .await
        .map_err(to_api_error)?;
    Ok(StatusCode::NO_CONTENT)
}
