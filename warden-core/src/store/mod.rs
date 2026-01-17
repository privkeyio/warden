#![forbid(unsafe_code)]

mod memory;
mod redb_store;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::policy::Policy;
use crate::Result;

pub use memory::{InMemoryAddressListStore, InMemoryPolicyStore};
pub use redb_store::{
    DbCipher, RedbAddressListStore, RedbApprovalStore, RedbGroupStore, RedbPolicyStore,
    RedbRevokedTokenStore, RedbStorage, RedbWorkflowStore,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressEntry {
    pub address: String,
    pub label: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokedToken {
    pub jti: String,
    pub exp: u64,
}

#[async_trait]
pub trait RevokedTokenStore: Send + Sync {
    async fn revoke(&self, jti: &str, exp: u64) -> Result<()>;
    async fn is_revoked(&self, jti: &str) -> Result<bool>;
    async fn list_valid(&self) -> Result<Vec<RevokedToken>>;
    async fn cleanup_expired(&self) -> Result<usize>;
}

#[async_trait]
pub trait AddressListStore: Send + Sync {
    async fn create_list(&self, name: &str) -> Result<()>;
    async fn delete_list(&self, name: &str) -> Result<()>;
    async fn list_names(&self) -> Result<Vec<String>>;
    async fn add_address(&self, list_name: &str, address: &str, label: Option<&str>) -> Result<()>;
    async fn remove_address(&self, list_name: &str, address: &str) -> Result<()>;
    async fn contains(&self, list_name: &str, address: &str) -> Result<bool>;
    async fn list_addresses(&self, list_name: &str) -> Result<Vec<AddressEntry>>;
}

#[async_trait]
pub trait PolicyStore: Send + Sync {
    async fn create(&self, policy: Policy) -> Result<Policy>;
    async fn get(&self, id: &Uuid) -> Result<Option<Policy>>;
    async fn get_by_name(&self, name: &str) -> Result<Option<Policy>>;
    async fn list(&self) -> Result<Vec<Policy>>;
    async fn update(&self, policy: Policy) -> Result<Policy>;
    async fn delete(&self, id: &Uuid) -> Result<()>;
    async fn activate(&self, id: &Uuid) -> Result<()>;
    async fn deactivate(&self, id: &Uuid) -> Result<()>;
    async fn get_active_policy(&self, wallet_id: &str) -> Result<Option<Policy>>;
}
