#![forbid(unsafe_code)]

use async_trait::async_trait;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use redb::{Database, ReadableTable, TableDefinition};
use std::path::Path;
use std::sync::{Arc, RwLock};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{AddressEntry, AddressListStore, PolicyStore};
use crate::approval::{
    Approval, ApprovalRequest, ApprovalStatus, ApprovalStore, ApprovalWorkflow, WorkflowStatus,
    WorkflowStore,
};
use crate::group::{ApproverGroup, GroupMember, GroupStore};
use crate::pattern::matches_pattern;
use crate::policy::Policy;
use crate::{Error, Result};

const NONCE_SIZE: usize = 12;

#[derive(Clone)]
pub struct DbCipher {
    cipher: ChaCha20Poly1305,
}

impl DbCipher {
    pub fn new(key: &[u8; 32]) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new_from_slice(key).expect("key is 32 bytes"),
        }
    }

    pub fn from_hex(hex_key: &str) -> Result<Self> {
        let key_bytes = hex::decode(hex_key).map_err(|e| Error::Encryption(e.to_string()))?;
        if key_bytes.len() != 32 {
            return Err(Error::Encryption(format!(
                "encryption key must be 32 bytes, got {}",
                key_bytes.len()
            )));
        }
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&key_bytes);
        Ok(Self::new(&key))
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        getrandom::getrandom(&mut nonce_bytes)
            .map_err(|e| Error::Encryption(format!("failed to generate nonce: {}", e)))?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| Error::Encryption(format!("encryption failed: {}", e)))?;

        let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < NONCE_SIZE {
            return Err(Error::Encryption("ciphertext too short".to_string()));
        }

        let (nonce_bytes, ciphertext) = data.split_at(NONCE_SIZE);
        let nonce = Nonce::from_slice(nonce_bytes);

        self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| Error::Encryption(format!("decryption failed: {}", e)))
    }
}

const POLICIES_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("policies");
const WALLET_BINDINGS_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("wallet_bindings");
const ADDRESS_LISTS_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("address_lists");
const WORKFLOWS_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("workflows");
const GROUPS_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("groups");
const APPROVALS_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("approvals");

pub struct RedbStorage {
    db: Arc<Database>,
    cipher: Option<Arc<DbCipher>>,
}

impl RedbStorage {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_with_cipher(path, None)
    }

    pub fn open_encrypted(path: impl AsRef<Path>, cipher: DbCipher) -> Result<Self> {
        Self::open_with_cipher(path, Some(cipher))
    }

    fn open_with_cipher(path: impl AsRef<Path>, cipher: Option<DbCipher>) -> Result<Self> {
        let path = path.as_ref();
        let db = Database::create(path).map_err(|e| Error::Storage(e.to_string()))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(path, perms)
                .map_err(|e| Error::Storage(format!("failed to set file permissions: {}", e)))?;
        }

        {
            let wtxn = db
                .begin_write()
                .map_err(|e| Error::Storage(e.to_string()))?;
            wtxn.open_table(POLICIES_TABLE)
                .map_err(|e| Error::Storage(e.to_string()))?;
            wtxn.open_table(WALLET_BINDINGS_TABLE)
                .map_err(|e| Error::Storage(e.to_string()))?;
            wtxn.open_table(ADDRESS_LISTS_TABLE)
                .map_err(|e| Error::Storage(e.to_string()))?;
            wtxn.open_table(WORKFLOWS_TABLE)
                .map_err(|e| Error::Storage(e.to_string()))?;
            wtxn.open_table(GROUPS_TABLE)
                .map_err(|e| Error::Storage(e.to_string()))?;
            wtxn.open_table(APPROVALS_TABLE)
                .map_err(|e| Error::Storage(e.to_string()))?;
            wtxn.commit().map_err(|e| Error::Storage(e.to_string()))?;
        }

        Ok(Self {
            db: Arc::new(db),
            cipher: cipher.map(Arc::new),
        })
    }

    pub fn policy_store(&self) -> RedbPolicyStore {
        let store = RedbPolicyStore {
            db: Arc::clone(&self.db),
            cipher: self.cipher.clone(),
            pattern_cache: RwLock::new(Vec::new()),
        };
        if let Err(e) = store.rebuild_pattern_cache() {
            tracing::error!(error = %e, "Failed to rebuild pattern cache");
        }
        store
    }

    pub fn address_list_store(&self) -> RedbAddressListStore {
        RedbAddressListStore {
            db: Arc::clone(&self.db),
            cipher: self.cipher.clone(),
        }
    }

    pub fn workflow_store(&self) -> RedbWorkflowStore {
        RedbWorkflowStore {
            db: Arc::clone(&self.db),
            cipher: self.cipher.clone(),
        }
    }

    pub fn group_store(&self) -> RedbGroupStore {
        RedbGroupStore {
            db: Arc::clone(&self.db),
            cipher: self.cipher.clone(),
        }
    }

    pub fn approval_store(&self) -> RedbApprovalStore {
        RedbApprovalStore {
            db: Arc::clone(&self.db),
            cipher: self.cipher.clone(),
        }
    }
}

pub struct RedbPolicyStore {
    db: Arc<Database>,
    cipher: Option<Arc<DbCipher>>,
    pattern_cache: RwLock<Vec<(String, Uuid)>>,
}

impl RedbPolicyStore {
    fn serialize<T: serde::Serialize>(&self, value: &T) -> Result<Vec<u8>> {
        let plaintext = bincode::serialize(value).map_err(|e| Error::Storage(e.to_string()))?;
        match &self.cipher {
            Some(cipher) => cipher.encrypt(&plaintext),
            None => Ok(plaintext),
        }
    }

    fn deserialize<T: serde::de::DeserializeOwned>(&self, data: &[u8]) -> Result<T> {
        let plaintext = match &self.cipher {
            Some(cipher) => cipher.decrypt(data)?,
            None => data.to_vec(),
        };
        bincode::deserialize(&plaintext).map_err(|e| Error::Storage(e.to_string()))
    }

    fn find_matching_binding(&self, wallet_id: &str) -> Option<Uuid> {
        let cache = self.pattern_cache.read().expect("lock poisoned");
        for (pattern, policy_id) in cache.iter() {
            if matches_pattern(pattern, wallet_id) {
                return Some(*policy_id);
            }
        }
        None
    }

    fn rebuild_pattern_cache(&self) -> Result<()> {
        let rtxn = self
            .db
            .begin_read()
            .map_err(|e| Error::Storage(e.to_string()))?;
        let table = rtxn
            .open_table(WALLET_BINDINGS_TABLE)
            .map_err(|e| Error::Storage(e.to_string()))?;

        let mut patterns = Vec::new();
        for result in table.iter().map_err(|e| Error::Storage(e.to_string()))? {
            let (pattern, id_bytes) = result.map_err(|e| Error::Storage(e.to_string()))?;
            let uuid: Uuid = self.deserialize(id_bytes.value())?;
            patterns.push((pattern.value().to_string(), uuid));
        }

        let mut cache = self.pattern_cache.write().expect("lock poisoned");
        *cache = patterns;
        Ok(())
    }
}

#[async_trait]
impl PolicyStore for RedbPolicyStore {
    async fn create(&self, policy: Policy) -> Result<Policy> {
        let wtxn = self
            .db
            .begin_write()
            .map_err(|e| Error::Storage(e.to_string()))?;
        {
            let mut table = wtxn
                .open_table(POLICIES_TABLE)
                .map_err(|e| Error::Storage(e.to_string()))?;
            let key = policy.id.as_bytes();
            let value = self.serialize(&policy)?;
            table
                .insert(key.as_slice(), value.as_slice())
                .map_err(|e| Error::Storage(e.to_string()))?;
        }
        wtxn.commit().map_err(|e| Error::Storage(e.to_string()))?;
        Ok(policy)
    }

    async fn get(&self, id: &Uuid) -> Result<Option<Policy>> {
        let rtxn = self
            .db
            .begin_read()
            .map_err(|e| Error::Storage(e.to_string()))?;
        let table = rtxn
            .open_table(POLICIES_TABLE)
            .map_err(|e| Error::Storage(e.to_string()))?;

        let key = id.as_bytes();
        match table
            .get(key.as_slice())
            .map_err(|e| Error::Storage(e.to_string()))?
        {
            Some(value) => {
                let policy: Policy = self.deserialize(value.value())?;
                Ok(Some(policy))
            }
            None => Ok(None),
        }
    }

    async fn get_by_name(&self, name: &str) -> Result<Option<Policy>> {
        let policies = self.list().await?;
        Ok(policies.into_iter().find(|p| p.name == name))
    }

    async fn list(&self) -> Result<Vec<Policy>> {
        let rtxn = self
            .db
            .begin_read()
            .map_err(|e| Error::Storage(e.to_string()))?;
        let table = rtxn
            .open_table(POLICIES_TABLE)
            .map_err(|e| Error::Storage(e.to_string()))?;

        let mut policies = Vec::new();
        for result in table.iter().map_err(|e| Error::Storage(e.to_string()))? {
            let (_, value) = result.map_err(|e| Error::Storage(e.to_string()))?;
            let policy: Policy = self.deserialize(value.value())?;
            policies.push(policy);
        }
        Ok(policies)
    }

    async fn update(&self, policy: Policy) -> Result<Policy> {
        self.create(policy).await
    }

    async fn delete(&self, id: &Uuid) -> Result<()> {
        let wtxn = self
            .db
            .begin_write()
            .map_err(|e| Error::Storage(e.to_string()))?;
        {
            let mut table = wtxn
                .open_table(POLICIES_TABLE)
                .map_err(|e| Error::Storage(e.to_string()))?;
            let key = id.as_bytes();
            table
                .remove(key.as_slice())
                .map_err(|e| Error::Storage(e.to_string()))?;
        }
        {
            let mut bindings = wtxn
                .open_table(WALLET_BINDINGS_TABLE)
                .map_err(|e| Error::Storage(e.to_string()))?;

            let mut to_remove = Vec::new();
            for result in bindings.iter().map_err(|e| Error::Storage(e.to_string()))? {
                let (pattern, id_bytes) = result.map_err(|e| Error::Storage(e.to_string()))?;
                let uuid: Uuid = self.deserialize(id_bytes.value())?;
                if &uuid == id {
                    to_remove.push(pattern.value().to_string());
                }
            }
            for pattern in to_remove {
                bindings
                    .remove(pattern.as_str())
                    .map_err(|e| Error::Storage(e.to_string()))?;
            }
        }
        wtxn.commit().map_err(|e| Error::Storage(e.to_string()))?;
        self.rebuild_pattern_cache()?;
        Ok(())
    }

    async fn activate(&self, id: &Uuid) -> Result<()> {
        let wtxn = self
            .db
            .begin_write()
            .map_err(|e| Error::Storage(e.to_string()))?;
        let key = id.as_bytes();

        let (policy_bytes, wallet_patterns): (Vec<u8>, Vec<String>) = {
            let table = wtxn
                .open_table(POLICIES_TABLE)
                .map_err(|e| Error::Storage(e.to_string()))?;

            let value = table
                .get(key.as_slice())
                .map_err(|e| Error::Storage(e.to_string()))?
                .ok_or_else(|| Error::NoPolicyFound(id.to_string()))?;

            let mut policy: Policy = self.deserialize(value.value())?;

            let patterns: Vec<String> = {
                let mut all_patterns: Vec<String> = policy
                    .rules
                    .iter()
                    .filter_map(|r| r.conditions.source_wallets.clone())
                    .flatten()
                    .collect();
                all_patterns.sort();
                all_patterns.dedup();
                if all_patterns.is_empty() {
                    vec!["*".to_string()]
                } else {
                    all_patterns
                }
            };

            policy.is_active = true;
            let bytes = self.serialize(&policy)?;
            (bytes, patterns)
        };

        {
            let mut table = wtxn
                .open_table(POLICIES_TABLE)
                .map_err(|e| Error::Storage(e.to_string()))?;
            table
                .insert(key.as_slice(), policy_bytes.as_slice())
                .map_err(|e| Error::Storage(e.to_string()))?;
        }

        {
            let mut bindings = wtxn
                .open_table(WALLET_BINDINGS_TABLE)
                .map_err(|e| Error::Storage(e.to_string()))?;
            let id_bytes = self.serialize(id)?;
            for pattern in &wallet_patterns {
                bindings
                    .insert(pattern.as_str(), id_bytes.as_slice())
                    .map_err(|e| Error::Storage(e.to_string()))?;
            }
        }

        wtxn.commit().map_err(|e| Error::Storage(e.to_string()))?;
        self.rebuild_pattern_cache()?;
        Ok(())
    }

    async fn deactivate(&self, id: &Uuid) -> Result<()> {
        let wtxn = self
            .db
            .begin_write()
            .map_err(|e| Error::Storage(e.to_string()))?;

        {
            let mut table = wtxn
                .open_table(POLICIES_TABLE)
                .map_err(|e| Error::Storage(e.to_string()))?;
            let key = id.as_bytes();

            let maybe_policy: Option<Policy> = table
                .get(key.as_slice())
                .map_err(|e| Error::Storage(e.to_string()))?
                .map(|value| self.deserialize(value.value()))
                .transpose()?;

            if let Some(mut policy) = maybe_policy {
                policy.is_active = false;
                let updated = self.serialize(&policy)?;
                table
                    .insert(key.as_slice(), updated.as_slice())
                    .map_err(|e| Error::Storage(e.to_string()))?;
            }
        }

        {
            let mut bindings = wtxn
                .open_table(WALLET_BINDINGS_TABLE)
                .map_err(|e| Error::Storage(e.to_string()))?;

            let mut to_remove = Vec::new();
            for result in bindings.iter().map_err(|e| Error::Storage(e.to_string()))? {
                let (pattern, id_bytes) = result.map_err(|e| Error::Storage(e.to_string()))?;
                let uuid: Uuid = self.deserialize(id_bytes.value())?;
                if &uuid == id {
                    to_remove.push(pattern.value().to_string());
                }
            }
            for pattern in to_remove {
                bindings
                    .remove(pattern.as_str())
                    .map_err(|e| Error::Storage(e.to_string()))?;
            }
        }

        wtxn.commit().map_err(|e| Error::Storage(e.to_string()))?;
        self.rebuild_pattern_cache()?;
        Ok(())
    }

    async fn get_active_policy(&self, wallet_id: &str) -> Result<Option<Policy>> {
        if let Some(policy_id) = self.find_matching_binding(wallet_id) {
            return self.get(&policy_id).await;
        }
        let policies = self.list().await?;
        Ok(policies.into_iter().find(|p| p.is_active))
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct AddressListData {
    addresses: Vec<AddressEntry>,
}

pub struct RedbAddressListStore {
    db: Arc<Database>,
    cipher: Option<Arc<DbCipher>>,
}

impl RedbAddressListStore {
    fn serialize<T: serde::Serialize>(&self, value: &T) -> Result<Vec<u8>> {
        let plaintext = bincode::serialize(value).map_err(|e| Error::Storage(e.to_string()))?;
        match &self.cipher {
            Some(cipher) => cipher.encrypt(&plaintext),
            None => Ok(plaintext),
        }
    }

    fn deserialize<T: serde::de::DeserializeOwned>(&self, data: &[u8]) -> Result<T> {
        let plaintext = match &self.cipher {
            Some(cipher) => cipher.decrypt(data)?,
            None => data.to_vec(),
        };
        bincode::deserialize(&plaintext).map_err(|e| Error::Storage(e.to_string()))
    }
}

#[async_trait]
impl AddressListStore for RedbAddressListStore {
    async fn create_list(&self, name: &str) -> Result<()> {
        let wtxn = self
            .db
            .begin_write()
            .map_err(|e| Error::Storage(e.to_string()))?;
        {
            let mut table = wtxn
                .open_table(ADDRESS_LISTS_TABLE)
                .map_err(|e| Error::Storage(e.to_string()))?;

            if table
                .get(name)
                .map_err(|e| Error::Storage(e.to_string()))?
                .is_none()
            {
                let data = AddressListData {
                    addresses: Vec::new(),
                };
                let value = self.serialize(&data)?;
                table
                    .insert(name, value.as_slice())
                    .map_err(|e| Error::Storage(e.to_string()))?;
            }
        }
        wtxn.commit().map_err(|e| Error::Storage(e.to_string()))?;
        Ok(())
    }

    async fn delete_list(&self, name: &str) -> Result<()> {
        let wtxn = self
            .db
            .begin_write()
            .map_err(|e| Error::Storage(e.to_string()))?;
        {
            let mut table = wtxn
                .open_table(ADDRESS_LISTS_TABLE)
                .map_err(|e| Error::Storage(e.to_string()))?;
            table
                .remove(name)
                .map_err(|e| Error::Storage(e.to_string()))?;
        }
        wtxn.commit().map_err(|e| Error::Storage(e.to_string()))?;
        Ok(())
    }

    async fn list_names(&self) -> Result<Vec<String>> {
        let rtxn = self
            .db
            .begin_read()
            .map_err(|e| Error::Storage(e.to_string()))?;
        let table = rtxn
            .open_table(ADDRESS_LISTS_TABLE)
            .map_err(|e| Error::Storage(e.to_string()))?;

        let mut names = Vec::new();
        for result in table.iter().map_err(|e| Error::Storage(e.to_string()))? {
            let (name, _) = result.map_err(|e| Error::Storage(e.to_string()))?;
            names.push(name.value().to_string());
        }
        Ok(names)
    }

    async fn add_address(&self, list_name: &str, address: &str, label: Option<&str>) -> Result<()> {
        let wtxn = self
            .db
            .begin_write()
            .map_err(|e| Error::Storage(e.to_string()))?;
        {
            let mut table = wtxn
                .open_table(ADDRESS_LISTS_TABLE)
                .map_err(|e| Error::Storage(e.to_string()))?;

            let mut data: AddressListData = {
                let value = table
                    .get(list_name)
                    .map_err(|e| Error::Storage(e.to_string()))?
                    .ok_or_else(|| Error::AddressListNotFound(list_name.to_string()))?;
                self.deserialize(value.value())?
            };

            if let Some(existing) = data.addresses.iter_mut().find(|e| e.address == address) {
                existing.label = label.map(String::from);
            } else {
                data.addresses.push(AddressEntry {
                    address: address.to_string(),
                    label: label.map(String::from),
                });
            }

            let updated = self.serialize(&data)?;
            table
                .insert(list_name, updated.as_slice())
                .map_err(|e| Error::Storage(e.to_string()))?;
        }
        wtxn.commit().map_err(|e| Error::Storage(e.to_string()))?;
        Ok(())
    }

    async fn remove_address(&self, list_name: &str, address: &str) -> Result<()> {
        let wtxn = self
            .db
            .begin_write()
            .map_err(|e| Error::Storage(e.to_string()))?;
        {
            let mut table = wtxn
                .open_table(ADDRESS_LISTS_TABLE)
                .map_err(|e| Error::Storage(e.to_string()))?;

            let mut data: AddressListData = {
                let value = table
                    .get(list_name)
                    .map_err(|e| Error::Storage(e.to_string()))?
                    .ok_or_else(|| Error::AddressListNotFound(list_name.to_string()))?;
                self.deserialize(value.value())?
            };

            data.addresses.retain(|e| e.address != address);

            let updated = self.serialize(&data)?;
            table
                .insert(list_name, updated.as_slice())
                .map_err(|e| Error::Storage(e.to_string()))?;
        }
        wtxn.commit().map_err(|e| Error::Storage(e.to_string()))?;
        Ok(())
    }

    async fn contains(&self, list_name: &str, address: &str) -> Result<bool> {
        let rtxn = self
            .db
            .begin_read()
            .map_err(|e| Error::Storage(e.to_string()))?;
        let table = rtxn
            .open_table(ADDRESS_LISTS_TABLE)
            .map_err(|e| Error::Storage(e.to_string()))?;

        let value = table
            .get(list_name)
            .map_err(|e| Error::Storage(e.to_string()))?
            .ok_or_else(|| Error::AddressListNotFound(list_name.to_string()))?;

        let data: AddressListData = self.deserialize(value.value())?;

        Ok(data.addresses.iter().any(|e| e.address == address))
    }

    async fn list_addresses(&self, list_name: &str) -> Result<Vec<AddressEntry>> {
        let rtxn = self
            .db
            .begin_read()
            .map_err(|e| Error::Storage(e.to_string()))?;
        let table = rtxn
            .open_table(ADDRESS_LISTS_TABLE)
            .map_err(|e| Error::Storage(e.to_string()))?;

        let value = table
            .get(list_name)
            .map_err(|e| Error::Storage(e.to_string()))?
            .ok_or_else(|| Error::AddressListNotFound(list_name.to_string()))?;

        let data: AddressListData = self.deserialize(value.value())?;

        Ok(data.addresses)
    }
}

pub struct RedbWorkflowStore {
    db: Arc<Database>,
    cipher: Option<Arc<DbCipher>>,
}

impl RedbWorkflowStore {
    fn serialize<T: serde::Serialize>(&self, value: &T) -> Result<Vec<u8>> {
        let plaintext = bincode::serialize(value).map_err(|e| Error::Storage(e.to_string()))?;
        match &self.cipher {
            Some(cipher) => cipher.encrypt(&plaintext),
            None => Ok(plaintext),
        }
    }

    fn deserialize<T: serde::de::DeserializeOwned>(&self, data: &[u8]) -> Result<T> {
        let plaintext = match &self.cipher {
            Some(cipher) => cipher.decrypt(data)?,
            None => data.to_vec(),
        };
        bincode::deserialize(&plaintext).map_err(|e| Error::Storage(e.to_string()))
    }
}

#[async_trait]
impl WorkflowStore for RedbWorkflowStore {
    async fn create_workflow(&self, workflow: ApprovalWorkflow) -> Result<ApprovalWorkflow> {
        let wtxn = self
            .db
            .begin_write()
            .map_err(|e| Error::Storage(e.to_string()))?;
        {
            let mut table = wtxn
                .open_table(WORKFLOWS_TABLE)
                .map_err(|e| Error::Storage(e.to_string()))?;
            let key = workflow.id.as_bytes();
            let value = self.serialize(&workflow)?;
            table
                .insert(key.as_slice(), value.as_slice())
                .map_err(|e| Error::Storage(e.to_string()))?;
        }
        wtxn.commit().map_err(|e| Error::Storage(e.to_string()))?;
        Ok(workflow)
    }

    async fn get_workflow(&self, id: &Uuid) -> Result<Option<ApprovalWorkflow>> {
        let rtxn = self
            .db
            .begin_read()
            .map_err(|e| Error::Storage(e.to_string()))?;
        let table = rtxn
            .open_table(WORKFLOWS_TABLE)
            .map_err(|e| Error::Storage(e.to_string()))?;

        let key = id.as_bytes();
        match table
            .get(key.as_slice())
            .map_err(|e| Error::Storage(e.to_string()))?
        {
            Some(value) => {
                let workflow: ApprovalWorkflow = self.deserialize(value.value())?;
                Ok(Some(workflow))
            }
            None => Ok(None),
        }
    }

    async fn get_workflow_by_transaction(
        &self,
        transaction_id: &Uuid,
    ) -> Result<Option<ApprovalWorkflow>> {
        let rtxn = self
            .db
            .begin_read()
            .map_err(|e| Error::Storage(e.to_string()))?;
        let table = rtxn
            .open_table(WORKFLOWS_TABLE)
            .map_err(|e| Error::Storage(e.to_string()))?;

        for result in table.iter().map_err(|e| Error::Storage(e.to_string()))? {
            let (_, value) = result.map_err(|e| Error::Storage(e.to_string()))?;
            let workflow: ApprovalWorkflow = self.deserialize(value.value())?;
            if workflow.transaction_id == *transaction_id {
                return Ok(Some(workflow));
            }
        }
        Ok(None)
    }

    async fn update_workflow(&self, workflow: ApprovalWorkflow) -> Result<ApprovalWorkflow> {
        self.create_workflow(workflow).await
    }

    async fn list_pending_workflows(&self) -> Result<Vec<ApprovalWorkflow>> {
        let rtxn = self
            .db
            .begin_read()
            .map_err(|e| Error::Storage(e.to_string()))?;
        let table = rtxn
            .open_table(WORKFLOWS_TABLE)
            .map_err(|e| Error::Storage(e.to_string()))?;

        let mut workflows = Vec::new();
        for result in table.iter().map_err(|e| Error::Storage(e.to_string()))? {
            let (_, value) = result.map_err(|e| Error::Storage(e.to_string()))?;
            let workflow: ApprovalWorkflow = self.deserialize(value.value())?;
            if workflow.status == WorkflowStatus::Pending {
                workflows.push(workflow);
            }
        }
        Ok(workflows)
    }

    async fn list_pending_for_approver(
        &self,
        _approver_id: &str,
        groups: &[String],
    ) -> Result<Vec<ApprovalWorkflow>> {
        let rtxn = self
            .db
            .begin_read()
            .map_err(|e| Error::Storage(e.to_string()))?;
        let table = rtxn
            .open_table(WORKFLOWS_TABLE)
            .map_err(|e| Error::Storage(e.to_string()))?;

        let mut workflows = Vec::new();
        for result in table.iter().map_err(|e| Error::Storage(e.to_string()))? {
            let (_, value) = result.map_err(|e| Error::Storage(e.to_string()))?;
            let workflow: ApprovalWorkflow = self.deserialize(value.value())?;
            if workflow.status == WorkflowStatus::Pending {
                let required_groups = workflow.requirement.all_groups();
                if groups.iter().any(|g| required_groups.contains(g)) {
                    workflows.push(workflow);
                }
            }
        }
        Ok(workflows)
    }

    async fn add_approval_to_workflow(
        &self,
        workflow_id: &Uuid,
        approval: Approval,
    ) -> Result<ApprovalWorkflow> {
        let wtxn = self
            .db
            .begin_write()
            .map_err(|e| Error::Storage(e.to_string()))?;

        let workflow = {
            let mut table = wtxn
                .open_table(WORKFLOWS_TABLE)
                .map_err(|e| Error::Storage(e.to_string()))?;

            let key = workflow_id.as_bytes();
            let mut workflow: ApprovalWorkflow = table
                .get(key.as_slice())
                .map_err(|e| Error::Storage(e.to_string()))?
                .ok_or_else(|| Error::WorkflowNotFound(workflow_id.to_string()))
                .map(|v| self.deserialize(v.value()))
                .and_then(|r| r)?;

            workflow.add_approval(approval);

            let value = self.serialize(&workflow)?;
            table
                .insert(key.as_slice(), value.as_slice())
                .map_err(|e| Error::Storage(e.to_string()))?;

            workflow
        };

        wtxn.commit().map_err(|e| Error::Storage(e.to_string()))?;
        Ok(workflow)
    }
}

pub struct RedbGroupStore {
    db: Arc<Database>,
    cipher: Option<Arc<DbCipher>>,
}

impl RedbGroupStore {
    fn serialize<T: serde::Serialize>(&self, value: &T) -> Result<Vec<u8>> {
        let plaintext = bincode::serialize(value).map_err(|e| Error::Storage(e.to_string()))?;
        match &self.cipher {
            Some(cipher) => cipher.encrypt(&plaintext),
            None => Ok(plaintext),
        }
    }

    fn deserialize<T: serde::de::DeserializeOwned>(&self, data: &[u8]) -> Result<T> {
        let plaintext = match &self.cipher {
            Some(cipher) => cipher.decrypt(data)?,
            None => data.to_vec(),
        };
        bincode::deserialize(&plaintext).map_err(|e| Error::Storage(e.to_string()))
    }
}

#[async_trait]
impl GroupStore for RedbGroupStore {
    async fn create(&self, group: ApproverGroup) -> Result<ApproverGroup> {
        let wtxn = self
            .db
            .begin_write()
            .map_err(|e| Error::Storage(e.to_string()))?;
        {
            let mut table = wtxn
                .open_table(GROUPS_TABLE)
                .map_err(|e| Error::Storage(e.to_string()))?;
            let key = group.id.as_bytes();
            let value = self.serialize(&group)?;
            table
                .insert(key.as_slice(), value.as_slice())
                .map_err(|e| Error::Storage(e.to_string()))?;
        }
        wtxn.commit().map_err(|e| Error::Storage(e.to_string()))?;
        Ok(group)
    }

    async fn get(&self, id: &Uuid) -> Result<Option<ApproverGroup>> {
        let rtxn = self
            .db
            .begin_read()
            .map_err(|e| Error::Storage(e.to_string()))?;
        let table = rtxn
            .open_table(GROUPS_TABLE)
            .map_err(|e| Error::Storage(e.to_string()))?;

        let key = id.as_bytes();
        match table
            .get(key.as_slice())
            .map_err(|e| Error::Storage(e.to_string()))?
        {
            Some(value) => {
                let group: ApproverGroup = self.deserialize(value.value())?;
                Ok(Some(group))
            }
            None => Ok(None),
        }
    }

    async fn get_by_name(&self, name: &str) -> Result<Option<ApproverGroup>> {
        let groups = self.list().await?;
        Ok(groups.into_iter().find(|g| g.name == name))
    }

    async fn list(&self) -> Result<Vec<ApproverGroup>> {
        let rtxn = self
            .db
            .begin_read()
            .map_err(|e| Error::Storage(e.to_string()))?;
        let table = rtxn
            .open_table(GROUPS_TABLE)
            .map_err(|e| Error::Storage(e.to_string()))?;

        let mut groups = Vec::new();
        for result in table.iter().map_err(|e| Error::Storage(e.to_string()))? {
            let (_, value) = result.map_err(|e| Error::Storage(e.to_string()))?;
            let group: ApproverGroup = self.deserialize(value.value())?;
            groups.push(group);
        }
        Ok(groups)
    }

    async fn update(&self, group: ApproverGroup) -> Result<ApproverGroup> {
        self.create(group).await
    }

    async fn delete(&self, id: &Uuid) -> Result<()> {
        let wtxn = self
            .db
            .begin_write()
            .map_err(|e| Error::Storage(e.to_string()))?;
        {
            let mut table = wtxn
                .open_table(GROUPS_TABLE)
                .map_err(|e| Error::Storage(e.to_string()))?;
            let key = id.as_bytes();
            table
                .remove(key.as_slice())
                .map_err(|e| Error::Storage(e.to_string()))?;
        }
        wtxn.commit().map_err(|e| Error::Storage(e.to_string()))?;
        Ok(())
    }

    async fn add_member(&self, group_id: &Uuid, member: GroupMember) -> Result<ApproverGroup> {
        let wtxn = self
            .db
            .begin_write()
            .map_err(|e| Error::Storage(e.to_string()))?;

        let group = {
            let mut table = wtxn
                .open_table(GROUPS_TABLE)
                .map_err(|e| Error::Storage(e.to_string()))?;

            let key = group_id.as_bytes();
            let mut group: ApproverGroup = table
                .get(key.as_slice())
                .map_err(|e| Error::Storage(e.to_string()))?
                .ok_or_else(|| Error::GroupNotFound(group_id.to_string()))
                .map(|v| self.deserialize(v.value()))
                .and_then(|r| r)?;

            if !group
                .members
                .iter()
                .any(|m| m.approver_id == member.approver_id)
            {
                group.members.push(member);
                group.updated_at = chrono::Utc::now();
            }

            let value = self.serialize(&group)?;
            table
                .insert(key.as_slice(), value.as_slice())
                .map_err(|e| Error::Storage(e.to_string()))?;

            group
        };

        wtxn.commit().map_err(|e| Error::Storage(e.to_string()))?;
        Ok(group)
    }

    async fn remove_member(&self, group_id: &Uuid, approver_id: &str) -> Result<ApproverGroup> {
        let wtxn = self
            .db
            .begin_write()
            .map_err(|e| Error::Storage(e.to_string()))?;

        let group = {
            let mut table = wtxn
                .open_table(GROUPS_TABLE)
                .map_err(|e| Error::Storage(e.to_string()))?;

            let key = group_id.as_bytes();
            let mut group: ApproverGroup = table
                .get(key.as_slice())
                .map_err(|e| Error::Storage(e.to_string()))?
                .ok_or_else(|| Error::GroupNotFound(group_id.to_string()))
                .map(|v| self.deserialize(v.value()))
                .and_then(|r| r)?;

            group.members.retain(|m| m.approver_id != approver_id);
            group.updated_at = chrono::Utc::now();

            let value = self.serialize(&group)?;
            table
                .insert(key.as_slice(), value.as_slice())
                .map_err(|e| Error::Storage(e.to_string()))?;

            group
        };

        wtxn.commit().map_err(|e| Error::Storage(e.to_string()))?;
        Ok(group)
    }

    async fn get_groups_for_approver(&self, approver_id: &str) -> Result<Vec<ApproverGroup>> {
        let groups = self.list().await?;
        Ok(groups
            .into_iter()
            .filter(|g| g.members.iter().any(|m| m.approver_id == approver_id))
            .collect())
    }
}

pub struct RedbApprovalStore {
    db: Arc<Database>,
    cipher: Option<Arc<DbCipher>>,
}

impl RedbApprovalStore {
    fn serialize<T: serde::Serialize>(&self, value: &T) -> Result<Vec<u8>> {
        let plaintext = bincode::serialize(value).map_err(|e| Error::Storage(e.to_string()))?;
        match &self.cipher {
            Some(cipher) => cipher.encrypt(&plaintext),
            None => Ok(plaintext),
        }
    }

    fn deserialize<T: serde::de::DeserializeOwned>(&self, data: &[u8]) -> Result<T> {
        let plaintext = match &self.cipher {
            Some(cipher) => cipher.decrypt(data)?,
            None => data.to_vec(),
        };
        bincode::deserialize(&plaintext).map_err(|e| Error::Storage(e.to_string()))
    }
}

#[async_trait]
impl ApprovalStore for RedbApprovalStore {
    async fn create(&self, request: ApprovalRequest) -> Result<ApprovalRequest> {
        let wtxn = self
            .db
            .begin_write()
            .map_err(|e| Error::Storage(e.to_string()))?;
        {
            let mut table = wtxn
                .open_table(APPROVALS_TABLE)
                .map_err(|e| Error::Storage(e.to_string()))?;
            let key = request.id.as_bytes();
            let value = self.serialize(&request)?;
            table
                .insert(key.as_slice(), value.as_slice())
                .map_err(|e| Error::Storage(e.to_string()))?;
        }
        wtxn.commit().map_err(|e| Error::Storage(e.to_string()))?;
        Ok(request)
    }

    async fn get(&self, id: &Uuid) -> Result<Option<ApprovalRequest>> {
        let rtxn = self
            .db
            .begin_read()
            .map_err(|e| Error::Storage(e.to_string()))?;
        let table = rtxn
            .open_table(APPROVALS_TABLE)
            .map_err(|e| Error::Storage(e.to_string()))?;

        let key = id.as_bytes();
        match table
            .get(key.as_slice())
            .map_err(|e| Error::Storage(e.to_string()))?
        {
            Some(value) => {
                let request: ApprovalRequest = self.deserialize(value.value())?;
                Ok(Some(request))
            }
            None => Ok(None),
        }
    }

    async fn get_by_transaction(&self, transaction_id: &Uuid) -> Result<Option<ApprovalRequest>> {
        let rtxn = self
            .db
            .begin_read()
            .map_err(|e| Error::Storage(e.to_string()))?;
        let table = rtxn
            .open_table(APPROVALS_TABLE)
            .map_err(|e| Error::Storage(e.to_string()))?;

        for result in table.iter().map_err(|e| Error::Storage(e.to_string()))? {
            let (_, value) = result.map_err(|e| Error::Storage(e.to_string()))?;
            let request: ApprovalRequest = self.deserialize(value.value())?;
            if request.transaction_id == *transaction_id {
                return Ok(Some(request));
            }
        }
        Ok(None)
    }

    async fn update(&self, request: ApprovalRequest) -> Result<ApprovalRequest> {
        self.create(request).await
    }

    async fn list_pending(&self) -> Result<Vec<ApprovalRequest>> {
        let rtxn = self
            .db
            .begin_read()
            .map_err(|e| Error::Storage(e.to_string()))?;
        let table = rtxn
            .open_table(APPROVALS_TABLE)
            .map_err(|e| Error::Storage(e.to_string()))?;

        let mut requests = Vec::new();
        for result in table.iter().map_err(|e| Error::Storage(e.to_string()))? {
            let (_, value) = result.map_err(|e| Error::Storage(e.to_string()))?;
            let request: ApprovalRequest = self.deserialize(value.value())?;
            if request.status == ApprovalStatus::Pending {
                requests.push(request);
            }
        }
        Ok(requests)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Action, Conditions, Rule};
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_redb_policy_store() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let storage = RedbStorage::open(&db_path).unwrap();
        let store = storage.policy_store();

        let policy = Policy {
            id: Uuid::new_v4(),
            version: "1.0".into(),
            name: "test".into(),
            description: None,
            rules: vec![Rule {
                id: "test".into(),
                description: None,
                conditions: Conditions::default(),
                action: Action::Allow,
                approval: None,
            }],
            default_action: Action::Deny,
            content_hash: None,
            created_at: None,
            created_by: None,
            is_active: false,
        };

        let created = store.create(policy.clone()).await.unwrap();
        assert_eq!(created.name, "test");

        let fetched = store.get(&created.id).await.unwrap();
        assert!(fetched.is_some());
        assert_eq!(fetched.unwrap().name, "test");

        store.activate(&created.id).await.unwrap();

        let fetched_after_activate = store.get(&created.id).await.unwrap();
        assert!(fetched_after_activate.is_some());
        assert!(fetched_after_activate.unwrap().is_active);

        let active = store.get_active_policy("any-wallet").await.unwrap();
        assert!(active.is_some(), "get_active_policy should find a policy");
        assert!(
            active.unwrap().is_active,
            "policy from get_active_policy should be active"
        );

        store.deactivate(&created.id).await.unwrap();
        let fetched = store.get(&created.id).await.unwrap();
        assert!(!fetched.unwrap().is_active);

        store.delete(&created.id).await.unwrap();
        let fetched = store.get(&created.id).await.unwrap();
        assert!(fetched.is_none());
    }

    #[tokio::test]
    async fn test_redb_address_list_store() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let storage = RedbStorage::open(&db_path).unwrap();
        let store = storage.address_list_store();

        store.create_list("vendors").await.unwrap();

        let names = store.list_names().await.unwrap();
        assert_eq!(names.len(), 1);
        assert_eq!(names[0], "vendors");

        store
            .add_address("vendors", "bc1qtest", Some("Test Vendor"))
            .await
            .unwrap();
        assert!(store.contains("vendors", "bc1qtest").await.unwrap());
        assert!(!store.contains("vendors", "bc1qother").await.unwrap());

        let entries = store.list_addresses("vendors").await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].address, "bc1qtest");
        assert_eq!(entries[0].label, Some("Test Vendor".to_string()));

        store.remove_address("vendors", "bc1qtest").await.unwrap();
        assert!(!store.contains("vendors", "bc1qtest").await.unwrap());

        store.delete_list("vendors").await.unwrap();
        let names = store.list_names().await.unwrap();
        assert!(names.is_empty());
    }

    #[tokio::test]
    async fn test_wallet_pattern_matching() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let storage = RedbStorage::open(&db_path).unwrap();
        let store = storage.policy_store();

        let policy = Policy {
            id: Uuid::new_v4(),
            version: "1.0".into(),
            name: "treasury".into(),
            description: None,
            rules: vec![Rule {
                id: "test".into(),
                description: None,
                conditions: Conditions {
                    source_wallets: Some(vec!["treasury-hot-*".to_string()]),
                    ..Conditions::default()
                },
                action: Action::Allow,
                approval: None,
            }],
            default_action: Action::Deny,
            content_hash: None,
            created_at: None,
            created_by: None,
            is_active: false,
        };

        store.create(policy.clone()).await.unwrap();
        store.activate(&policy.id).await.unwrap();

        let matched = store.get_active_policy("treasury-hot-1").await.unwrap();
        assert!(matched.is_some());
        assert_eq!(matched.unwrap().name, "treasury");

        let matched = store.get_active_policy("treasury-hot-prod").await.unwrap();
        assert!(matched.is_some());

        let fallback = store.get_active_policy("cold-storage").await.unwrap();
        assert!(
            fallback.is_some(),
            "should fall back to active policy when no binding matches"
        );
    }

    #[tokio::test]
    async fn test_encrypted_redb_policy_store() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("encrypted.db");
        let key = [0x42u8; 32];
        let cipher = DbCipher::new(&key);
        let storage = RedbStorage::open_encrypted(&db_path, cipher).unwrap();
        let store = storage.policy_store();

        let policy = Policy {
            id: Uuid::new_v4(),
            version: "1.0".into(),
            name: "encrypted-test".into(),
            description: None,
            rules: vec![Rule {
                id: "test".into(),
                description: None,
                conditions: Conditions::default(),
                action: Action::Allow,
                approval: None,
            }],
            default_action: Action::Deny,
            content_hash: None,
            created_at: None,
            created_by: None,
            is_active: false,
        };

        let created = store.create(policy.clone()).await.unwrap();
        assert_eq!(created.name, "encrypted-test");

        let fetched = store.get(&created.id).await.unwrap();
        assert!(fetched.is_some());
        assert_eq!(fetched.unwrap().name, "encrypted-test");

        let raw_bytes = std::fs::read(&db_path).unwrap();
        assert!(
            !raw_bytes
                .windows(b"encrypted-test".len())
                .any(|w| w == b"encrypted-test"),
            "policy name should not appear in plaintext in database file"
        );
    }

    #[tokio::test]
    async fn test_db_cipher_from_hex() {
        let hex_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let cipher = DbCipher::from_hex(hex_key).unwrap();

        let plaintext = b"test data";
        let encrypted = cipher.encrypt(plaintext).unwrap();
        let decrypted = cipher.decrypt(&encrypted).unwrap();
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());

        assert!(DbCipher::from_hex("tooshort").is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        let db_path = dir.path().join("perms.db");
        let _storage = RedbStorage::open(&db_path).unwrap();

        let metadata = std::fs::metadata(&db_path).unwrap();
        let mode = metadata.permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "database file should have 0600 permissions"
        );
    }
}
