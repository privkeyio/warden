#![forbid(unsafe_code)]

use async_trait::async_trait;
use redb::{Database, ReadableTable, TableDefinition};
use std::path::Path;
use std::sync::{Arc, RwLock};
use uuid::Uuid;

use super::{AddressEntry, AddressListStore, PolicyStore};
use crate::pattern::matches_pattern;
use crate::policy::Policy;
use crate::{Error, Result};

const POLICIES_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("policies");
const WALLET_BINDINGS_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("wallet_bindings");
const ADDRESS_LISTS_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("address_lists");

pub struct RedbStorage {
    db: Arc<Database>,
}

impl RedbStorage {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let db = Database::create(path).map_err(|e| Error::Storage(e.to_string()))?;

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
            wtxn.commit().map_err(|e| Error::Storage(e.to_string()))?;
        }

        Ok(Self { db: Arc::new(db) })
    }

    pub fn policy_store(&self) -> RedbPolicyStore {
        let store = RedbPolicyStore {
            db: Arc::clone(&self.db),
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
        }
    }
}

pub struct RedbPolicyStore {
    db: Arc<Database>,
    pattern_cache: RwLock<Vec<(String, Uuid)>>,
}

impl RedbPolicyStore {
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
            let uuid: Uuid = bincode::deserialize(id_bytes.value())
                .map_err(|e| Error::Storage(e.to_string()))?;
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
            let value = bincode::serialize(&policy).map_err(|e| Error::Storage(e.to_string()))?;
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
                let policy: Policy = bincode::deserialize(value.value())
                    .map_err(|e| Error::Storage(e.to_string()))?;
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
            let policy: Policy =
                bincode::deserialize(value.value()).map_err(|e| Error::Storage(e.to_string()))?;
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
                let uuid: Uuid = bincode::deserialize(id_bytes.value())
                    .map_err(|e| Error::Storage(e.to_string()))?;
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

            let mut policy: Policy =
                bincode::deserialize(value.value()).map_err(|e| Error::Storage(e.to_string()))?;

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
            let bytes = bincode::serialize(&policy).map_err(|e| Error::Storage(e.to_string()))?;
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
            let id_bytes = bincode::serialize(id).map_err(|e| Error::Storage(e.to_string()))?;
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

            let maybe_policy = {
                table
                    .get(key.as_slice())
                    .map_err(|e| Error::Storage(e.to_string()))?
                    .map(|value| {
                        bincode::deserialize::<Policy>(value.value())
                            .map_err(|e| Error::Storage(e.to_string()))
                    })
                    .transpose()?
            };

            if let Some(mut policy) = maybe_policy {
                policy.is_active = false;
                let updated =
                    bincode::serialize(&policy).map_err(|e| Error::Storage(e.to_string()))?;
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
                let uuid: Uuid = bincode::deserialize(id_bytes.value())
                    .map_err(|e| Error::Storage(e.to_string()))?;
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
                let value = bincode::serialize(&data).map_err(|e| Error::Storage(e.to_string()))?;
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
                bincode::deserialize(value.value()).map_err(|e| Error::Storage(e.to_string()))?
            };

            if let Some(existing) = data.addresses.iter_mut().find(|e| e.address == address) {
                existing.label = label.map(String::from);
            } else {
                data.addresses.push(AddressEntry {
                    address: address.to_string(),
                    label: label.map(String::from),
                });
            }

            let updated = bincode::serialize(&data).map_err(|e| Error::Storage(e.to_string()))?;
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
                bincode::deserialize(value.value()).map_err(|e| Error::Storage(e.to_string()))?
            };

            data.addresses.retain(|e| e.address != address);

            let updated = bincode::serialize(&data).map_err(|e| Error::Storage(e.to_string()))?;
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

        let data: AddressListData =
            bincode::deserialize(value.value()).map_err(|e| Error::Storage(e.to_string()))?;

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

        let data: AddressListData =
            bincode::deserialize(value.value()).map_err(|e| Error::Storage(e.to_string()))?;

        Ok(data.addresses)
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
}
