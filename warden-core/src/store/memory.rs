#![forbid(unsafe_code)]

use async_trait::async_trait;
use indexmap::IndexMap;
use parking_lot::RwLock;
use std::collections::HashMap;
use uuid::Uuid;

use super::{AddressEntry, AddressListStore, PolicyStore};
use crate::pattern::matches_pattern;
use crate::policy::Policy;
use crate::{Error, Result};

pub struct InMemoryAddressListStore {
    lists: RwLock<HashMap<String, HashMap<String, Option<String>>>>,
}

impl InMemoryAddressListStore {
    pub fn new() -> Self {
        Self {
            lists: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryAddressListStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AddressListStore for InMemoryAddressListStore {
    async fn create_list(&self, name: &str) -> Result<()> {
        let mut lists = self.lists.write();
        lists.entry(name.to_string()).or_default();
        Ok(())
    }

    async fn delete_list(&self, name: &str) -> Result<()> {
        let mut lists = self.lists.write();
        lists.remove(name);
        Ok(())
    }

    async fn list_names(&self) -> Result<Vec<String>> {
        let lists = self.lists.read();
        Ok(lists.keys().cloned().collect())
    }

    async fn add_address(&self, list_name: &str, address: &str, label: Option<&str>) -> Result<()> {
        let mut lists = self.lists.write();
        let list = lists
            .get_mut(list_name)
            .ok_or_else(|| Error::AddressListNotFound(list_name.to_string()))?;
        list.insert(address.to_string(), label.map(String::from));
        Ok(())
    }

    async fn remove_address(&self, list_name: &str, address: &str) -> Result<()> {
        let mut lists = self.lists.write();
        let list = lists
            .get_mut(list_name)
            .ok_or_else(|| Error::AddressListNotFound(list_name.to_string()))?;
        list.remove(address);
        Ok(())
    }

    async fn contains(&self, list_name: &str, address: &str) -> Result<bool> {
        let lists = self.lists.read();
        let list = lists
            .get(list_name)
            .ok_or_else(|| Error::AddressListNotFound(list_name.to_string()))?;
        Ok(list.contains_key(address))
    }

    async fn list_addresses(&self, list_name: &str) -> Result<Vec<AddressEntry>> {
        let lists = self.lists.read();
        let list = lists
            .get(list_name)
            .ok_or_else(|| Error::AddressListNotFound(list_name.to_string()))?;
        Ok(list
            .iter()
            .map(|(addr, label)| AddressEntry {
                address: addr.clone(),
                label: label.clone(),
            })
            .collect())
    }
}

pub struct InMemoryPolicyStore {
    policies: RwLock<HashMap<Uuid, Policy>>,
    wallet_bindings: RwLock<IndexMap<String, Uuid>>,
}

impl InMemoryPolicyStore {
    pub fn new() -> Self {
        Self {
            policies: RwLock::new(HashMap::new()),
            wallet_bindings: RwLock::new(IndexMap::new()),
        }
    }

    fn find_matching_binding(
        &self,
        wallet_id: &str,
        bindings: &IndexMap<String, Uuid>,
    ) -> Option<Uuid> {
        for (pattern, policy_id) in bindings {
            if matches_pattern(pattern, wallet_id) {
                return Some(*policy_id);
            }
        }
        None
    }
}

impl Default for InMemoryPolicyStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl PolicyStore for InMemoryPolicyStore {
    async fn create(&self, policy: Policy) -> Result<Policy> {
        let mut policies = self.policies.write();
        policies.insert(policy.id, policy.clone());
        Ok(policy)
    }

    async fn get(&self, id: &Uuid) -> Result<Option<Policy>> {
        let policies = self.policies.read();
        Ok(policies.get(id).cloned())
    }

    async fn get_by_name(&self, name: &str) -> Result<Option<Policy>> {
        let policies = self.policies.read();
        Ok(policies.values().find(|p| p.name == name).cloned())
    }

    async fn list(&self) -> Result<Vec<Policy>> {
        let policies = self.policies.read();
        Ok(policies.values().cloned().collect())
    }

    async fn update(&self, policy: Policy) -> Result<Policy> {
        let mut policies = self.policies.write();
        policies.insert(policy.id, policy.clone());
        Ok(policy)
    }

    async fn delete(&self, id: &Uuid) -> Result<()> {
        let mut policies = self.policies.write();
        policies.remove(id);
        let mut bindings = self.wallet_bindings.write();
        bindings.retain(|_, v| v != id);
        Ok(())
    }

    async fn activate(&self, id: &Uuid) -> Result<()> {
        let mut policies = self.policies.write();
        let policy = policies
            .get_mut(id)
            .ok_or_else(|| Error::NoPolicyFound(id.to_string()))?;
        policy.is_active = true;

        let mut bindings = self.wallet_bindings.write();
        let mut found_wallets = false;
        for rule in &policy.rules {
            if let Some(ref wallets) = rule.conditions.source_wallets {
                for pattern in wallets {
                    bindings.insert(pattern.clone(), *id);
                    found_wallets = true;
                }
            }
        }
        if !found_wallets {
            bindings.insert("*".to_string(), *id);
        }
        Ok(())
    }

    async fn deactivate(&self, id: &Uuid) -> Result<()> {
        let mut policies = self.policies.write();
        if let Some(policy) = policies.get_mut(id) {
            policy.is_active = false;
        }
        let mut bindings = self.wallet_bindings.write();
        bindings.retain(|_, v| v != id);
        Ok(())
    }

    async fn get_active_policy(&self, wallet_id: &str) -> Result<Option<Policy>> {
        // Read bindings first and release lock before acquiring policies lock.
        // This matches the lock order used by activate/deactivate (policies -> bindings)
        // by not holding both locks simultaneously.
        let maybe_policy_id = {
            let bindings = self.wallet_bindings.read();
            self.find_matching_binding(wallet_id, &bindings)
        };

        let policies = self.policies.read();
        if let Some(policy_id) = maybe_policy_id {
            return Ok(policies.get(&policy_id).cloned());
        }

        Ok(policies.values().find(|p| p.is_active).cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Action, Conditions, Rule};

    #[tokio::test]
    async fn test_address_list_store() {
        let store = InMemoryAddressListStore::new();
        store.create_list("vendors").await.unwrap();
        store
            .add_address("vendors", "bc1qtest", Some("Test"))
            .await
            .unwrap();
        assert!(store.contains("vendors", "bc1qtest").await.unwrap());
        assert!(!store.contains("vendors", "bc1qother").await.unwrap());
    }

    #[tokio::test]
    async fn test_policy_store() {
        let store = InMemoryPolicyStore::new();
        let policy = Policy {
            id: Uuid::new_v4(),
            version: "1.0".into(),
            name: "test".into(),
            description: None,
            rules: vec![Rule {
                id: "test".into(),
                description: None,
                conditions: Conditions {
                    source_wallets: Some(vec!["*".into()]),
                    ..Default::default()
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
        let created = store.create(policy.clone()).await.unwrap();
        assert_eq!(created.name, "test");
        store.activate(&created.id).await.unwrap();
        let active = store.get_active_policy("any-wallet").await.unwrap();
        assert!(active.is_some());
    }
}
