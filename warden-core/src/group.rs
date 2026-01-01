#![forbid(unsafe_code)]

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use uuid::Uuid;

use crate::quorum::GroupId;
use crate::Result;
use zeroize::Zeroizing;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApproverGroup {
    pub id: Uuid,
    pub name: GroupId,
    pub description: Option<String>,
    pub members: Vec<GroupMember>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl ApproverGroup {
    pub fn new(name: impl Into<GroupId>) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            name: name.into(),
            description: None,
            members: Vec::new(),
            created_at: now,
            updated_at: now,
        }
    }

    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    pub fn add_member(&mut self, member: GroupMember) {
        if !self
            .members
            .iter()
            .any(|m| m.approver_id == member.approver_id)
        {
            self.members.push(member);
            self.updated_at = Utc::now();
        }
    }

    pub fn remove_member(&mut self, approver_id: &str) -> bool {
        let len_before = self.members.len();
        self.members.retain(|m| m.approver_id != approver_id);
        if self.members.len() != len_before {
            self.updated_at = Utc::now();
            true
        } else {
            false
        }
    }

    pub fn has_member(&self, approver_id: &str) -> bool {
        self.members.iter().any(|m| m.approver_id == approver_id)
    }

    pub fn member_count(&self) -> usize {
        self.members.len()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMember {
    pub approver_id: String,
    pub display_name: Option<String>,
    pub added_at: DateTime<Utc>,
    pub added_by: Option<String>,
}

impl GroupMember {
    pub fn new(approver_id: impl Into<String>) -> Self {
        Self {
            approver_id: approver_id.into(),
            display_name: None,
            added_at: Utc::now(),
            added_by: None,
        }
    }

    pub fn with_display_name(mut self, name: impl Into<String>) -> Self {
        self.display_name = Some(name.into());
        self
    }

    pub fn with_added_by(mut self, by: impl Into<String>) -> Self {
        self.added_by = Some(by.into());
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Approver {
    pub id: String,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub notification_channels: Vec<NotificationChannel>,
    pub groups: Vec<GroupId>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Approver {
    pub fn new(id: impl Into<String>) -> Self {
        let now = Utc::now();
        Self {
            id: id.into(),
            display_name: None,
            email: None,
            notification_channels: Vec::new(),
            groups: Vec::new(),
            created_at: now,
            updated_at: now,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum NotificationChannel {
    Email {
        address: String,
    },
    Webhook {
        url: String,
        secret: Zeroizing<String>,
    },
    Slack {
        channel_id: String,
        token: Zeroizing<String>,
    },
    Nostr {
        pubkey: String,
    },
}

impl std::fmt::Debug for NotificationChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Email { address } => f.debug_struct("Email").field("address", address).finish(),
            Self::Webhook { url, .. } => f
                .debug_struct("Webhook")
                .field("url", url)
                .field("secret", &"[REDACTED]")
                .finish(),
            Self::Slack { channel_id, .. } => f
                .debug_struct("Slack")
                .field("channel_id", channel_id)
                .field("token", &"[REDACTED]")
                .finish(),
            Self::Nostr { pubkey } => f.debug_struct("Nostr").field("pubkey", pubkey).finish(),
        }
    }
}

#[async_trait]
pub trait GroupStore: Send + Sync {
    async fn create(&self, group: ApproverGroup) -> Result<ApproverGroup>;
    async fn get(&self, id: &Uuid) -> Result<Option<ApproverGroup>>;
    async fn get_by_name(&self, name: &str) -> Result<Option<ApproverGroup>>;
    async fn list(&self) -> Result<Vec<ApproverGroup>>;
    async fn update(&self, group: ApproverGroup) -> Result<ApproverGroup>;
    async fn delete(&self, id: &Uuid) -> Result<()>;
    async fn add_member(&self, group_id: &Uuid, member: GroupMember) -> Result<ApproverGroup>;
    async fn remove_member(&self, group_id: &Uuid, approver_id: &str) -> Result<ApproverGroup>;
    async fn get_groups_for_approver(&self, approver_id: &str) -> Result<Vec<ApproverGroup>>;
}

pub struct InMemoryGroupStore {
    groups: RwLock<HashMap<Uuid, ApproverGroup>>,
}

impl InMemoryGroupStore {
    pub fn new() -> Self {
        Self {
            groups: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryGroupStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl GroupStore for InMemoryGroupStore {
    async fn create(&self, group: ApproverGroup) -> Result<ApproverGroup> {
        let mut groups = self.groups.write().expect("lock poisoned");
        groups.insert(group.id, group.clone());
        Ok(group)
    }

    async fn get(&self, id: &Uuid) -> Result<Option<ApproverGroup>> {
        let groups = self.groups.read().expect("lock poisoned");
        Ok(groups.get(id).cloned())
    }

    async fn get_by_name(&self, name: &str) -> Result<Option<ApproverGroup>> {
        let groups = self.groups.read().expect("lock poisoned");
        Ok(groups.values().find(|g| g.name == name).cloned())
    }

    async fn list(&self) -> Result<Vec<ApproverGroup>> {
        let groups = self.groups.read().expect("lock poisoned");
        Ok(groups.values().cloned().collect())
    }

    async fn update(&self, group: ApproverGroup) -> Result<ApproverGroup> {
        let mut groups = self.groups.write().expect("lock poisoned");
        groups.insert(group.id, group.clone());
        Ok(group)
    }

    async fn delete(&self, id: &Uuid) -> Result<()> {
        let mut groups = self.groups.write().expect("lock poisoned");
        groups.remove(id);
        Ok(())
    }

    async fn add_member(&self, group_id: &Uuid, member: GroupMember) -> Result<ApproverGroup> {
        let mut groups = self.groups.write().expect("lock poisoned");
        if let Some(group) = groups.get_mut(group_id) {
            group.add_member(member);
            Ok(group.clone())
        } else {
            Err(crate::Error::Storage(format!(
                "group not found: {}",
                group_id
            )))
        }
    }

    async fn remove_member(&self, group_id: &Uuid, approver_id: &str) -> Result<ApproverGroup> {
        let mut groups = self.groups.write().expect("lock poisoned");
        if let Some(group) = groups.get_mut(group_id) {
            group.remove_member(approver_id);
            Ok(group.clone())
        } else {
            Err(crate::Error::Storage(format!(
                "group not found: {}",
                group_id
            )))
        }
    }

    async fn get_groups_for_approver(&self, approver_id: &str) -> Result<Vec<ApproverGroup>> {
        let groups = self.groups.read().expect("lock poisoned");
        Ok(groups
            .values()
            .filter(|g| g.has_member(approver_id))
            .cloned()
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_group_lifecycle() {
        let store = InMemoryGroupStore::new();

        let mut group = ApproverGroup::new("treasury-signers");
        group = group.with_description("Treasury signing team");

        let created = store.create(group.clone()).await.unwrap();
        assert_eq!(created.name, "treasury-signers");

        let fetched = store.get(&created.id).await.unwrap().unwrap();
        assert_eq!(fetched.name, "treasury-signers");

        let member = GroupMember::new("alice").with_display_name("Alice");
        let updated = store.add_member(&created.id, member).await.unwrap();
        assert_eq!(updated.member_count(), 1);

        let groups = store.get_groups_for_approver("alice").await.unwrap();
        assert_eq!(groups.len(), 1);

        let updated = store.remove_member(&created.id, "alice").await.unwrap();
        assert_eq!(updated.member_count(), 0);
    }

    #[tokio::test]
    async fn test_get_by_name() {
        let store = InMemoryGroupStore::new();

        let group = ApproverGroup::new("security-team");
        store.create(group).await.unwrap();

        let found = store.get_by_name("security-team").await.unwrap();
        assert!(found.is_some());

        let not_found = store.get_by_name("nonexistent").await.unwrap();
        assert!(not_found.is_none());
    }

    #[test]
    fn test_member_operations() {
        let mut group = ApproverGroup::new("test");

        group.add_member(GroupMember::new("alice"));
        assert!(group.has_member("alice"));
        assert_eq!(group.member_count(), 1);

        group.add_member(GroupMember::new("alice"));
        assert_eq!(group.member_count(), 1);

        group.add_member(GroupMember::new("bob"));
        assert_eq!(group.member_count(), 2);

        assert!(group.remove_member("alice"));
        assert!(!group.has_member("alice"));

        assert!(!group.remove_member("charlie"));
    }
}
