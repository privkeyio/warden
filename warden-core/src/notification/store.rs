//! Notification storage.

use async_trait::async_trait;
use parking_lot::RwLock;
use std::collections::HashMap;
use uuid::Uuid;

use super::types::{NotificationRecord, NotificationStatus};
use crate::Result;

#[async_trait]
pub trait NotificationStore: Send + Sync {
    async fn save_record(&self, record: NotificationRecord) -> Result<NotificationRecord>;
    async fn get_records_for_workflow(&self, workflow_id: &Uuid)
        -> Result<Vec<NotificationRecord>>;
    async fn update_record(&self, record: NotificationRecord) -> Result<NotificationRecord>;
    async fn list_pending(&self) -> Result<Vec<NotificationRecord>>;
}

pub struct InMemoryNotificationStore {
    records: RwLock<HashMap<Uuid, NotificationRecord>>,
}

impl InMemoryNotificationStore {
    pub fn new() -> Self {
        Self {
            records: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryNotificationStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NotificationStore for InMemoryNotificationStore {
    async fn save_record(&self, record: NotificationRecord) -> Result<NotificationRecord> {
        let mut records = self.records.write();
        records.insert(record.id, record.clone());
        Ok(record)
    }

    async fn get_records_for_workflow(
        &self,
        workflow_id: &Uuid,
    ) -> Result<Vec<NotificationRecord>> {
        let records = self.records.read();
        Ok(records
            .values()
            .filter(|r| &r.workflow_id == workflow_id)
            .cloned()
            .collect())
    }

    async fn update_record(&self, record: NotificationRecord) -> Result<NotificationRecord> {
        let mut records = self.records.write();
        records.insert(record.id, record.clone());
        Ok(record)
    }

    async fn list_pending(&self) -> Result<Vec<NotificationRecord>> {
        let records = self.records.read();
        Ok(records
            .values()
            .filter(|r| r.status == NotificationStatus::Pending)
            .cloned()
            .collect())
    }
}
