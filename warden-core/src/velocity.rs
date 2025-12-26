#![forbid(unsafe_code)]

use async_trait::async_trait;
use chrono::{DateTime, Datelike, Duration, Timelike, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WindowType {
    Hourly,
    Daily,
    Weekly,
    Monthly,
}

impl std::fmt::Display for WindowType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WindowType::Hourly => write!(f, "hourly"),
            WindowType::Daily => write!(f, "daily"),
            WindowType::Weekly => write!(f, "weekly"),
            WindowType::Monthly => write!(f, "monthly"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VelocityWindow {
    pub window_type: WindowType,
    pub used_sats: u64,
    pub limit_sats: u64,
    pub transaction_count: u32,
    pub window_start: DateTime<Utc>,
    pub window_end: DateTime<Utc>,
}

impl VelocityWindow {
    pub fn utilization(&self) -> f64 {
        if self.limit_sats == 0 {
            return 0.0;
        }
        self.used_sats as f64 / self.limit_sats as f64
    }

    pub fn remaining_sats(&self) -> u64 {
        self.limit_sats.saturating_sub(self.used_sats)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VelocityCheck {
    pub window_type: WindowType,
    pub allowed: bool,
    pub current_sats: u64,
    pub limit_sats: u64,
    pub would_be_sats: u64,
    pub utilization: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VelocityLimits {
    pub hourly_sats: u64,
    pub daily_sats: u64,
    pub weekly_sats: u64,
    pub monthly_sats: u64,
}

impl Default for VelocityLimits {
    fn default() -> Self {
        Self {
            hourly_sats: 50_000_000,
            daily_sats: 200_000_000,
            weekly_sats: 500_000_000,
            monthly_sats: 1_000_000_000,
        }
    }
}

impl VelocityLimits {
    pub fn get(&self, window_type: WindowType) -> u64 {
        match window_type {
            WindowType::Hourly => self.hourly_sats,
            WindowType::Daily => self.daily_sats,
            WindowType::Weekly => self.weekly_sats,
            WindowType::Monthly => self.monthly_sats,
        }
    }
}

#[async_trait]
pub trait VelocityStore: Send + Sync {
    async fn get_window(
        &self,
        user_id: &str,
        window_type: WindowType,
        path: Option<&str>,
    ) -> Result<Option<VelocityWindow>>;

    async fn update_window(
        &self,
        user_id: &str,
        window_type: WindowType,
        path: Option<&str>,
        amount_sats: u64,
    ) -> Result<VelocityWindow>;

    async fn get_all_windows(
        &self,
        user_id: &str,
        path: Option<&str>,
    ) -> Result<HashMap<WindowType, VelocityWindow>>;
}

pub struct VelocityTracker<S: VelocityStore> {
    store: S,
    limits: VelocityLimits,
}

impl<S: VelocityStore> VelocityTracker<S> {
    pub fn new(store: S, limits: VelocityLimits) -> Self {
        Self { store, limits }
    }

    pub async fn check(
        &self,
        user_id: &str,
        amount_sats: u64,
        path: Option<&str>,
    ) -> Result<Vec<VelocityCheck>> {
        let mut checks = Vec::new();

        for window_type in [
            WindowType::Hourly,
            WindowType::Daily,
            WindowType::Weekly,
            WindowType::Monthly,
        ] {
            let window = self.store.get_window(user_id, window_type, path).await?;
            let current = window.map(|w| w.used_sats).unwrap_or(0);
            let limit = self.limits.get(window_type);
            let would_be = current + amount_sats;

            checks.push(VelocityCheck {
                window_type,
                allowed: would_be <= limit,
                current_sats: current,
                limit_sats: limit,
                would_be_sats: would_be,
                utilization: if limit == 0 {
                    0.0
                } else {
                    would_be as f64 / limit as f64
                },
            });
        }

        Ok(checks)
    }

    pub async fn check_and_update(
        &self,
        user_id: &str,
        amount_sats: u64,
        path: Option<&str>,
    ) -> Result<Vec<VelocityCheck>> {
        let checks = self.check(user_id, amount_sats, path).await?;

        if checks.iter().all(|c| c.allowed) {
            for window_type in [
                WindowType::Hourly,
                WindowType::Daily,
                WindowType::Weekly,
                WindowType::Monthly,
            ] {
                self.store
                    .update_window(user_id, window_type, path, amount_sats)
                    .await?;
            }
        }

        Ok(checks)
    }

    pub async fn get_utilizations(
        &self,
        user_id: &str,
        path: Option<&str>,
    ) -> Result<HashMap<WindowType, f64>> {
        let windows = self.store.get_all_windows(user_id, path).await?;
        let mut utilizations = HashMap::new();

        for window_type in [
            WindowType::Hourly,
            WindowType::Daily,
            WindowType::Weekly,
            WindowType::Monthly,
        ] {
            let util = windows
                .get(&window_type)
                .map(|w| w.utilization())
                .unwrap_or(0.0);
            utilizations.insert(window_type, util);
        }

        Ok(utilizations)
    }

    pub async fn max_utilization(&self, user_id: &str, path: Option<&str>) -> Result<f64> {
        let utils = self.get_utilizations(user_id, path).await?;
        Ok(utils.values().cloned().fold(0.0, f64::max))
    }
}

pub struct InMemoryVelocityStore {
    windows: Arc<RwLock<HashMap<String, VelocityWindow>>>,
    limits: VelocityLimits,
}

impl InMemoryVelocityStore {
    pub fn new(limits: VelocityLimits) -> Self {
        Self {
            windows: Arc::new(RwLock::new(HashMap::new())),
            limits,
        }
    }

    fn make_key(user_id: &str, window_type: WindowType, path: Option<&str>) -> String {
        let (start, _) = Self::calculate_bounds(window_type);
        format!(
            "{}:{}:{}:{}",
            user_id,
            window_type,
            path.unwrap_or("primary"),
            start.timestamp()
        )
    }

    fn calculate_bounds(window_type: WindowType) -> (DateTime<Utc>, DateTime<Utc>) {
        let now = Utc::now();

        match window_type {
            WindowType::Hourly => {
                let start = now
                    .date_naive()
                    .and_hms_opt(now.hour(), 0, 0)
                    .unwrap()
                    .and_utc();
                (start, start + Duration::hours(1))
            }
            WindowType::Daily => {
                let start = now.date_naive().and_hms_opt(0, 0, 0).unwrap().and_utc();
                (start, start + Duration::days(1))
            }
            WindowType::Weekly => {
                let days_since_monday = now.weekday().num_days_from_monday();
                let start = (now.date_naive() - Duration::days(days_since_monday as i64))
                    .and_hms_opt(0, 0, 0)
                    .unwrap()
                    .and_utc();
                (start, start + Duration::weeks(1))
            }
            WindowType::Monthly => {
                let start = now
                    .date_naive()
                    .with_day(1)
                    .unwrap()
                    .and_hms_opt(0, 0, 0)
                    .unwrap()
                    .and_utc();
                let next_month = if now.month() == 12 {
                    now.with_year(now.year() + 1)
                        .unwrap()
                        .with_month(1)
                        .unwrap()
                } else {
                    now.with_month(now.month() + 1).unwrap()
                };
                (
                    start,
                    next_month
                        .date_naive()
                        .with_day(1)
                        .unwrap()
                        .and_hms_opt(0, 0, 0)
                        .unwrap()
                        .and_utc(),
                )
            }
        }
    }
}

#[async_trait]
impl VelocityStore for InMemoryVelocityStore {
    async fn get_window(
        &self,
        user_id: &str,
        window_type: WindowType,
        path: Option<&str>,
    ) -> Result<Option<VelocityWindow>> {
        let key = Self::make_key(user_id, window_type, path);
        let windows = self.windows.read().await;
        Ok(windows.get(&key).cloned())
    }

    async fn update_window(
        &self,
        user_id: &str,
        window_type: WindowType,
        path: Option<&str>,
        amount_sats: u64,
    ) -> Result<VelocityWindow> {
        let key = Self::make_key(user_id, window_type, path);
        let (window_start, window_end) = Self::calculate_bounds(window_type);
        let limit = self.limits.get(window_type);

        let mut windows = self.windows.write().await;
        let window = windows.entry(key).or_insert_with(|| VelocityWindow {
            window_type,
            used_sats: 0,
            limit_sats: limit,
            transaction_count: 0,
            window_start,
            window_end,
        });

        window.used_sats += amount_sats;
        window.transaction_count += 1;

        Ok(window.clone())
    }

    async fn get_all_windows(
        &self,
        user_id: &str,
        path: Option<&str>,
    ) -> Result<HashMap<WindowType, VelocityWindow>> {
        let mut result = HashMap::new();

        for window_type in [
            WindowType::Hourly,
            WindowType::Daily,
            WindowType::Weekly,
            WindowType::Monthly,
        ] {
            if let Some(window) = self.get_window(user_id, window_type, path).await? {
                result.insert(window_type, window);
            }
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_velocity_check() {
        let limits = VelocityLimits {
            hourly_sats: 100_000,
            daily_sats: 500_000,
            weekly_sats: 1_000_000,
            monthly_sats: 5_000_000,
        };
        let store = InMemoryVelocityStore::new(limits.clone());
        let tracker = VelocityTracker::new(store, limits);

        let checks = tracker.check("user1", 50_000, None).await.unwrap();
        assert!(checks.iter().all(|c| c.allowed));

        let checks = tracker.check("user1", 200_000, None).await.unwrap();
        assert!(!checks[0].allowed); // hourly exceeded
        assert!(checks[1].allowed); // daily ok
    }

    #[tokio::test]
    async fn test_velocity_update() {
        let limits = VelocityLimits::default();
        let store = InMemoryVelocityStore::new(limits.clone());
        let tracker = VelocityTracker::new(store, limits);

        tracker
            .check_and_update("user1", 10_000_000, None)
            .await
            .unwrap();
        let util = tracker.max_utilization("user1", None).await.unwrap();
        assert!(util > 0.0);
    }
}
