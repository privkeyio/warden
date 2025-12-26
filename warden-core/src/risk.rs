#![forbid(unsafe_code)]

use chrono::{DateTime, Datelike, Timelike, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskScore {
    pub total: u32,
    pub level: RiskLevel,
    pub factors: RiskFactors,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFactors {
    pub amount: u32,
    pub time: u32,
    pub destination: u32,
    pub velocity: u32,
    pub script: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RiskLevel::Low => write!(f, "low"),
            RiskLevel::Medium => write!(f, "medium"),
            RiskLevel::High => write!(f, "high"),
            RiskLevel::Critical => write!(f, "critical"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskConfig {
    pub amount_weight: u32,
    pub time_weight: u32,
    pub destination_weight: u32,
    pub velocity_weight: u32,
    pub script_weight: u32,
    pub business_hours: (u32, u32),
    pub business_days: Vec<chrono::Weekday>,
}

impl Default for RiskConfig {
    fn default() -> Self {
        Self {
            amount_weight: 40,
            time_weight: 20,
            destination_weight: 20,
            velocity_weight: 10,
            script_weight: 10,
            business_hours: (9, 17),
            business_days: vec![
                chrono::Weekday::Mon,
                chrono::Weekday::Tue,
                chrono::Weekday::Wed,
                chrono::Weekday::Thu,
                chrono::Weekday::Fri,
            ],
        }
    }
}

pub struct RiskEngine {
    config: RiskConfig,
}

impl RiskEngine {
    pub fn new(config: RiskConfig) -> Self {
        Self { config }
    }

    pub fn calculate(
        &self,
        amount_sats: u64,
        timestamp: DateTime<Utc>,
        destination_risk: u32,
        velocity_utilization: f64,
        miniscript_path: Option<&str>,
    ) -> RiskScore {
        let factors = RiskFactors {
            amount: self.calculate_amount_risk(amount_sats),
            time: self.calculate_time_risk(timestamp),
            destination: destination_risk.min(20),
            velocity: self.calculate_velocity_risk(velocity_utilization),
            script: self.calculate_script_risk(miniscript_path),
        };

        let total = self.weighted_total(&factors);
        let level = match total {
            0..=30 => RiskLevel::Low,
            31..=70 => RiskLevel::Medium,
            71..=90 => RiskLevel::High,
            _ => RiskLevel::Critical,
        };

        RiskScore {
            total,
            level,
            factors,
        }
    }

    fn calculate_amount_risk(&self, amount_sats: u64) -> u32 {
        let btc = amount_sats as f64 / 100_000_000.0;
        match btc {
            x if x < 0.1 => 0,
            x if x < 0.5 => 10,
            x if x < 1.0 => 20,
            x if x < 5.0 => 30,
            _ => 40,
        }
    }

    fn calculate_time_risk(&self, timestamp: DateTime<Utc>) -> u32 {
        let hour = timestamp.hour();
        let weekday = timestamp.weekday();

        let mut risk = 0u32;

        if hour < self.config.business_hours.0 || hour >= self.config.business_hours.1 {
            risk += 10;
        }

        if !self.config.business_days.contains(&weekday) {
            risk += 10;
        }

        risk.min(20)
    }

    fn calculate_velocity_risk(&self, utilization: f64) -> u32 {
        match utilization {
            x if x < 0.5 => 0,
            x if x < 0.7 => 3,
            x if x < 0.9 => 7,
            _ => 10,
        }
    }

    fn calculate_script_risk(&self, miniscript_path: Option<&str>) -> u32 {
        match miniscript_path {
            None | Some("primary") => 0,
            Some("recovery") => 8,
            Some("emergency") => 10,
            _ => 5,
        }
    }

    fn weighted_total(&self, factors: &RiskFactors) -> u32 {
        (factors.amount * self.config.amount_weight / 100)
            + (factors.time * self.config.time_weight / 100)
            + (factors.destination * self.config.destination_weight / 100)
            + (factors.velocity * self.config.velocity_weight / 100)
            + (factors.script * self.config.script_weight / 100)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_amount_risk_tiers() {
        let engine = RiskEngine::new(RiskConfig::default());
        assert_eq!(engine.calculate_amount_risk(5_000_000), 0);
        assert_eq!(engine.calculate_amount_risk(30_000_000), 10);
        assert_eq!(engine.calculate_amount_risk(70_000_000), 20);
        assert_eq!(engine.calculate_amount_risk(300_000_000), 30);
        assert_eq!(engine.calculate_amount_risk(1_000_000_000), 40);
    }

    #[test]
    fn test_script_risk() {
        let engine = RiskEngine::new(RiskConfig::default());
        assert_eq!(engine.calculate_script_risk(None), 0);
        assert_eq!(engine.calculate_script_risk(Some("primary")), 0);
        assert_eq!(engine.calculate_script_risk(Some("recovery")), 8);
        assert_eq!(engine.calculate_script_risk(Some("emergency")), 10);
    }

    #[test]
    fn test_risk_level_classification() {
        let engine = RiskEngine::new(RiskConfig::default());
        let low = engine.calculate(1_000_000, Utc::now(), 0, 0.1, None);
        assert_eq!(low.level, RiskLevel::Low);
    }
}
