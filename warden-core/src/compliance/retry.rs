use crate::retry::TieredRetryPolicy;

use super::types::{ComplianceError, ComplianceProvider, ScreeningResult};

pub struct RetryingComplianceProvider<P: ComplianceProvider> {
    inner: P,
    retry_policy: TieredRetryPolicy,
}

impl<P: ComplianceProvider> RetryingComplianceProvider<P> {
    pub fn new(provider: P) -> Self {
        Self {
            inner: provider,
            retry_policy: TieredRetryPolicy::default(),
        }
    }

    pub fn with_retry_policy(mut self, policy: TieredRetryPolicy) -> Self {
        self.retry_policy = policy;
        self
    }
}

#[async_trait::async_trait]
impl<P: ComplianceProvider> ComplianceProvider for RetryingComplianceProvider<P> {
    fn provider_name(&self) -> &str {
        self.inner.provider_name()
    }

    async fn screen_address(
        &self,
        address: &str,
    ) -> std::result::Result<ScreeningResult, ComplianceError> {
        self.retry_policy
            .execute(|| self.inner.screen_address(address))
            .await
    }

    async fn register_transfer(
        &self,
        tx_hash: &str,
        output_address: &str,
        amount_btc: f64,
    ) -> std::result::Result<(), ComplianceError> {
        self.retry_policy
            .execute(|| {
                self.inner
                    .register_transfer(tx_hash, output_address, amount_btc)
            })
            .await
    }

    async fn health_check(&self) -> std::result::Result<(), ComplianceError> {
        self.inner.health_check().await
    }
}
