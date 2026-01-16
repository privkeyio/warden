#![forbid(unsafe_code)]

use async_trait::async_trait;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::Notify;

#[derive(Debug, Error)]
pub enum QuotaError {
    #[error("dealer is closed")]
    Closed,
    #[error("quota exceeded")]
    QuotaExceeded,
    #[error("acquisition failed: {0}")]
    AcquisitionFailed(String),
}

#[async_trait]
pub trait SlotSupplier: Send + Sync {
    type Context: Send + Sync;

    async fn acquire(&self, ctx: &Self::Context) -> Result<(), QuotaError>;
    fn release(&self);
    fn available(&self) -> usize;
}

pub struct PermitDealer<S: SlotSupplier> {
    supplier: S,
}

impl<S: SlotSupplier> PermitDealer<S> {
    pub fn new(supplier: S) -> Self {
        Self { supplier }
    }

    pub async fn acquire(&self, ctx: &S::Context) -> Result<OwnedPermit<'_, S>, QuotaError> {
        self.supplier.acquire(ctx).await?;
        Ok(OwnedPermit {
            dealer: self,
            released: false,
        })
    }

    pub fn available(&self) -> usize {
        self.supplier.available()
    }
}

pub struct OwnedPermit<'a, S: SlotSupplier> {
    dealer: &'a PermitDealer<S>,
    released: bool,
}

impl<S: SlotSupplier> OwnedPermit<'_, S> {
    pub fn release(mut self) {
        self.dealer.supplier.release();
        self.released = true;
    }
}

impl<S: SlotSupplier> Drop for OwnedPermit<'_, S> {
    fn drop(&mut self) {
        if !self.released {
            self.dealer.supplier.release();
        }
    }
}

pub struct ClosablePermitDealer<S: SlotSupplier> {
    inner: PermitDealer<S>,
    closed: AtomicBool,
    outstanding: AtomicUsize,
    drain_complete: Notify,
}

impl<S: SlotSupplier> ClosablePermitDealer<S> {
    pub fn new(supplier: S) -> Self {
        Self {
            inner: PermitDealer::new(supplier),
            closed: AtomicBool::new(false),
            outstanding: AtomicUsize::new(0),
            drain_complete: Notify::new(),
        }
    }

    pub async fn acquire(&self, ctx: &S::Context) -> Result<ClosableOwnedPermit<'_, S>, QuotaError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(QuotaError::Closed);
        }

        self.outstanding.fetch_add(1, Ordering::AcqRel);

        // Double-check closed after incrementing to prevent race with close()
        if self.closed.load(Ordering::Acquire) {
            self.dec_outstanding();
            return Err(QuotaError::Closed);
        }

        match self.inner.supplier.acquire(ctx).await {
            Ok(()) => Ok(ClosableOwnedPermit {
                dealer: self,
                released: false,
            }),
            Err(e) => {
                self.dec_outstanding();
                Err(e)
            }
        }
    }

    pub fn close(&self) {
        self.closed.store(true, Ordering::Release);
        if self.outstanding.load(Ordering::Acquire) == 0 {
            self.drain_complete.notify_waiters();
        }
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    pub async fn drain_complete(&self) {
        loop {
            let mut notified = std::pin::pin!(self.drain_complete.notified());
            notified.as_mut().enable();

            if self.outstanding.load(Ordering::Acquire) == 0 {
                return;
            }

            notified.await;
        }
    }

    pub async fn drain_with_timeout(&self, timeout: Duration) -> bool {
        tokio::time::timeout(timeout, self.drain_complete()).await.is_ok()
    }

    pub fn outstanding_count(&self) -> usize {
        self.outstanding.load(Ordering::Acquire)
    }

    pub fn available(&self) -> usize {
        self.inner.available()
    }

    fn dec_outstanding(&self) {
        if self.outstanding.fetch_sub(1, Ordering::AcqRel) == 1
            && self.closed.load(Ordering::Acquire)
        {
            self.drain_complete.notify_waiters();
        }
    }
}

pub struct ClosableOwnedPermit<'a, S: SlotSupplier> {
    dealer: &'a ClosablePermitDealer<S>,
    released: bool,
}

impl<S: SlotSupplier> ClosableOwnedPermit<'_, S> {
    pub fn release(mut self) {
        self.dealer.inner.supplier.release();
        self.dealer.dec_outstanding();
        self.released = true;
    }
}

impl<S: SlotSupplier> Drop for ClosableOwnedPermit<'_, S> {
    fn drop(&mut self) {
        if !self.released {
            self.dealer.inner.supplier.release();
            self.dealer.dec_outstanding();
        }
    }
}

pub struct SemaphoreSlotSupplier {
    semaphore: Arc<tokio::sync::Semaphore>,
}

impl SemaphoreSlotSupplier {
    pub fn new(max_slots: usize) -> Self {
        Self {
            semaphore: Arc::new(tokio::sync::Semaphore::new(max_slots)),
        }
    }
}

#[async_trait]
impl SlotSupplier for SemaphoreSlotSupplier {
    type Context = ();

    async fn acquire(&self, _ctx: &Self::Context) -> Result<(), QuotaError> {
        self.semaphore
            .try_acquire()
            .map(|permit| permit.forget())
            .map_err(|_| QuotaError::QuotaExceeded)
    }

    fn release(&self) {
        self.semaphore.add_permits(1);
    }

    fn available(&self) -> usize {
        self.semaphore.available_permits()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_permit_dealer_acquire_release() {
        let supplier = SemaphoreSlotSupplier::new(2);
        let dealer = PermitDealer::new(supplier);

        assert_eq!(dealer.available(), 2);

        let permit1 = dealer.acquire(&()).await.unwrap();
        assert_eq!(dealer.available(), 1);

        let permit2 = dealer.acquire(&()).await.unwrap();
        assert_eq!(dealer.available(), 0);

        assert!(dealer.acquire(&()).await.is_err());

        permit1.release();
        assert_eq!(dealer.available(), 1);

        drop(permit2);
        assert_eq!(dealer.available(), 2);
    }

    #[tokio::test]
    async fn test_closable_permit_dealer_close() {
        let supplier = SemaphoreSlotSupplier::new(2);
        let dealer = ClosablePermitDealer::new(supplier);

        let _permit = dealer.acquire(&()).await.unwrap();
        assert_eq!(dealer.outstanding_count(), 1);

        dealer.close();
        assert!(dealer.is_closed());

        let result = dealer.acquire(&()).await;
        assert!(matches!(result, Err(QuotaError::Closed)));
    }

    #[tokio::test]
    async fn test_closable_permit_dealer_drain() {
        let supplier = SemaphoreSlotSupplier::new(2);
        let dealer = Arc::new(ClosablePermitDealer::new(supplier));

        let permit = dealer.acquire(&()).await.unwrap();
        assert_eq!(dealer.outstanding_count(), 1);

        dealer.close();

        let dealer_clone = Arc::clone(&dealer);
        let handle = tokio::spawn(async move {
            dealer_clone.drain_complete().await;
        });

        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(!handle.is_finished());

        permit.release();

        tokio::time::timeout(Duration::from_millis(100), handle)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(dealer.outstanding_count(), 0);
    }

    #[tokio::test]
    async fn test_closable_permit_dealer_drain_with_timeout() {
        let supplier = SemaphoreSlotSupplier::new(2);
        let dealer = ClosablePermitDealer::new(supplier);

        let _permit = dealer.acquire(&()).await.unwrap();
        dealer.close();

        let drained = dealer.drain_with_timeout(Duration::from_millis(10)).await;
        assert!(!drained);
    }

    #[tokio::test]
    async fn test_closable_permit_dealer_immediate_drain_when_empty() {
        let supplier = SemaphoreSlotSupplier::new(2);
        let dealer = ClosablePermitDealer::new(supplier);

        dealer.close();

        let drained = dealer.drain_with_timeout(Duration::from_millis(10)).await;
        assert!(drained);
    }

    #[tokio::test]
    async fn test_permit_drop_decrements_outstanding() {
        let supplier = SemaphoreSlotSupplier::new(2);
        let dealer = Arc::new(ClosablePermitDealer::new(supplier));

        {
            let _permit = dealer.acquire(&()).await.unwrap();
            assert_eq!(dealer.outstanding_count(), 1);
        }

        assert_eq!(dealer.outstanding_count(), 0);
    }

    #[tokio::test]
    async fn test_concurrent_close_and_acquire() {
        for _ in 0..100 {
            let supplier = SemaphoreSlotSupplier::new(10);
            let dealer = Arc::new(ClosablePermitDealer::new(supplier));

            let mut handles = Vec::new();
            for _ in 0..10 {
                let d = Arc::clone(&dealer);
                handles.push(tokio::spawn(async move {
                    let _ = d.acquire(&()).await;
                }));
            }

            dealer.close();
            dealer.drain_complete().await;

            for h in handles {
                let _ = h.await;
            }

            assert_eq!(dealer.outstanding_count(), 0);
        }
    }
}
