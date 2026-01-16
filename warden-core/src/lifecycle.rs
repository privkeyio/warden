#![forbid(unsafe_code)]

use async_trait::async_trait;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, warn};

use crate::Result;

#[async_trait]
pub trait LifecycleComponent: Send + Sync {
    fn name(&self) -> &str;
    async fn start(&self) -> Result<()>;
    async fn stop(&self) -> Result<()>;
    async fn drain(&self, timeout: Duration) -> Result<()>;
}

pub struct ServiceLifecycle {
    components: Vec<Arc<dyn LifecycleComponent>>,
    startup_order: Vec<usize>,
}

impl ServiceLifecycle {
    pub fn new() -> Self {
        Self {
            components: Vec::new(),
            startup_order: Vec::new(),
        }
    }

    pub fn register(&mut self, component: Arc<dyn LifecycleComponent>) -> usize {
        let idx = self.components.len();
        self.components.push(component);
        idx
    }

    pub async fn start(&mut self) -> Result<()> {
        for (idx, component) in self.components.iter().enumerate() {
            info!(component = component.name(), "Starting component");
            component.start().await?;
            self.startup_order.push(idx);
            info!(component = component.name(), "Component started");
        }
        Ok(())
    }

    pub async fn start_component(&mut self, idx: usize) -> Result<()> {
        if idx >= self.components.len() {
            return Err(crate::Error::InvalidInput(format!(
                "Component index {} out of bounds",
                idx
            )));
        }
        let component = &self.components[idx];
        info!(component = component.name(), "Starting component");
        component.start().await?;
        if !self.startup_order.contains(&idx) {
            self.startup_order.push(idx);
        }
        info!(component = component.name(), "Component started");
        Ok(())
    }

    pub async fn shutdown(&self, timeout: Duration) {
        let component_count = self.startup_order.len();
        if component_count == 0 {
            return;
        }

        let per_component_timeout = timeout / (component_count as u32 * 2);

        for idx in self.startup_order.iter().rev() {
            let component = &self.components[*idx];
            info!(component = component.name(), "Draining component");

            if let Err(e) = component.drain(per_component_timeout).await {
                warn!(
                    component = component.name(),
                    error = %e,
                    "Drain failed"
                );
            }

            info!(component = component.name(), "Stopping component");
            if let Err(e) = component.stop().await {
                error!(
                    component = component.name(),
                    error = %e,
                    "Stop failed"
                );
            }
        }

        info!("All components shut down");
    }

    pub async fn shutdown_with_force(&self, timeout: Duration) {
        if tokio::time::timeout(timeout, self.shutdown(timeout))
            .await
            .is_ok()
        {
            info!("Graceful shutdown completed");
        } else {
            warn!("Shutdown timeout exceeded, force stopping");
        }
    }

    pub fn component_count(&self) -> usize {
        self.components.len()
    }

    pub fn started_count(&self) -> usize {
        self.startup_order.len()
    }
}

impl Default for ServiceLifecycle {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    struct TestComponent {
        name: String,
        started: AtomicBool,
        stopped: AtomicBool,
        drained: AtomicBool,
        start_order: AtomicUsize,
        stop_order: AtomicUsize,
        counter: Arc<AtomicUsize>,
    }

    impl TestComponent {
        fn new(name: &str, counter: Arc<AtomicUsize>) -> Self {
            Self {
                name: name.to_string(),
                started: AtomicBool::new(false),
                stopped: AtomicBool::new(false),
                drained: AtomicBool::new(false),
                start_order: AtomicUsize::new(0),
                stop_order: AtomicUsize::new(0),
                counter,
            }
        }
    }

    #[async_trait]
    impl LifecycleComponent for TestComponent {
        fn name(&self) -> &str {
            &self.name
        }

        async fn start(&self) -> Result<()> {
            self.start_order.store(
                self.counter.fetch_add(1, Ordering::SeqCst),
                Ordering::SeqCst,
            );
            self.started.store(true, Ordering::SeqCst);
            Ok(())
        }

        async fn stop(&self) -> Result<()> {
            self.stop_order.store(
                self.counter.fetch_add(1, Ordering::SeqCst),
                Ordering::SeqCst,
            );
            self.stopped.store(true, Ordering::SeqCst);
            Ok(())
        }

        async fn drain(&self, _timeout: Duration) -> Result<()> {
            self.drained.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_lifecycle_start_and_shutdown() {
        let counter = Arc::new(AtomicUsize::new(0));
        let c1 = Arc::new(TestComponent::new("component1", Arc::clone(&counter)));
        let c2 = Arc::new(TestComponent::new("component2", Arc::clone(&counter)));
        let c3 = Arc::new(TestComponent::new("component3", Arc::clone(&counter)));

        let mut lifecycle = ServiceLifecycle::new();
        lifecycle.register(Arc::clone(&c1) as Arc<dyn LifecycleComponent>);
        lifecycle.register(Arc::clone(&c2) as Arc<dyn LifecycleComponent>);
        lifecycle.register(Arc::clone(&c3) as Arc<dyn LifecycleComponent>);

        lifecycle.start().await.unwrap();

        assert!(c1.started.load(Ordering::SeqCst));
        assert!(c2.started.load(Ordering::SeqCst));
        assert!(c3.started.load(Ordering::SeqCst));

        assert_eq!(c1.start_order.load(Ordering::SeqCst), 0);
        assert_eq!(c2.start_order.load(Ordering::SeqCst), 1);
        assert_eq!(c3.start_order.load(Ordering::SeqCst), 2);

        lifecycle.shutdown(Duration::from_secs(5)).await;

        assert!(c1.drained.load(Ordering::SeqCst));
        assert!(c2.drained.load(Ordering::SeqCst));
        assert!(c3.drained.load(Ordering::SeqCst));

        assert!(c1.stopped.load(Ordering::SeqCst));
        assert!(c2.stopped.load(Ordering::SeqCst));
        assert!(c3.stopped.load(Ordering::SeqCst));

        assert!(c3.stop_order.load(Ordering::SeqCst) < c2.stop_order.load(Ordering::SeqCst));
        assert!(c2.stop_order.load(Ordering::SeqCst) < c1.stop_order.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn test_empty_lifecycle() {
        let lifecycle = ServiceLifecycle::new();
        lifecycle.shutdown(Duration::from_secs(1)).await;
        assert_eq!(lifecycle.component_count(), 0);
    }
}
