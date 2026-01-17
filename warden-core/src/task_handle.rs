#![forbid(unsafe_code)]

use parking_lot::Mutex;
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::Notify;
use tokio::task::JoinHandle;

use crate::Error;

pub struct CancellationToken {
    cancelled: AtomicBool,
    notify: Notify,
}

impl CancellationToken {
    pub fn new() -> Self {
        Self {
            cancelled: AtomicBool::new(false),
            notify: Notify::new(),
        }
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    pub async fn cancelled(&self) {
        loop {
            let notified = self.notify.notified();
            if self.is_cancelled() {
                return;
            }
            notified.await;
        }
    }
}

impl Default for CancellationToken {
    fn default() -> Self {
        Self::new()
    }
}

pub struct TaskHandle<E = Error> {
    cancel_token: Arc<CancellationToken>,
    done: Arc<AtomicBool>,
    done_notify: Arc<Notify>,
    error: Arc<Mutex<Option<E>>>,
    join_handle: Mutex<Option<JoinHandle<()>>>,
}

impl<E: Send + 'static> TaskHandle<E> {
    pub fn spawn<F, Fut>(f: F) -> Self
    where
        F: FnOnce(Arc<CancellationToken>) -> Fut + Send + 'static,
        Fut: Future<Output = Result<(), E>> + Send,
    {
        let cancel_token = Arc::new(CancellationToken::new());
        let done = Arc::new(AtomicBool::new(false));
        let done_notify = Arc::new(Notify::new());
        let error: Arc<Mutex<Option<E>>> = Arc::new(Mutex::new(None));

        let token_clone = Arc::clone(&cancel_token);
        let done_clone = Arc::clone(&done);
        let done_notify_clone = Arc::clone(&done_notify);
        let error_clone = Arc::clone(&error);

        let handle = tokio::spawn(async move {
            tokio::select! {
                biased;
                _ = token_clone.cancelled() => {}
                result = f(Arc::clone(&token_clone)) => {
                    if let Err(e) = result {
                        *error_clone.lock() = Some(e);
                    }
                }
            }
            done_clone.store(true, Ordering::SeqCst);
            done_notify_clone.notify_waiters();
        });

        Self {
            cancel_token,
            done,
            done_notify,
            error,
            join_handle: Mutex::new(Some(handle)),
        }
    }

    pub fn cancel(&self) {
        self.cancel_token.cancel();
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancel_token.is_cancelled()
    }

    pub fn is_done(&self) -> bool {
        self.done.load(Ordering::SeqCst)
    }

    pub async fn done(&self) {
        loop {
            let notified = self.done_notify.notified();
            if self.is_done() {
                return;
            }
            notified.await;
        }
    }

    pub async fn cancel_and_wait(&self) {
        self.cancel();
        self.done().await;
    }

    pub fn error(&self) -> Option<E>
    where
        E: Clone,
    {
        self.error.lock().clone()
    }

    pub fn take_error(&self) -> Option<E> {
        self.error.lock().take()
    }

    pub fn token(&self) -> Arc<CancellationToken> {
        Arc::clone(&self.cancel_token)
    }

    pub async fn join(self) -> Result<(), E>
    where
        E: Clone,
    {
        self.done().await;
        let handle = self.join_handle.lock().take();
        if let Some(h) = handle {
            let _ = h.await;
        }
        match self.take_error() {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

impl<E> Drop for TaskHandle<E> {
    fn drop(&mut self) {
        self.cancel_token.cancel();
    }
}

pub struct TaskGroup<E = Error> {
    handles: Mutex<Vec<TaskHandle<E>>>,
}

impl<E: Send + Clone + 'static> TaskGroup<E> {
    pub fn new() -> Self {
        Self {
            handles: Mutex::new(Vec::new()),
        }
    }

    pub fn spawn<F, Fut>(&self, f: F)
    where
        F: FnOnce(Arc<CancellationToken>) -> Fut + Send + 'static,
        Fut: Future<Output = Result<(), E>> + Send,
    {
        let handle = TaskHandle::spawn(f);
        self.handles.lock().push(handle);
    }

    pub fn cancel_all(&self) {
        for handle in self.handles.lock().iter() {
            handle.cancel();
        }
    }

    pub async fn wait_all(&self) {
        loop {
            let pending: Vec<(Arc<AtomicBool>, Arc<Notify>)> = {
                let handles = self.handles.lock();
                handles
                    .iter()
                    .filter(|h| !h.is_done())
                    .map(|h| (Arc::clone(&h.done), Arc::clone(&h.done_notify)))
                    .collect()
            };
            if pending.is_empty() {
                return;
            }
            for (done, notify) in pending {
                if !done.load(Ordering::SeqCst) {
                    notify.notified().await;
                }
            }
        }
    }

    pub async fn cancel_and_wait(&self) {
        self.cancel_all();
        self.wait_all().await;
    }

    pub fn active_count(&self) -> usize {
        self.handles.lock().iter().filter(|h| !h.is_done()).count()
    }

    pub fn collect_errors(&self) -> Vec<E> {
        self.handles
            .lock()
            .iter()
            .filter_map(|h| h.error())
            .collect()
    }
}

impl<E: Send + Clone + 'static> Default for TaskGroup<E> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU32;
    use std::time::Duration;

    #[derive(Debug, Clone)]
    struct TestError(String);

    #[tokio::test]
    async fn test_task_handle_completes_successfully() {
        let counter = Arc::new(AtomicU32::new(0));
        let counter_clone = Arc::clone(&counter);

        let handle: TaskHandle<TestError> = TaskHandle::spawn(move |_token| async move {
            counter_clone.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });

        handle.done().await;
        assert!(handle.is_done());
        assert!(handle.error().is_none());
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_task_handle_captures_error() {
        let handle: TaskHandle<TestError> =
            TaskHandle::spawn(|_token| async { Err(TestError("task failed".into())) });

        handle.done().await;
        assert!(handle.is_done());

        let error = handle.error();
        assert!(error.is_some());
        assert_eq!(error.unwrap().0, "task failed");
    }

    #[tokio::test]
    async fn test_task_handle_cancellation() {
        let started = Arc::new(AtomicBool::new(false));
        let started_clone = Arc::clone(&started);
        let completed = Arc::new(AtomicBool::new(false));
        let completed_clone = Arc::clone(&completed);

        let handle: TaskHandle<TestError> = TaskHandle::spawn(move |token| async move {
            started_clone.store(true, Ordering::SeqCst);

            loop {
                if token.is_cancelled() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }

            completed_clone.store(true, Ordering::SeqCst);
            Ok(())
        });

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(started.load(Ordering::SeqCst));

        handle.cancel_and_wait().await;
        assert!(handle.is_done());
        assert!(handle.is_cancelled());
    }

    #[tokio::test]
    async fn test_task_handle_cancel_is_idempotent() {
        let handle: TaskHandle<TestError> = TaskHandle::spawn(|token| async move {
            token.cancelled().await;
            Ok(())
        });

        handle.cancel();
        handle.cancel();
        handle.cancel();

        handle.done().await;
        assert!(handle.is_done());
    }

    #[tokio::test]
    async fn test_cancellation_token() {
        let token = CancellationToken::new();
        assert!(!token.is_cancelled());

        token.cancel();
        assert!(token.is_cancelled());

        token.cancelled().await;
    }

    #[tokio::test]
    async fn test_task_group() {
        let counter = Arc::new(AtomicU32::new(0));
        let group: TaskGroup<TestError> = TaskGroup::new();

        for _ in 0..5 {
            let counter_clone = Arc::clone(&counter);
            group.spawn(move |_token| async move {
                counter_clone.fetch_add(1, Ordering::SeqCst);
                Ok(())
            });
        }

        group.wait_all().await;
        assert_eq!(counter.load(Ordering::SeqCst), 5);
    }

    #[tokio::test]
    async fn test_task_group_cancel_all() {
        let group: TaskGroup<TestError> = TaskGroup::new();
        let started_count = Arc::new(AtomicU32::new(0));

        for _ in 0..3 {
            let started = Arc::clone(&started_count);
            group.spawn(move |token| async move {
                started.fetch_add(1, Ordering::SeqCst);
                loop {
                    if token.is_cancelled() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Ok(())
            });
        }

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(started_count.load(Ordering::SeqCst), 3);

        group.cancel_and_wait().await;
    }

    #[tokio::test]
    async fn test_task_group_collect_errors() {
        let group: TaskGroup<TestError> = TaskGroup::new();

        group.spawn(|_| async { Ok(()) });
        group.spawn(|_| async { Err(TestError("error 1".into())) });
        group.spawn(|_| async { Ok(()) });
        group.spawn(|_| async { Err(TestError("error 2".into())) });

        group.wait_all().await;

        let errors = group.collect_errors();
        assert_eq!(errors.len(), 2);
    }

    #[tokio::test]
    async fn test_task_handle_join() {
        let handle: TaskHandle<TestError> = TaskHandle::spawn(|_| async { Ok(()) });
        let result = handle.join().await;
        assert!(result.is_ok());

        let handle: TaskHandle<TestError> =
            TaskHandle::spawn(|_| async { Err(TestError("join error".into())) });
        let result = handle.join().await;
        assert!(result.is_err());
    }
}
