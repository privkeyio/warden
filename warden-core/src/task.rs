#![forbid(unsafe_code)]

use parking_lot::Mutex;
use tokio::sync::Notify;
use tokio::task::JoinHandle;

use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::Error;

async fn wait_for_signal(flag: &AtomicBool, notify: &Notify) {
    loop {
        let mut notified = std::pin::pin!(notify.notified());
        notified.as_mut().enable();
        if flag.load(Ordering::Acquire) {
            return;
        }
        notified.await;
    }
}

#[derive(Clone)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
    notify: Arc<Notify>,
}

impl CancellationToken {
    pub fn new() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
            notify: Arc::new(Notify::new()),
        }
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        self.notify.notify_waiters();
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    pub async fn cancelled(&self) {
        wait_for_signal(&self.cancelled, &self.notify).await;
    }
}

impl Default for CancellationToken {
    fn default() -> Self {
        Self::new()
    }
}

pub struct TaskHandle {
    token: CancellationToken,
    done: Arc<AtomicBool>,
    done_notify: Arc<Notify>,
    error: Arc<Mutex<Option<Error>>>,
    join_handle: Mutex<Option<JoinHandle<()>>>,
}

impl TaskHandle {
    pub fn spawn<F, Fut>(f: F) -> Self
    where
        F: FnOnce(CancellationToken) -> Fut + Send + 'static,
        Fut: Future<Output = Result<(), Error>> + Send,
    {
        let token = CancellationToken::new();
        let done = Arc::new(AtomicBool::new(false));
        let done_notify = Arc::new(Notify::new());
        let error = Arc::new(Mutex::new(None));

        let task_token = token.clone();
        let task_done = Arc::clone(&done);
        let task_done_notify = Arc::clone(&done_notify);
        let task_error = Arc::clone(&error);

        let handle = tokio::spawn(async move {
            if let Err(e) = f(task_token).await {
                *task_error.lock() = Some(e);
            }
            task_done.store(true, Ordering::Release);
            task_done_notify.notify_waiters();
        });

        Self {
            token,
            done,
            done_notify,
            error,
            join_handle: Mutex::new(Some(handle)),
        }
    }

    pub fn cancel(&self) {
        self.token.cancel();
    }

    pub fn is_cancelled(&self) -> bool {
        self.token.is_cancelled()
    }

    pub fn is_done(&self) -> bool {
        self.done.load(Ordering::Acquire)
    }

    pub async fn done(&self) {
        wait_for_signal(&self.done, &self.done_notify).await;
    }

    pub async fn done_timeout(&self, timeout: std::time::Duration) -> Result<(), ()> {
        tokio::time::timeout(timeout, self.done())
            .await
            .map_err(|_| ())
    }

    pub fn error(&self) -> Option<Error> {
        self.error.lock().clone()
    }

    pub fn take_error(&self) -> Option<Error> {
        self.error.lock().take()
    }

    pub fn abort(&self) {
        if let Some(handle) = self.join_handle.lock().take() {
            self.done.store(true, Ordering::Release);
            self.done_notify.notify_waiters();
            handle.abort();
        }
    }
}

impl Drop for TaskHandle {
    fn drop(&mut self) {
        if let Some(handle) = self.join_handle.get_mut().take() {
            handle.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;

    #[tokio::test]
    async fn test_task_completes_successfully() {
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = Arc::clone(&counter);

        let handle = TaskHandle::spawn(move |_token| async move {
            counter_clone.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });

        handle.done().await;

        assert!(handle.is_done());
        assert!(handle.error().is_none());
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_task_returns_error() {
        let handle =
            TaskHandle::spawn(|_token| async move { Err(Error::Backend("task failed".into())) });

        handle.done().await;

        assert!(handle.is_done());
        let err = handle.error();
        assert!(err.is_some());
        assert!(err.unwrap().to_string().contains("task failed"));
    }

    #[tokio::test]
    async fn test_cancellation_token() {
        let cancelled_flag = Arc::new(AtomicBool::new(false));
        let flag_clone = Arc::clone(&cancelled_flag);

        let handle = TaskHandle::spawn(move |token| async move {
            token.cancelled().await;
            flag_clone.store(true, Ordering::SeqCst);
            Ok(())
        });

        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(!handle.is_done());

        handle.cancel();
        handle.done().await;

        assert!(handle.is_done());
        assert!(cancelled_flag.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn test_idempotent_cancel() {
        let handle = TaskHandle::spawn(|token| async move {
            token.cancelled().await;
            Ok(())
        });

        handle.cancel();
        handle.cancel();
        handle.cancel();

        assert!(handle.is_cancelled());
        handle.done().await;
        assert!(handle.is_done());
    }

    #[tokio::test]
    async fn test_cancel_before_spawn_check() {
        let token = CancellationToken::new();
        token.cancel();

        assert!(token.is_cancelled());

        let token_clone = token.clone();
        let result =
            tokio::time::timeout(Duration::from_millis(100), token_clone.cancelled()).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_take_error_clears_error() {
        let handle =
            TaskHandle::spawn(|_token| async move { Err(Error::Backend("take me".into())) });

        handle.done().await;

        let err1 = handle.take_error();
        assert!(err1.is_some());

        let err2 = handle.take_error();
        assert!(err2.is_none());
    }

    #[tokio::test]
    async fn test_abort_stops_task() {
        let started = Arc::new(AtomicBool::new(false));
        let started_clone = Arc::clone(&started);

        let handle = TaskHandle::spawn(move |_token| async move {
            started_clone.store(true, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_secs(60)).await;
            Ok(())
        });

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(started.load(Ordering::SeqCst));

        handle.abort();

        let result = tokio::time::timeout(Duration::from_millis(100), handle.done()).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_check_cancellation_in_loop() {
        let iterations = Arc::new(AtomicUsize::new(0));
        let iterations_clone = Arc::clone(&iterations);

        let handle = TaskHandle::spawn(move |token| async move {
            while !token.is_cancelled() {
                iterations_clone.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Ok(())
        });

        tokio::time::sleep(Duration::from_millis(50)).await;
        handle.cancel();
        handle.done().await;

        assert!(iterations.load(Ordering::SeqCst) > 0);
        assert!(handle.is_done());
    }

    #[tokio::test]
    async fn test_done_returns_immediately_if_already_done() {
        let handle = TaskHandle::spawn(|_token| async move { Ok(()) });

        handle.done().await;

        let result = tokio::time::timeout(Duration::from_millis(10), handle.done()).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_drop_aborts_task() {
        let started = Arc::new(AtomicBool::new(false));
        let completed = Arc::new(AtomicBool::new(false));
        let started_clone = Arc::clone(&started);
        let completed_clone = Arc::clone(&completed);

        {
            let _handle = TaskHandle::spawn(move |_token| async move {
                started_clone.store(true, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_secs(60)).await;
                completed_clone.store(true, Ordering::SeqCst);
                Ok(())
            });

            tokio::time::sleep(Duration::from_millis(50)).await;
            assert!(started.load(Ordering::SeqCst));
        }

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!completed.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn test_multiple_handles_independent() {
        let handle1 = TaskHandle::spawn(|_token| async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            Ok(())
        });

        let handle2 =
            TaskHandle::spawn(|_token| async move { Err(Error::Backend("h2 error".into())) });

        handle2.done().await;
        assert!(handle2.is_done());
        assert!(handle2.error().is_some());
        assert!(!handle1.is_done());

        handle1.done().await;
        assert!(handle1.is_done());
        assert!(handle1.error().is_none());
    }

    #[tokio::test]
    async fn test_done_timeout_success() {
        let handle = TaskHandle::spawn(|_token| async move { Ok(()) });

        let result = handle.done_timeout(Duration::from_secs(1)).await;
        assert!(result.is_ok());
        assert!(handle.is_done());
    }

    #[tokio::test]
    async fn test_done_timeout_expires() {
        let handle = TaskHandle::spawn(|_token| async move {
            tokio::time::sleep(Duration::from_secs(60)).await;
            Ok(())
        });

        let result = handle.done_timeout(Duration::from_millis(50)).await;
        assert!(result.is_err());
        assert!(!handle.is_done());
    }

    #[tokio::test]
    async fn test_abort_sets_done_before_abort() {
        let handle = TaskHandle::spawn(|_token| async move {
            tokio::time::sleep(Duration::from_secs(60)).await;
            Ok(())
        });

        tokio::time::sleep(Duration::from_millis(10)).await;
        handle.abort();
        assert!(handle.is_done());
    }
}
