#![forbid(unsafe_code)]

use parking_lot::Mutex;
use tokio::sync::Notify;
use tokio::task::JoinHandle;

use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::Error;

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
        loop {
            let mut notified = std::pin::pin!(self.notify.notified());
            notified.as_mut().enable();
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

pub struct TaskHandle {
    cancelled: Arc<AtomicBool>,
    cancel_notify: Arc<Notify>,
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
        let cancelled = Arc::new(AtomicBool::new(false));
        let cancel_notify = Arc::new(Notify::new());
        let done = Arc::new(AtomicBool::new(false));
        let done_notify = Arc::new(Notify::new());
        let error = Arc::new(Mutex::new(None));

        let token = CancellationToken {
            cancelled: Arc::clone(&cancelled),
            notify: Arc::clone(&cancel_notify),
        };

        let done_clone = Arc::clone(&done);
        let done_notify_clone = Arc::clone(&done_notify);
        let error_clone = Arc::clone(&error);

        let handle = tokio::spawn(async move {
            let result = f(token).await;
            if let Err(e) = result {
                *error_clone.lock() = Some(e);
            }
            done_clone.store(true, Ordering::Release);
            done_notify_clone.notify_waiters();
        });

        Self {
            cancelled,
            cancel_notify,
            done,
            done_notify,
            error,
            join_handle: Mutex::new(Some(handle)),
        }
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        self.cancel_notify.notify_waiters();
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    pub fn is_done(&self) -> bool {
        self.done.load(Ordering::Acquire)
    }

    pub async fn done(&self) {
        loop {
            let mut notified = std::pin::pin!(self.done_notify.notified());
            notified.as_mut().enable();
            if self.is_done() {
                return;
            }
            notified.await;
        }
    }

    pub fn error(&self) -> Option<Error> {
        self.error.lock().clone()
    }

    pub fn take_error(&self) -> Option<Error> {
        self.error.lock().take()
    }

    pub fn abort(&self) {
        if let Some(handle) = self.join_handle.lock().take() {
            handle.abort();
            self.done.store(true, Ordering::Release);
            self.done_notify.notify_waiters();
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
}
