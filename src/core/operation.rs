use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Notify;

use super::error::SshError;

#[derive(Debug)]
struct CancellationState {
    cancelled: AtomicBool,
    notify: Notify,
}

/// A cheap, cloneable cancellation signal shared by SSH operations.
#[derive(Clone, Debug)]
pub struct CancellationToken {
    state: Arc<CancellationState>,
}

impl Default for CancellationToken {
    fn default() -> Self {
        Self::new()
    }
}

impl CancellationToken {
    pub fn new() -> Self {
        Self {
            state: Arc::new(CancellationState {
                cancelled: AtomicBool::new(false),
                notify: Notify::new(),
            }),
        }
    }

    /// Signal cancellation. Calling this method more than once is harmless.
    pub fn cancel(&self) {
        if !self.state.cancelled.swap(true, Ordering::SeqCst) {
            self.state.notify.notify_waiters();
        }
    }

    pub fn is_cancelled(&self) -> bool {
        self.state.cancelled.load(Ordering::SeqCst)
    }

    /// Wait until [`CancellationToken::cancel`] is called.
    pub async fn cancelled(&self) {
        if self.is_cancelled() {
            return;
        }

        loop {
            let notified = self.state.notify.notified();
            if self.is_cancelled() {
                return;
            }
            notified.await;
        }
    }
}

/// Per-operation deadline and cancellation policy.
///
/// Contexts are intentionally independent from a session so a UI can cancel
/// one terminal or SFTP request without tearing down the whole SSH session.
#[derive(Clone, Debug)]
pub struct OperationContext {
    deadline: Option<Instant>,
    cancellation: CancellationToken,
}

impl Default for OperationContext {
    fn default() -> Self {
        Self::new()
    }
}

impl OperationContext {
    pub fn new() -> Self {
        Self {
            deadline: None,
            cancellation: CancellationToken::new(),
        }
    }

    pub fn with_timeout(timeout: Duration) -> Self {
        Self::new().with_timeout_from_now(timeout)
    }

    pub fn with_deadline(deadline: Instant) -> Self {
        Self {
            deadline: Some(deadline),
            cancellation: CancellationToken::new(),
        }
    }

    pub fn with_cancellation(mut self, cancellation: CancellationToken) -> Self {
        self.cancellation = cancellation;
        self
    }

    /// Add a timeout without extending an already earlier deadline.
    pub fn with_timeout_from_now(mut self, timeout: Duration) -> Self {
        let deadline = Instant::now() + timeout;
        self.deadline = match self.deadline {
            Some(existing) => Some(existing.min(deadline)),
            None => Some(deadline),
        };
        self
    }

    pub fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    pub fn cancellation_token(&self) -> CancellationToken {
        self.cancellation.clone()
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }

    /// Run a fallible async operation with this context's deadline and cancel
    /// signal. The operation future is dropped when either condition wins.
    pub async fn run<T, F>(&self, operation: impl Into<String>, future: F) -> Result<T, SshError>
    where
        F: Future<Output = Result<T, SshError>>,
    {
        let operation = operation.into();
        if self.is_cancelled() {
            return Err(
                SshError::cancelled(format!("{operation} was cancelled")).with_operation(operation)
            );
        }

        let result = match self.deadline {
            Some(deadline) => {
                let timeout = deadline.saturating_duration_since(Instant::now());
                tokio::select! {
                    _ = self.cancellation.cancelled() => {
                        return Err(SshError::cancelled(format!("{operation} was cancelled"))
                            .with_operation(operation.clone()));
                    }
                    result = tokio::time::timeout(timeout, future) => {
                        result.map_err(|_| SshError::timeout(format!(
                            "{operation} timed out after the operation deadline"
                        )).with_operation(operation.clone()))?
                    }
                }
            }
            None => {
                tokio::select! {
                    _ = self.cancellation.cancelled() => {
                        return Err(SshError::cancelled(format!("{operation} was cancelled"))
                            .with_operation(operation.clone()));
                    }
                    result = future => result,
                }
            }
        };

        result.map_err(|error| error.with_operation(operation))
    }

    pub async fn run_with_timeout<T, F>(
        &self,
        operation: impl Into<String>,
        timeout: Duration,
        future: F,
    ) -> Result<T, SshError>
    where
        F: Future<Output = Result<T, SshError>>,
    {
        self.clone()
            .with_timeout_from_now(timeout)
            .run(operation, future)
            .await
    }

    /// Variant of [`OperationContext::run`] for frontends with their own
    /// error type. Timeout and cancellation errors are converted through
    /// `From<SshError>` while protocol errors remain untouched.
    pub async fn run_with<T, E, F>(&self, operation: impl Into<String>, future: F) -> Result<T, E>
    where
        E: From<SshError>,
        F: Future<Output = Result<T, E>>,
    {
        let operation = operation.into();
        if self.is_cancelled() {
            return Err(SshError::cancelled(format!("{operation} was cancelled"))
                .with_operation(operation)
                .into());
        }

        match self.deadline {
            Some(deadline) => {
                let timeout = deadline.saturating_duration_since(Instant::now());
                tokio::select! {
                    _ = self.cancellation.cancelled() => Err(
                        SshError::cancelled(format!("{operation} was cancelled"))
                            .with_operation(operation.clone())
                            .into()
                    ),
                    result = tokio::time::timeout(timeout, future) => result
                        .map_err(|_| E::from(SshError::timeout(format!(
                            "{operation} timed out after the operation deadline"
                        )).with_operation(operation)))?,
                }
            }
            None => {
                tokio::select! {
                    _ = self.cancellation.cancelled() => Err(
                        SshError::cancelled(format!("{operation} was cancelled"))
                            .with_operation(operation)
                            .into()
                    ),
                    result = future => result,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{CancellationToken, OperationContext};
    use crate::ErrorKind;

    #[tokio::test]
    async fn cancellation_interrupts_an_operation() {
        let token = CancellationToken::new();
        let context = OperationContext::new().with_cancellation(token.clone());
        let task = tokio::spawn(async move {
            context
                .run("test operation", async {
                    tokio::time::sleep(Duration::from_secs(60)).await;
                    Ok::<_, crate::SshError>(())
                })
                .await
        });

        token.cancel();
        let error = task.await.unwrap().unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Cancelled);
        assert_eq!(error.operation(), Some("test operation"));
    }

    #[tokio::test]
    async fn deadline_interrupts_an_operation() {
        let context = OperationContext::with_timeout(Duration::from_millis(1));
        let error = context
            .run("test operation", async {
                tokio::time::sleep(Duration::from_secs(60)).await;
                Ok::<_, crate::SshError>(())
            })
            .await
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Timeout);
        assert!(error.is_retryable());
    }
}
