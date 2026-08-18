use std::fmt;
use std::sync::Arc;

use super::host_key::HostKeyObservation;

/// Broad phase in which an SSH operation failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ErrorKind {
    Configuration,
    Connection,
    Handshake,
    HostKey,
    Authentication,
    Channel,
    Protocol,
    Timeout,
    Cancelled,
    Internal,
}

/// Non-secret information attached to an SSH failure.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ErrorContext {
    operation: Option<String>,
    host: Option<String>,
    port: Option<u16>,
    path: Option<String>,
    host_key_observation: Option<HostKeyObservation>,
}

impl ErrorContext {
    pub fn operation(&self) -> Option<&str> {
        self.operation.as_deref()
    }

    pub fn host(&self) -> Option<&str> {
        self.host.as_deref()
    }

    pub fn port(&self) -> Option<u16> {
        self.port
    }

    pub fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }

    pub fn host_key_observation(&self) -> Option<&HostKeyObservation> {
        self.host_key_observation.as_ref()
    }
}

/// Error returned by the SSH core.
#[derive(Debug)]
pub struct SshError {
    kind: ErrorKind,
    message: String,
    context: Box<ErrorContext>,
    retryable: bool,
    source: Option<Arc<dyn std::error::Error + Send + Sync>>,
}

impl SshError {
    pub(crate) fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            context: Box::new(ErrorContext::default()),
            retryable: is_retryable_kind(kind),
            source: None,
        }
    }

    pub(crate) fn reclassify(mut self, kind: ErrorKind) -> Self {
        self.kind = kind;
        self.retryable = is_retryable_kind(kind);
        self
    }

    pub fn configuration(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Configuration, message)
    }

    pub(crate) fn host_key(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::HostKey, message)
    }

    pub(crate) fn authentication(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Authentication, message)
    }

    pub(crate) fn timeout(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Timeout, message)
    }

    pub(crate) fn cancelled(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Cancelled, message)
    }

    pub(crate) fn from_source<E>(kind: ErrorKind, message: impl Into<String>, source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        let mut error = Self::new(kind, message);
        error.source = Some(Arc::new(source));
        error
    }

    pub fn with_operation(mut self, operation: impl Into<String>) -> Self {
        self.context.operation = Some(operation.into());
        self
    }

    pub fn with_endpoint(mut self, host: impl Into<String>, port: u16) -> Self {
        self.context.host = Some(host.into());
        self.context.port = Some(port);
        self
    }

    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.context.path = Some(path.into());
        self
    }

    pub(crate) fn with_host_key_observation(mut self, observation: HostKeyObservation) -> Self {
        self.context.host_key_observation = Some(observation);
        self
    }

    pub fn with_retryable(mut self, retryable: bool) -> Self {
        self.retryable = retryable;
        self
    }

    /// Return the broad failure category for programmatic handling.
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// Return the human-readable detail without exposing any credentials.
    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn context(&self) -> &ErrorContext {
        &self.context
    }

    pub fn operation(&self) -> Option<&str> {
        self.context.operation()
    }

    pub fn host(&self) -> Option<&str> {
        self.context.host()
    }

    pub fn port(&self) -> Option<u16> {
        self.context.port()
    }

    pub fn path(&self) -> Option<&str> {
        self.context.path()
    }

    pub fn host_key_observation(&self) -> Option<&HostKeyObservation> {
        self.context.host_key_observation()
    }

    pub fn is_retryable(&self) -> bool {
        self.retryable
    }
}

fn is_retryable_kind(kind: ErrorKind) -> bool {
    matches!(
        kind,
        ErrorKind::Connection | ErrorKind::Handshake | ErrorKind::Channel | ErrorKind::Timeout
    )
}

impl Clone for SshError {
    fn clone(&self) -> Self {
        Self {
            kind: self.kind,
            message: self.message.clone(),
            context: self.context.clone(),
            retryable: self.retryable,
            source: self.source.clone(),
        }
    }
}

impl PartialEq for SshError {
    fn eq(&self, other: &Self) -> bool {
        self.kind == other.kind
            && self.message == other.message
            && self.context == other.context
            && self.retryable == other.retryable
    }
}

impl Eq for SshError {}

impl fmt::Display for SshError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.kind, self.message)?;
        if let Some(operation) = self.operation() {
            write!(f, " (operation: {operation})")?;
        }
        if let Some(host) = self.host() {
            write!(f, " [{host}:{}]", self.port().unwrap_or(22))?;
        }
        if let Some(path) = self.path() {
            write!(f, " [path: {path}]")?;
        }
        Ok(())
    }
}

impl std::error::Error for SshError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_deref()
            .map(|source| source as &(dyn std::error::Error + 'static))
    }
}

impl From<russh::Error> for SshError {
    fn from(error: russh::Error) -> Self {
        Self::from_source(ErrorKind::Internal, error.to_string(), error)
    }
}

impl From<russh::keys::ssh_key::Error> for SshError {
    fn from(error: russh::keys::ssh_key::Error) -> Self {
        Self::from_source(
            ErrorKind::Configuration,
            format!("invalid SSH key: {error}"),
            error,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{ErrorKind, SshError};

    #[test]
    fn error_keeps_its_phase() {
        let error = SshError::timeout("SSH handshake timed out");
        assert_eq!(error.kind(), ErrorKind::Timeout);
        assert_eq!(error.message(), "SSH handshake timed out");
        assert!(error.to_string().contains("Timeout"));
        assert!(error.is_retryable());
    }

    #[test]
    fn error_has_structured_context() {
        let error = SshError::timeout("operation deadline exceeded")
            .with_operation("ssh connect")
            .with_endpoint("example.com", 2222)
            .with_path("/tmp/a.txt");
        assert_eq!(error.operation(), Some("ssh connect"));
        assert_eq!(error.host(), Some("example.com"));
        assert_eq!(error.port(), Some(2222));
        assert_eq!(error.path(), Some("/tmp/a.txt"));
    }
}
