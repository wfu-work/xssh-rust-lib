use std::fmt;

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
    Timeout,
    Cancelled,
    Internal,
}

/// Error returned by the SSH core.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SshError {
    kind: ErrorKind,
    message: String,
}

impl SshError {
    pub(crate) fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
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

    pub(crate) fn connection(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Connection, message)
    }

    pub(crate) fn handshake(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Handshake, message)
    }

    pub(crate) fn channel(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Channel, message)
    }

    pub(crate) fn timeout(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Timeout, message)
    }

    /// Return the broad failure category for programmatic handling.
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// Return the human-readable detail without exposing any credentials.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for SshError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.kind, self.message)
    }
}

impl std::error::Error for SshError {}

impl From<russh::Error> for SshError {
    fn from(error: russh::Error) -> Self {
        Self::new(ErrorKind::Internal, error.to_string())
    }
}

impl From<russh::keys::ssh_key::Error> for SshError {
    fn from(error: russh::keys::ssh_key::Error) -> Self {
        Self::configuration(format!("invalid SSH key: {error}"))
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
    }
}
