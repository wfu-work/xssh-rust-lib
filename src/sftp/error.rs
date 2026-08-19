use std::fmt;

use crate::core::{ErrorKind, SshError};

/// SFTP operation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SftpError {
    Core(SshError),
    Protocol(String),
}

impl fmt::Display for SftpError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Core(error) => write!(formatter, "SSH core: {error}"),
            Self::Protocol(message) => write!(formatter, "SFTP: {message}"),
        }
    }
}

impl std::error::Error for SftpError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Core(error) => Some(error),
            Self::Protocol(_) => None,
        }
    }
}

impl From<SshError> for SftpError {
    fn from(error: SshError) -> Self {
        Self::Core(error)
    }
}

impl From<russh_sftp::client::error::Error> for SftpError {
    fn from(error: russh_sftp::client::error::Error) -> Self {
        Self::Core(SshError::from_source(
            ErrorKind::Protocol,
            error.to_string(),
            error,
        ))
    }
}

impl SftpError {
    pub fn kind(&self) -> Option<ErrorKind> {
        match self {
            Self::Core(error) => Some(error.kind()),
            Self::Protocol(_) => None,
        }
    }

    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Core(error) => error.is_retryable(),
            Self::Protocol(_) => false,
        }
    }

    pub fn operation(&self) -> Option<&str> {
        match self {
            Self::Core(error) => error.operation(),
            Self::Protocol(_) => None,
        }
    }

    pub fn path(&self) -> Option<&str> {
        match self {
            Self::Core(error) => error.path(),
            Self::Protocol(_) => None,
        }
    }

    pub(crate) fn with_path(self, path: impl Into<String>) -> Self {
        match self {
            Self::Core(error) => Self::Core(error.with_path(path)),
            error => error,
        }
    }
}
