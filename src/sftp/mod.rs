//! High-level SFTP operations for an authenticated `core::SshSession`.

use std::fmt;

use crate::core::{ErrorKind, OperationContext, SshError, SshSession};
use russh_sftp::client::{fs, SftpSession};

pub use fs::{File as SftpFile, Metadata};
pub use russh_sftp::protocol::OpenFlags;

/// A directory entry returned by [`SftpClient::read_dir`].
#[derive(Clone, Debug)]
pub struct RemoteDirEntry {
    pub name: String,
    pub metadata: Metadata,
}

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

    fn with_path(self, path: impl Into<String>) -> Self {
        match self {
            Self::Core(error) => Self::Core(error.with_path(path)),
            error => error,
        }
    }
}

/// High-level SFTP client attached to an authenticated SSH session.
pub struct SftpClient {
    inner: SftpSession,
    context: OperationContext,
    operation_timeout: std::time::Duration,
}

impl SftpClient {
    /// Open and initialize the SFTP subsystem on a new SSH channel.
    pub async fn connect(session: &SshSession) -> Result<Self, SftpError> {
        Self::connect_with_context(session, session.base_context()).await
    }

    pub async fn connect_with_context(
        session: &SshSession,
        context: OperationContext,
    ) -> Result<Self, SftpError> {
        let setup_context = context
            .clone()
            .with_timeout_from_now(session.config().operation_timeout);
        let channel = session
            .open_session_channel_with_context(context.clone())
            .await?;
        channel
            .request_subsystem_with_context(true, "sftp", &setup_context)
            .await?;
        let inner = setup_context
            .run_with("initialize SFTP subsystem", async {
                SftpSession::new(channel.into_stream())
                    .await
                    .map_err(SftpError::from)
            })
            .await?;
        Ok(Self {
            inner,
            context,
            operation_timeout: session.config().operation_timeout,
        })
    }

    pub fn with_context(mut self, context: OperationContext) -> Self {
        self.context = context;
        self
    }

    pub async fn close(&self) -> Result<(), SftpError> {
        self.context
            .clone()
            .with_timeout_from_now(self.operation_timeout)
            .run_with("close SFTP subsystem", async {
                self.inner.close().await.map_err(SftpError::from)
            })
            .await
    }

    pub async fn canonicalize(&self, path: impl Into<String>) -> Result<String, SftpError> {
        let path = path.into();
        self.context
            .clone()
            .with_timeout_from_now(self.operation_timeout)
            .run_with("canonicalize SFTP path", async {
                self.inner
                    .canonicalize(path.clone())
                    .await
                    .map_err(SftpError::from)
            })
            .await
            .map_err(|error| error.with_path(path))
    }

    pub async fn exists(&self, path: impl Into<String>) -> Result<bool, SftpError> {
        let path = path.into();
        self.context
            .clone()
            .with_timeout_from_now(self.operation_timeout)
            .run_with("check SFTP path existence", async {
                self.inner
                    .try_exists(path.clone())
                    .await
                    .map_err(SftpError::from)
            })
            .await
            .map_err(|error| error.with_path(path))
    }

    pub async fn read(&self, path: impl Into<String>) -> Result<Vec<u8>, SftpError> {
        let path = path.into();
        self.context
            .clone()
            .with_timeout_from_now(self.operation_timeout)
            .run_with("read SFTP file", async {
                self.inner.read(path.clone()).await.map_err(SftpError::from)
            })
            .await
            .map_err(|error| error.with_path(path))
    }

    pub async fn write(&self, path: impl Into<String>, data: &[u8]) -> Result<(), SftpError> {
        let path = path.into();
        self.context
            .clone()
            .with_timeout_from_now(self.operation_timeout)
            .run_with("write SFTP file", async {
                self.inner
                    .write(path.clone(), data)
                    .await
                    .map_err(SftpError::from)
            })
            .await
            .map_err(|error| error.with_path(path))
    }

    /// Open a remote file for streaming reads.
    pub async fn open(&self, path: impl Into<String>) -> Result<SftpFile, SftpError> {
        let path = path.into();
        self.context
            .clone()
            .with_timeout_from_now(self.operation_timeout)
            .run_with("open SFTP file", async {
                self.inner.open(path.clone()).await.map_err(SftpError::from)
            })
            .await
            .map_err(|error| error.with_path(path))
    }

    /// Create or truncate a remote file for streaming writes.
    pub async fn create(&self, path: impl Into<String>) -> Result<SftpFile, SftpError> {
        let path = path.into();
        self.context
            .clone()
            .with_timeout_from_now(self.operation_timeout)
            .run_with("create SFTP file", async {
                self.inner
                    .create(path.clone())
                    .await
                    .map_err(SftpError::from)
            })
            .await
            .map_err(|error| error.with_path(path))
    }

    /// Open a remote file with explicit SFTP flags.
    pub async fn open_with_flags(
        &self,
        path: impl Into<String>,
        flags: OpenFlags,
    ) -> Result<SftpFile, SftpError> {
        let path = path.into();
        self.context
            .clone()
            .with_timeout_from_now(self.operation_timeout)
            .run_with("open SFTP file with flags", async {
                self.inner
                    .open_with_flags(path.clone(), flags)
                    .await
                    .map_err(SftpError::from)
            })
            .await
            .map_err(|error| error.with_path(path))
    }

    pub async fn create_dir(&self, path: impl Into<String>) -> Result<(), SftpError> {
        let path = path.into();
        self.context
            .clone()
            .with_timeout_from_now(self.operation_timeout)
            .run_with("create SFTP directory", async {
                self.inner
                    .create_dir(path.clone())
                    .await
                    .map_err(SftpError::from)
            })
            .await
            .map_err(|error| error.with_path(path))
    }

    pub async fn read_dir(
        &self,
        path: impl Into<String>,
    ) -> Result<Vec<RemoteDirEntry>, SftpError> {
        let path = path.into();
        let entries = self
            .context
            .clone()
            .with_timeout_from_now(self.operation_timeout)
            .run_with("read SFTP directory", async {
                self.inner
                    .read_dir(path.clone())
                    .await
                    .map_err(SftpError::from)
            })
            .await
            .map_err(|error| error.with_path(path))?;
        Ok(entries
            .map(|entry| RemoteDirEntry {
                name: entry.file_name(),
                metadata: entry.metadata(),
            })
            .collect())
    }

    pub async fn metadata(&self, path: impl Into<String>) -> Result<Metadata, SftpError> {
        let path = path.into();
        self.context
            .clone()
            .with_timeout_from_now(self.operation_timeout)
            .run_with("read SFTP metadata", async {
                self.inner
                    .metadata(path.clone())
                    .await
                    .map_err(SftpError::from)
            })
            .await
            .map_err(|error| error.with_path(path))
    }

    pub async fn remove_file(&self, path: impl Into<String>) -> Result<(), SftpError> {
        let path = path.into();
        self.context
            .clone()
            .with_timeout_from_now(self.operation_timeout)
            .run_with("remove SFTP file", async {
                self.inner
                    .remove_file(path.clone())
                    .await
                    .map_err(SftpError::from)
            })
            .await
            .map_err(|error| error.with_path(path))
    }

    pub async fn remove_dir(&self, path: impl Into<String>) -> Result<(), SftpError> {
        let path = path.into();
        self.context
            .clone()
            .with_timeout_from_now(self.operation_timeout)
            .run_with("remove SFTP directory", async {
                self.inner
                    .remove_dir(path.clone())
                    .await
                    .map_err(SftpError::from)
            })
            .await
            .map_err(|error| error.with_path(path))
    }

    pub async fn rename(
        &self,
        old_path: impl Into<String>,
        new_path: impl Into<String>,
    ) -> Result<(), SftpError> {
        let old_path = old_path.into();
        let new_path = new_path.into();
        self.context
            .clone()
            .with_timeout_from_now(self.operation_timeout)
            .run_with("rename SFTP path", async {
                self.inner
                    .rename(old_path.clone(), new_path.clone())
                    .await
                    .map_err(SftpError::from)
            })
            .await
            .map_err(|error| error.with_path(format!("{old_path} -> {new_path}")))
    }
}
