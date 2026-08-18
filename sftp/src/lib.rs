//! High-level SFTP operations for an authenticated `xssh-rust-core` session.

use std::fmt;

use russh_sftp::client::{fs, SftpSession};
use xssh_rust_core::{SshError, SshSession};

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

impl std::error::Error for SftpError {}

impl From<SshError> for SftpError {
    fn from(error: SshError) -> Self {
        Self::Core(error)
    }
}

impl From<russh_sftp::client::error::Error> for SftpError {
    fn from(error: russh_sftp::client::error::Error) -> Self {
        Self::Protocol(error.to_string())
    }
}

/// High-level SFTP client attached to an authenticated SSH session.
pub struct SftpClient {
    inner: SftpSession,
}

impl SftpClient {
    /// Open and initialize the SFTP subsystem on a new SSH channel.
    pub async fn connect(session: &SshSession) -> Result<Self, SftpError> {
        let channel = session.open_session_channel().await?;
        channel.request_subsystem(true, "sftp").await?;
        let inner = SftpSession::new(channel.into_stream()).await?;
        Ok(Self { inner })
    }

    pub async fn close(&self) -> Result<(), SftpError> {
        self.inner.close().await.map_err(Into::into)
    }

    pub async fn canonicalize(&self, path: impl Into<String>) -> Result<String, SftpError> {
        self.inner.canonicalize(path).await.map_err(Into::into)
    }

    pub async fn exists(&self, path: impl Into<String>) -> Result<bool, SftpError> {
        self.inner.try_exists(path).await.map_err(Into::into)
    }

    pub async fn read(&self, path: impl Into<String>) -> Result<Vec<u8>, SftpError> {
        self.inner.read(path).await.map_err(Into::into)
    }

    pub async fn write(&self, path: impl Into<String>, data: &[u8]) -> Result<(), SftpError> {
        self.inner.write(path, data).await.map_err(Into::into)
    }

    /// Open a remote file for streaming reads.
    pub async fn open(&self, path: impl Into<String>) -> Result<SftpFile, SftpError> {
        self.inner.open(path).await.map_err(Into::into)
    }

    /// Create or truncate a remote file for streaming writes.
    pub async fn create(&self, path: impl Into<String>) -> Result<SftpFile, SftpError> {
        self.inner.create(path).await.map_err(Into::into)
    }

    /// Open a remote file with explicit SFTP flags.
    pub async fn open_with_flags(
        &self,
        path: impl Into<String>,
        flags: OpenFlags,
    ) -> Result<SftpFile, SftpError> {
        self.inner
            .open_with_flags(path, flags)
            .await
            .map_err(Into::into)
    }

    pub async fn create_dir(&self, path: impl Into<String>) -> Result<(), SftpError> {
        self.inner.create_dir(path).await.map_err(Into::into)
    }

    pub async fn read_dir(
        &self,
        path: impl Into<String>,
    ) -> Result<Vec<RemoteDirEntry>, SftpError> {
        let entries = self.inner.read_dir(path).await.map_err(SftpError::from)?;
        Ok(entries
            .map(|entry| RemoteDirEntry {
                name: entry.file_name(),
                metadata: entry.metadata(),
            })
            .collect())
    }

    pub async fn metadata(&self, path: impl Into<String>) -> Result<Metadata, SftpError> {
        self.inner.metadata(path).await.map_err(Into::into)
    }

    pub async fn remove_file(&self, path: impl Into<String>) -> Result<(), SftpError> {
        self.inner.remove_file(path).await.map_err(Into::into)
    }

    pub async fn remove_dir(&self, path: impl Into<String>) -> Result<(), SftpError> {
        self.inner.remove_dir(path).await.map_err(Into::into)
    }

    pub async fn rename(
        &self,
        old_path: impl Into<String>,
        new_path: impl Into<String>,
    ) -> Result<(), SftpError> {
        self.inner
            .rename(old_path, new_path)
            .await
            .map_err(Into::into)
    }
}
