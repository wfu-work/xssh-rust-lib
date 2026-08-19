use crate::core::{OperationContext, SshSession};
use russh_sftp::client::{fs, SftpSession};

use super::{RemoteDirEntry, SftpError};

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
        self.run("close SFTP subsystem", async {
            self.inner.close().await.map_err(SftpError::from)
        })
        .await
    }

    pub async fn canonicalize(&self, path: impl Into<String>) -> Result<String, SftpError> {
        let path = path.into();
        self.run_path("canonicalize SFTP path", &path, async {
            self.inner
                .canonicalize(path.clone())
                .await
                .map_err(SftpError::from)
        })
        .await
    }

    pub async fn exists(&self, path: impl Into<String>) -> Result<bool, SftpError> {
        let path = path.into();
        self.run_path("check SFTP path existence", &path, async {
            self.inner
                .try_exists(path.clone())
                .await
                .map_err(SftpError::from)
        })
        .await
    }

    pub async fn read(&self, path: impl Into<String>) -> Result<Vec<u8>, SftpError> {
        let path = path.into();
        self.run_path("read SFTP file", &path, async {
            self.inner.read(path.clone()).await.map_err(SftpError::from)
        })
        .await
    }

    pub async fn write(&self, path: impl Into<String>, data: &[u8]) -> Result<(), SftpError> {
        let path = path.into();
        self.run_path("write SFTP file", &path, async {
            self.inner
                .write(path.clone(), data)
                .await
                .map_err(SftpError::from)
        })
        .await
    }

    /// Open a remote file for streaming reads.
    pub async fn open(&self, path: impl Into<String>) -> Result<fs::File, SftpError> {
        let path = path.into();
        self.run_path("open SFTP file", &path, async {
            self.inner.open(path.clone()).await.map_err(SftpError::from)
        })
        .await
    }

    /// Create or truncate a remote file for streaming writes.
    pub async fn create(&self, path: impl Into<String>) -> Result<fs::File, SftpError> {
        let path = path.into();
        self.run_path("create SFTP file", &path, async {
            self.inner
                .create(path.clone())
                .await
                .map_err(SftpError::from)
        })
        .await
    }

    /// Open a remote file with explicit SFTP flags.
    pub async fn open_with_flags(
        &self,
        path: impl Into<String>,
        flags: russh_sftp::protocol::OpenFlags,
    ) -> Result<fs::File, SftpError> {
        let path = path.into();
        self.run_path("open SFTP file with flags", &path, async {
            self.inner
                .open_with_flags(path.clone(), flags)
                .await
                .map_err(SftpError::from)
        })
        .await
    }

    pub async fn create_dir(&self, path: impl Into<String>) -> Result<(), SftpError> {
        let path = path.into();
        self.run_path("create SFTP directory", &path, async {
            self.inner
                .create_dir(path.clone())
                .await
                .map_err(SftpError::from)
        })
        .await
    }

    pub async fn read_dir(
        &self,
        path: impl Into<String>,
    ) -> Result<Vec<RemoteDirEntry>, SftpError> {
        let path = path.into();
        let entries = self
            .run_path("read SFTP directory", &path, async {
                self.inner
                    .read_dir(path.clone())
                    .await
                    .map_err(SftpError::from)
            })
            .await?;
        Ok(entries
            .map(|entry| RemoteDirEntry {
                name: entry.file_name(),
                metadata: entry.metadata(),
            })
            .collect())
    }

    pub async fn metadata(
        &self,
        path: impl Into<String>,
    ) -> Result<russh_sftp::client::fs::Metadata, SftpError> {
        let path = path.into();
        self.run_path("read SFTP metadata", &path, async {
            self.inner
                .metadata(path.clone())
                .await
                .map_err(SftpError::from)
        })
        .await
    }

    pub async fn remove_file(&self, path: impl Into<String>) -> Result<(), SftpError> {
        let path = path.into();
        self.run_path("remove SFTP file", &path, async {
            self.inner
                .remove_file(path.clone())
                .await
                .map_err(SftpError::from)
        })
        .await
    }

    pub async fn remove_dir(&self, path: impl Into<String>) -> Result<(), SftpError> {
        let path = path.into();
        self.run_path("remove SFTP directory", &path, async {
            self.inner
                .remove_dir(path.clone())
                .await
                .map_err(SftpError::from)
        })
        .await
    }

    pub async fn rename(
        &self,
        old_path: impl Into<String>,
        new_path: impl Into<String>,
    ) -> Result<(), SftpError> {
        let old_path = old_path.into();
        let new_path = new_path.into();
        let display_path = format!("{old_path} -> {new_path}");
        self.run_path("rename SFTP path", &display_path, async {
            self.inner
                .rename(old_path.clone(), new_path.clone())
                .await
                .map_err(SftpError::from)
        })
        .await
    }

    async fn run<T, F>(&self, operation: &'static str, future: F) -> Result<T, SftpError>
    where
        F: std::future::Future<Output = Result<T, SftpError>>,
    {
        self.context
            .clone()
            .with_timeout_from_now(self.operation_timeout)
            .run_with(operation, future)
            .await
    }

    async fn run_path<T, F>(
        &self,
        operation: &'static str,
        path: &str,
        future: F,
    ) -> Result<T, SftpError>
    where
        F: std::future::Future<Output = Result<T, SftpError>>,
    {
        self.run(operation, future)
            .await
            .map_err(|error| error.with_path(path.to_owned()))
    }
}
