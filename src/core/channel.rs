use std::pin::Pin;

use russh::ChannelMsg;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::{OperationContext, SshError, SshSession};

/// Events received from an opened SSH channel.
#[derive(Debug, PartialEq, Eq)]
pub enum SshChannelEvent {
    Data(Vec<u8>),
    ExtendedData {
        ext: u32,
        data: Vec<u8>,
    },
    Eof,
    Close,
    ExitStatus(u32),
    ExitSignal {
        signal: String,
        core_dumped: bool,
        error_message: String,
        language_tag: String,
    },
    Success,
    Failure,
    OpenFailure(String),
}

/// A generic SSH session channel.
///
/// The core exposes protocol-safe channel primitives. Higher-level crates use
/// this type to implement terminal and SFTP semantics without accessing the
/// underlying `russh` client handle.
pub struct SshChannel {
    inner: russh::Channel<russh::client::Msg>,
    context: OperationContext,
    operation_timeout: std::time::Duration,
}

impl SshSession {
    /// Open a generic SSH session channel after authentication.
    pub async fn open_session_channel(&self) -> Result<SshChannel, SshError> {
        self.open_session_channel_with_context(self.base_context())
            .await
    }

    /// Open a channel with a caller-owned deadline or cancellation signal.
    pub async fn open_session_channel_with_context(
        &self,
        context: OperationContext,
    ) -> Result<SshChannel, SshError> {
        self.open_raw_session_channel_with_context(&context)
            .await
            .map(|inner| SshChannel {
                inner,
                context,
                operation_timeout: self.config().operation_timeout,
            })
    }
}

impl SshChannel {
    /// Replace the default context used by operations on this channel.
    pub fn with_context(mut self, context: OperationContext) -> Self {
        self.context = context;
        self
    }

    /// Request a remote pseudo-terminal.
    #[allow(clippy::too_many_arguments)]
    pub async fn request_pty(
        &self,
        want_reply: bool,
        term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        terminal_modes: &[(russh::Pty, u32)],
    ) -> Result<(), SshError> {
        let context = self
            .context
            .clone()
            .with_timeout_from_now(self.operation_timeout);
        self.request_pty_with_context(
            want_reply,
            term,
            col_width,
            row_height,
            pix_width,
            pix_height,
            terminal_modes,
            &context,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn request_pty_with_context(
        &self,
        want_reply: bool,
        term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        terminal_modes: &[(russh::Pty, u32)],
        context: &OperationContext,
    ) -> Result<(), SshError> {
        context
            .run("request remote PTY", async {
                self.inner
                    .request_pty(
                        want_reply,
                        term,
                        col_width,
                        row_height,
                        pix_width,
                        pix_height,
                        terminal_modes,
                    )
                    .await
                    .map_err(|error| {
                        SshError::from_source(crate::ErrorKind::Channel, error.to_string(), error)
                    })
            })
            .await
    }

    /// Request a remote login shell.
    pub async fn request_shell(&self, want_reply: bool) -> Result<(), SshError> {
        let context = self
            .context
            .clone()
            .with_timeout_from_now(self.operation_timeout);
        self.request_shell_with_context(want_reply, &context).await
    }

    pub async fn request_shell_with_context(
        &self,
        want_reply: bool,
        context: &OperationContext,
    ) -> Result<(), SshError> {
        context
            .run("request remote shell", async {
                self.inner.request_shell(want_reply).await.map_err(|error| {
                    SshError::from_source(crate::ErrorKind::Channel, error.to_string(), error)
                })
            })
            .await
    }

    /// Execute a command in this channel.
    pub async fn exec(
        &self,
        want_reply: bool,
        command: impl Into<Vec<u8>>,
    ) -> Result<(), SshError> {
        let context = self
            .context
            .clone()
            .with_timeout_from_now(self.operation_timeout);
        self.exec_with_context(want_reply, command, &context).await
    }

    pub async fn exec_with_context(
        &self,
        want_reply: bool,
        command: impl Into<Vec<u8>>,
        context: &OperationContext,
    ) -> Result<(), SshError> {
        let command = command.into();
        context
            .run("execute SSH command", async {
                self.inner.exec(want_reply, command).await.map_err(|error| {
                    SshError::from_source(crate::ErrorKind::Channel, error.to_string(), error)
                })
            })
            .await
    }

    /// Request an SSH subsystem such as `sftp`.
    pub async fn request_subsystem(
        &self,
        want_reply: bool,
        name: impl Into<String>,
    ) -> Result<(), SshError> {
        let context = self
            .context
            .clone()
            .with_timeout_from_now(self.operation_timeout);
        self.request_subsystem_with_context(want_reply, name, &context)
            .await
    }

    pub async fn request_subsystem_with_context(
        &self,
        want_reply: bool,
        name: impl Into<String>,
        context: &OperationContext,
    ) -> Result<(), SshError> {
        let name = name.into();
        context
            .run("request SSH subsystem", async {
                self.inner
                    .request_subsystem(want_reply, name)
                    .await
                    .map_err(|error| {
                        SshError::from_source(crate::ErrorKind::Channel, error.to_string(), error)
                    })
            })
            .await
    }

    /// Send bytes to the remote channel.
    pub async fn write(&self, data: &[u8]) -> Result<(), SshError> {
        let context = self
            .context
            .clone()
            .with_timeout_from_now(self.operation_timeout);
        self.write_with_context(data, &context).await
    }

    pub async fn write_with_context(
        &self,
        data: &[u8],
        context: &OperationContext,
    ) -> Result<(), SshError> {
        context
            .run("write SSH channel data", async {
                self.inner.data(data).await.map_err(|error| {
                    SshError::from_source(crate::ErrorKind::Channel, error.to_string(), error)
                })
            })
            .await
    }

    /// Send an EOF marker to the remote channel.
    pub async fn eof(&self) -> Result<(), SshError> {
        let context = self
            .context
            .clone()
            .with_timeout_from_now(self.operation_timeout);
        self.eof_with_context(&context).await
    }

    pub async fn eof_with_context(&self, context: &OperationContext) -> Result<(), SshError> {
        context
            .run("send SSH channel EOF", async {
                self.inner.eof().await.map_err(|error| {
                    SshError::from_source(crate::ErrorKind::Channel, error.to_string(), error)
                })
            })
            .await
    }

    /// Notify the remote PTY about a window resize.
    pub async fn window_change(&self, col_width: u32, row_height: u32) -> Result<(), SshError> {
        let context = self
            .context
            .clone()
            .with_timeout_from_now(self.operation_timeout);
        self.window_change_with_context(col_width, row_height, &context)
            .await
    }

    pub async fn window_change_with_context(
        &self,
        col_width: u32,
        row_height: u32,
        context: &OperationContext,
    ) -> Result<(), SshError> {
        context
            .run("resize remote PTY", async {
                self.inner
                    .window_change(col_width, row_height, 0, 0)
                    .await
                    .map_err(|error| {
                        SshError::from_source(crate::ErrorKind::Channel, error.to_string(), error)
                    })
            })
            .await
    }

    /// Close the channel.
    pub async fn close(&self) -> Result<(), SshError> {
        let context = self
            .context
            .clone()
            .with_timeout_from_now(self.operation_timeout);
        self.close_with_context(&context).await
    }

    pub async fn close_with_context(&self, context: &OperationContext) -> Result<(), SshError> {
        context
            .run("close SSH channel", async {
                self.inner.close().await.map_err(|error| {
                    SshError::from_source(crate::ErrorKind::Channel, error.to_string(), error)
                })
            })
            .await
    }

    /// Wait for the next protocol event.
    pub async fn next_event(&mut self) -> Option<SshChannelEvent> {
        let context = self
            .context
            .clone()
            .with_timeout_from_now(self.operation_timeout);
        self.next_event_with_context(&context).await.ok().flatten()
    }

    pub async fn next_event_with_context(
        &mut self,
        context: &OperationContext,
    ) -> Result<Option<SshChannelEvent>, SshError> {
        context
            .run("wait for SSH channel event", async {
                Ok(self.inner.wait().await.map(channel_event))
            })
            .await
    }

    /// Convert the channel into an asynchronous byte stream.
    pub fn into_stream(self) -> SshChannelStream {
        SshChannelStream {
            inner: self.inner.into_stream(),
            context: self.context,
            operation_timeout: self.operation_timeout,
        }
    }
}

fn channel_event(message: ChannelMsg) -> SshChannelEvent {
    match message {
        ChannelMsg::Data { data } => SshChannelEvent::Data(data.to_vec()),
        ChannelMsg::ExtendedData { data, ext } => SshChannelEvent::ExtendedData {
            ext,
            data: data.to_vec(),
        },
        ChannelMsg::Eof => SshChannelEvent::Eof,
        ChannelMsg::Close => SshChannelEvent::Close,
        ChannelMsg::ExitStatus { exit_status } => SshChannelEvent::ExitStatus(exit_status),
        ChannelMsg::ExitSignal {
            signal_name,
            core_dumped,
            error_message,
            lang_tag,
        } => SshChannelEvent::ExitSignal {
            signal: format!("{signal_name:?}"),
            core_dumped,
            error_message,
            language_tag: lang_tag,
        },
        ChannelMsg::Success => SshChannelEvent::Success,
        ChannelMsg::Failure => SshChannelEvent::Failure,
        ChannelMsg::OpenFailure(error) => SshChannelEvent::OpenFailure(format!("{error:?}")),
        _ => SshChannelEvent::Failure,
    }
}

/// Async byte stream backed by an SSH channel.
pub struct SshChannelStream {
    inner: russh::ChannelStream<russh::client::Msg>,
    context: OperationContext,
    operation_timeout: std::time::Duration,
}

impl SshChannelStream {
    pub fn with_context(mut self, context: OperationContext) -> Self {
        self.context = context;
        self
    }

    pub async fn read(&mut self, buffer: &mut [u8]) -> Result<usize, SshError> {
        let context = self
            .context
            .clone()
            .with_timeout_from_now(self.operation_timeout);
        self.read_with_context(buffer, &context).await
    }

    pub async fn read_with_context(
        &mut self,
        buffer: &mut [u8],
        context: &OperationContext,
    ) -> Result<usize, SshError> {
        context
            .run("read SSH channel stream", async {
                AsyncReadExt::read(&mut self.inner, buffer)
                    .await
                    .map_err(|error| {
                        SshError::from_source(crate::ErrorKind::Channel, error.to_string(), error)
                    })
            })
            .await
    }

    pub async fn write(&mut self, data: &[u8]) -> Result<(), SshError> {
        let context = self
            .context
            .clone()
            .with_timeout_from_now(self.operation_timeout);
        self.write_with_context(data, &context).await
    }

    pub async fn write_with_context(
        &mut self,
        data: &[u8],
        context: &OperationContext,
    ) -> Result<(), SshError> {
        context
            .run("write SSH channel stream", async {
                AsyncWriteExt::write_all(&mut self.inner, data)
                    .await
                    .map_err(|error| {
                        SshError::from_source(crate::ErrorKind::Channel, error.to_string(), error)
                    })
            })
            .await
    }

    pub async fn flush(&mut self) -> Result<(), SshError> {
        let context = self
            .context
            .clone()
            .with_timeout_from_now(self.operation_timeout);
        self.flush_with_context(&context).await
    }

    pub async fn flush_with_context(&mut self, context: &OperationContext) -> Result<(), SshError> {
        context
            .run("flush SSH channel stream", async {
                AsyncWriteExt::flush(&mut self.inner)
                    .await
                    .map_err(|error| {
                        SshError::from_source(crate::ErrorKind::Channel, error.to_string(), error)
                    })
            })
            .await
    }
}

impl AsyncRead for SshChannelStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buffer)
    }
}

impl AsyncWrite for SshChannelStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, data)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
