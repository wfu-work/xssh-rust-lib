use std::pin::Pin;

use russh::ChannelMsg;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{SshError, SshSession};

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
}

impl SshSession {
    /// Open a generic SSH session channel after authentication.
    pub async fn open_session_channel(&self) -> Result<SshChannel, SshError> {
        self.open_raw_session_channel()
            .await
            .map(|inner| SshChannel { inner })
    }
}

impl SshChannel {
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
            .map_err(|error| SshError::channel(error.to_string()))
    }

    /// Request a remote login shell.
    pub async fn request_shell(&self, want_reply: bool) -> Result<(), SshError> {
        self.inner
            .request_shell(want_reply)
            .await
            .map_err(|error| SshError::channel(error.to_string()))
    }

    /// Execute a command in this channel.
    pub async fn exec(
        &self,
        want_reply: bool,
        command: impl Into<Vec<u8>>,
    ) -> Result<(), SshError> {
        self.inner
            .exec(want_reply, command)
            .await
            .map_err(|error| SshError::channel(error.to_string()))
    }

    /// Request an SSH subsystem such as `sftp`.
    pub async fn request_subsystem(
        &self,
        want_reply: bool,
        name: impl Into<String>,
    ) -> Result<(), SshError> {
        self.inner
            .request_subsystem(want_reply, name)
            .await
            .map_err(|error| SshError::channel(error.to_string()))
    }

    /// Send bytes to the remote channel.
    pub async fn write(&self, data: &[u8]) -> Result<(), SshError> {
        self.inner
            .data(data)
            .await
            .map_err(|error| SshError::channel(error.to_string()))
    }

    /// Send an EOF marker to the remote channel.
    pub async fn eof(&self) -> Result<(), SshError> {
        self.inner
            .eof()
            .await
            .map_err(|error| SshError::channel(error.to_string()))
    }

    /// Notify the remote PTY about a window resize.
    pub async fn window_change(&self, col_width: u32, row_height: u32) -> Result<(), SshError> {
        self.inner
            .window_change(col_width, row_height, 0, 0)
            .await
            .map_err(|error| SshError::channel(error.to_string()))
    }

    /// Close the channel.
    pub async fn close(&self) -> Result<(), SshError> {
        self.inner
            .close()
            .await
            .map_err(|error| SshError::channel(error.to_string()))
    }

    /// Wait for the next protocol event.
    pub async fn next_event(&mut self) -> Option<SshChannelEvent> {
        self.inner.wait().await.map(channel_event)
    }

    /// Convert the channel into an asynchronous byte stream.
    pub fn into_stream(self) -> SshChannelStream {
        SshChannelStream {
            inner: self.inner.into_stream(),
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
