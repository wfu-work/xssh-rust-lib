use std::fmt;
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

/// A server-side TCP/IP forwarding request accepted by the SSH server.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SshRemoteTcpipForward {
    address: String,
    port: u16,
}

impl SshRemoteTcpipForward {
    pub(crate) fn new(address: String, port: u16) -> Self {
        Self { address, port }
    }

    /// Address on which the SSH server requested the remote listener.
    pub fn address(&self) -> &str {
        &self.address
    }

    /// Effective listener port. A requested port of zero is replaced by the
    /// port selected by the SSH server.
    pub fn port(&self) -> u16 {
        self.port
    }
}

/// A server-side Unix socket forwarding request accepted by the SSH server.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SshRemoteStreamlocalForward {
    socket_path: String,
}

impl SshRemoteStreamlocalForward {
    pub(crate) fn new(socket_path: String) -> Self {
        Self { socket_path }
    }

    /// Unix socket path on which the SSH server requested the remote listener.
    pub fn socket_path(&self) -> &str {
        &self.socket_path
    }
}

/// One incoming connection from a remote TCP/IP forward.
pub struct SshForwardedTcpipChannel {
    connected_address: String,
    connected_port: u16,
    originator_address: String,
    originator_port: u16,
    channel: SshChannel,
}

impl fmt::Debug for SshForwardedTcpipChannel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SshForwardedTcpipChannel")
            .field("connected_address", &self.connected_address)
            .field("connected_port", &self.connected_port)
            .field("originator_address", &self.originator_address)
            .field("originator_port", &self.originator_port)
            .finish_non_exhaustive()
    }
}

impl SshForwardedTcpipChannel {
    pub(crate) fn new(
        connected_address: String,
        connected_port: u16,
        originator_address: String,
        originator_port: u16,
        channel: SshChannel,
    ) -> Self {
        Self {
            connected_address,
            connected_port,
            originator_address,
            originator_port,
            channel,
        }
    }

    pub fn connected_address(&self) -> &str {
        &self.connected_address
    }

    pub fn connected_port(&self) -> u16 {
        self.connected_port
    }

    pub fn originator_address(&self) -> &str {
        &self.originator_address
    }

    pub fn originator_port(&self) -> u16 {
        self.originator_port
    }

    pub fn into_channel(self) -> SshChannel {
        self.channel
    }

    pub fn into_stream(self) -> SshChannelStream {
        self.channel.into_stream()
    }
}

/// One incoming connection from a remote Unix socket forward.
pub struct SshForwardedStreamlocalChannel {
    socket_path: String,
    channel: SshChannel,
}

impl fmt::Debug for SshForwardedStreamlocalChannel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SshForwardedStreamlocalChannel")
            .field("socket_path", &self.socket_path)
            .finish_non_exhaustive()
    }
}

impl SshForwardedStreamlocalChannel {
    pub(crate) fn new(socket_path: String, channel: SshChannel) -> Self {
        Self {
            socket_path,
            channel,
        }
    }

    /// Server-side socket path associated with this forwarded connection.
    pub fn socket_path(&self) -> &str {
        &self.socket_path
    }

    pub fn into_channel(self) -> SshChannel {
        self.channel
    }

    pub fn into_stream(self) -> SshChannelStream {
        self.channel.into_stream()
    }
}

pub(crate) struct PendingForwardedTcpip {
    pub(crate) channel: russh::Channel<russh::client::Msg>,
    pub(crate) connected_address: String,
    pub(crate) connected_port: u32,
    pub(crate) originator_address: String,
    pub(crate) originator_port: u32,
}

pub(crate) struct PendingForwardedStreamlocal {
    pub(crate) channel: russh::Channel<russh::client::Msg>,
    pub(crate) socket_path: String,
}

impl SshSession {
    /// Open a direct TCP/IP channel to a host reachable by the SSH server.
    ///
    /// The returned channel carries raw bidirectional TCP bytes. The
    /// originator is reported as `127.0.0.1:0`; use
    /// [`SshSession::open_direct_tcpip_from_with_context`] when the server
    /// needs the actual local originator address.
    pub async fn open_direct_tcpip(
        &self,
        target_host: impl Into<String>,
        target_port: u16,
    ) -> Result<SshChannel, SshError> {
        let context = self
            .base_context()
            .with_timeout_from_now(self.config().operation_timeout);
        self.open_direct_tcpip_from_with_context(target_host, target_port, "127.0.0.1", 0, &context)
            .await
    }

    /// Open a direct TCP/IP channel with an explicit operation context.
    pub async fn open_direct_tcpip_with_context(
        &self,
        target_host: impl Into<String>,
        target_port: u16,
        context: &OperationContext,
    ) -> Result<SshChannel, SshError> {
        self.open_direct_tcpip_from_with_context(target_host, target_port, "127.0.0.1", 0, context)
            .await
    }

    /// Open a direct TCP/IP channel and provide its originator address.
    pub async fn open_direct_tcpip_from(
        &self,
        target_host: impl Into<String>,
        target_port: u16,
        originator_address: impl Into<String>,
        originator_port: u16,
    ) -> Result<SshChannel, SshError> {
        let context = self
            .base_context()
            .with_timeout_from_now(self.config().operation_timeout);
        self.open_direct_tcpip_from_with_context(
            target_host,
            target_port,
            originator_address,
            originator_port,
            &context,
        )
        .await
    }

    /// Open a direct TCP/IP channel with explicit originator and context.
    pub async fn open_direct_tcpip_from_with_context(
        &self,
        target_host: impl Into<String>,
        target_port: u16,
        originator_address: impl Into<String>,
        originator_port: u16,
        context: &OperationContext,
    ) -> Result<SshChannel, SshError> {
        let target_host = target_host.into();
        let originator_address = originator_address.into();
        if target_host.trim().is_empty() {
            return Err(SshError::configuration(
                "direct-tcpip target host must not be empty",
            ));
        }
        if target_port == 0 {
            return Err(SshError::configuration(
                "direct-tcpip target port must be greater than zero",
            ));
        }
        if originator_address.trim().is_empty() {
            return Err(SshError::configuration(
                "direct-tcpip originator address must not be empty",
            ));
        }

        let channel = self
            .open_raw_direct_tcpip_with_context(
                target_host,
                target_port,
                originator_address,
                originator_port,
                context,
            )
            .await?;

        Ok(SshChannel::from_inner(
            channel,
            context.clone(),
            self.config().operation_timeout,
        ))
    }

    /// Open a channel to a Unix socket reachable by the SSH server.
    pub async fn open_direct_streamlocal(
        &self,
        socket_path: impl Into<String>,
    ) -> Result<SshChannel, SshError> {
        let context = self
            .base_context()
            .with_timeout_from_now(self.config().operation_timeout);
        self.open_direct_streamlocal_with_context(socket_path, &context)
            .await
    }

    /// Open a remote Unix socket channel with an explicit operation context.
    pub async fn open_direct_streamlocal_with_context(
        &self,
        socket_path: impl Into<String>,
        context: &OperationContext,
    ) -> Result<SshChannel, SshError> {
        let socket_path = validate_streamlocal_path(socket_path.into())?;
        let channel = self
            .open_raw_direct_streamlocal_with_context(socket_path, context)
            .await?;
        Ok(SshChannel::from_inner(
            channel,
            context.clone(),
            self.config().operation_timeout,
        ))
    }

    /// Ask the SSH server to listen for remote connections.
    ///
    /// Use [`SshSession::next_forwarded_tcpip`] to receive each incoming
    /// connection. Port zero asks the server to choose an available port.
    pub async fn request_remote_tcpip_forward(
        &mut self,
        address: impl Into<String>,
        port: u16,
    ) -> Result<SshRemoteTcpipForward, SshError> {
        let context = self
            .base_context()
            .with_timeout_from_now(self.config().operation_timeout);
        self.request_remote_tcpip_forward_with_context(address, port, &context)
            .await
    }

    /// Ask the SSH server to listen with an explicit operation context.
    pub async fn request_remote_tcpip_forward_with_context(
        &mut self,
        address: impl Into<String>,
        port: u16,
        context: &OperationContext,
    ) -> Result<SshRemoteTcpipForward, SshError> {
        let address = address.into();
        let returned_port = self
            .request_raw_tcpip_forward_with_context(address.clone(), port, context)
            .await?;
        let effective_port = if returned_port == 0 {
            port
        } else {
            u16::try_from(returned_port).map_err(|_| {
                SshError::from_source(
                    crate::ErrorKind::Protocol,
                    format!("SSH server returned invalid forwarded port {returned_port}"),
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "forwarded port exceeds the TCP port range",
                    ),
                )
            })?
        };
        if effective_port == 0 {
            return Err(SshError::protocol(
                "SSH server did not return a port for a dynamic remote forward",
            ));
        }
        Ok(SshRemoteTcpipForward::new(address, effective_port))
    }

    /// Wait for the next connection accepted by a remote TCP/IP forward.
    pub async fn next_forwarded_tcpip(&self) -> Result<Option<SshForwardedTcpipChannel>, SshError> {
        let context = self.base_context();
        self.next_forwarded_tcpip_with_context(&context).await
    }

    /// Wait for the next remote forwarded connection with cancellation.
    pub async fn next_forwarded_tcpip_with_context(
        &self,
        context: &OperationContext,
    ) -> Result<Option<SshForwardedTcpipChannel>, SshError> {
        let pending = self.next_raw_forwarded_tcpip_with_context(context).await?;
        let Some(pending) = pending else {
            return Ok(None);
        };
        let connected_port = u16::try_from(pending.connected_port).map_err(|_| {
            SshError::protocol(format!(
                "forwarded-tcpip connected port {} is outside the TCP port range",
                pending.connected_port
            ))
        })?;
        let originator_port = u16::try_from(pending.originator_port).map_err(|_| {
            SshError::protocol(format!(
                "forwarded-tcpip originator port {} is outside the TCP port range",
                pending.originator_port
            ))
        })?;
        Ok(Some(SshForwardedTcpipChannel::new(
            pending.connected_address,
            connected_port,
            pending.originator_address,
            originator_port,
            SshChannel::from_inner(
                pending.channel,
                self.base_context(),
                self.config().operation_timeout,
            ),
        )))
    }

    /// Cancel a previously registered remote TCP/IP forward.
    pub async fn cancel_remote_tcpip_forward(
        &mut self,
        forward: &SshRemoteTcpipForward,
    ) -> Result<(), SshError> {
        let context = self
            .base_context()
            .with_timeout_from_now(self.config().operation_timeout);
        self.cancel_remote_tcpip_forward_with_context(forward, &context)
            .await
    }

    /// Cancel a remote TCP/IP forward with an explicit operation context.
    pub async fn cancel_remote_tcpip_forward_with_context(
        &mut self,
        forward: &SshRemoteTcpipForward,
        context: &OperationContext,
    ) -> Result<(), SshError> {
        self.cancel_raw_tcpip_forward_with_context(forward.address.clone(), forward.port, context)
            .await
    }

    /// Ask the SSH server to listen for remote Unix socket connections.
    pub async fn request_remote_streamlocal_forward(
        &mut self,
        socket_path: impl Into<String>,
    ) -> Result<SshRemoteStreamlocalForward, SshError> {
        let context = self
            .base_context()
            .with_timeout_from_now(self.config().operation_timeout);
        self.request_remote_streamlocal_forward_with_context(socket_path, &context)
            .await
    }

    /// Ask the SSH server to listen on a Unix socket with an explicit context.
    pub async fn request_remote_streamlocal_forward_with_context(
        &mut self,
        socket_path: impl Into<String>,
        context: &OperationContext,
    ) -> Result<SshRemoteStreamlocalForward, SshError> {
        let socket_path = validate_streamlocal_path(socket_path.into())?;
        self.request_raw_streamlocal_forward_with_context(socket_path.clone(), context)
            .await?;
        Ok(SshRemoteStreamlocalForward::new(socket_path))
    }

    /// Wait for the next connection accepted by a remote Unix socket forward.
    pub async fn next_forwarded_streamlocal(
        &self,
    ) -> Result<Option<SshForwardedStreamlocalChannel>, SshError> {
        let context = self.base_context();
        self.next_forwarded_streamlocal_with_context(&context).await
    }

    /// Wait for the next remote Unix socket connection with cancellation.
    pub async fn next_forwarded_streamlocal_with_context(
        &self,
        context: &OperationContext,
    ) -> Result<Option<SshForwardedStreamlocalChannel>, SshError> {
        let pending = self
            .next_raw_forwarded_streamlocal_with_context(context)
            .await?;
        let Some(pending) = pending else {
            return Ok(None);
        };
        Ok(Some(SshForwardedStreamlocalChannel::new(
            pending.socket_path,
            SshChannel::from_inner(
                pending.channel,
                self.base_context(),
                self.config().operation_timeout,
            ),
        )))
    }

    /// Cancel a previously registered remote Unix socket forward.
    pub async fn cancel_remote_streamlocal_forward(
        &mut self,
        forward: &SshRemoteStreamlocalForward,
    ) -> Result<(), SshError> {
        let context = self
            .base_context()
            .with_timeout_from_now(self.config().operation_timeout);
        self.cancel_remote_streamlocal_forward_with_context(forward, &context)
            .await
    }

    /// Cancel a remote Unix socket forward with an explicit context.
    pub async fn cancel_remote_streamlocal_forward_with_context(
        &mut self,
        forward: &SshRemoteStreamlocalForward,
        context: &OperationContext,
    ) -> Result<(), SshError> {
        self.cancel_raw_streamlocal_forward_with_context(forward.socket_path.clone(), context)
            .await
    }

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
            .map(|inner| SshChannel::from_inner(inner, context, self.config().operation_timeout))
    }
}

fn validate_streamlocal_path(socket_path: String) -> Result<String, SshError> {
    if socket_path.trim().is_empty() {
        return Err(SshError::configuration(
            "streamlocal socket path must not be empty",
        ));
    }
    if socket_path.contains('\0') {
        return Err(SshError::configuration(
            "streamlocal socket path must not contain NUL",
        ));
    }
    Ok(socket_path)
}

impl SshChannel {
    pub(crate) fn from_inner(
        inner: russh::Channel<russh::client::Msg>,
        context: OperationContext,
        operation_timeout: std::time::Duration,
    ) -> Self {
        Self {
            inner,
            context,
            operation_timeout,
        }
    }

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
