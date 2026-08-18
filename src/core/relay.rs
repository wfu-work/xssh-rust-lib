use std::net::{IpAddr, SocketAddr};
#[cfg(unix)]
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
#[cfg(unix)]
use tokio::net::UnixListener;
use tokio::net::{TcpListener, ToSocketAddrs};
use tokio::sync::Semaphore;

use crate::{CancellationToken, ErrorKind, OperationContext, SshError, SshSession};

/// The SSH endpoint selected for each accepted local relay connection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ForwardingTarget {
    Tcp { host: String, port: u16 },
    Streamlocal { socket_path: String },
}

impl ForwardingTarget {
    pub fn tcp(host: impl Into<String>, port: u16) -> Result<Self, SshError> {
        let host = host.into();
        if host.trim().is_empty() {
            return Err(SshError::configuration(
                "forwarding target host must not be empty",
            ));
        }
        if port == 0 {
            return Err(SshError::configuration(
                "forwarding target port must be greater than zero",
            ));
        }
        Ok(Self::Tcp { host, port })
    }

    pub fn streamlocal(socket_path: impl Into<String>) -> Result<Self, SshError> {
        let socket_path = socket_path.into();
        validate_socket_path(&socket_path)?;
        Ok(Self::Streamlocal { socket_path })
    }

    fn validate(&self) -> Result<(), SshError> {
        match self {
            Self::Tcp { host, port } => {
                if host.trim().is_empty() {
                    return Err(SshError::configuration(
                        "forwarding target host must not be empty",
                    ));
                }
                if *port == 0 {
                    return Err(SshError::configuration(
                        "forwarding target port must be greater than zero",
                    ));
                }
            }
            Self::Streamlocal { socket_path } => validate_socket_path(socket_path)?,
        }
        Ok(())
    }
}

/// Peer address policy for locally accepted relay connections.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ForwardingAccessPolicy {
    allowed_peer_ips: Vec<IpAddr>,
}

impl ForwardingAccessPolicy {
    /// Allow every TCP peer and local Unix socket peer.
    pub fn allow_all() -> Self {
        Self::default()
    }

    /// Allow only the exact IP addresses supplied. Unix socket peers are
    /// rejected when an allowlist is configured because they have no IP.
    pub fn allow_peer_ips<I>(ips: I) -> Self
    where
        I: IntoIterator<Item = IpAddr>,
    {
        Self {
            allowed_peer_ips: ips.into_iter().collect(),
        }
    }

    pub fn allowed_peer_ips(&self) -> &[IpAddr] {
        &self.allowed_peer_ips
    }

    fn allows(&self, peer_ip: Option<IpAddr>) -> bool {
        self.allowed_peer_ips.is_empty()
            || peer_ip.is_some_and(|peer_ip| self.allowed_peer_ips.contains(&peer_ip))
    }
}

/// Limits applied to each [`SshForwardingRelay`].
#[derive(Clone, Debug)]
pub struct ForwardingRelayOptions {
    pub max_connections: usize,
    pub connection_timeout: Duration,
    pub access_policy: ForwardingAccessPolicy,
}

impl Default for ForwardingRelayOptions {
    fn default() -> Self {
        Self {
            max_connections: 128,
            connection_timeout: Duration::from_secs(15),
            access_policy: ForwardingAccessPolicy::default(),
        }
    }
}

impl ForwardingRelayOptions {
    fn validate(&self) -> Result<(), SshError> {
        if self.max_connections == 0 {
            return Err(SshError::configuration(
                "forwarding max_connections must be greater than zero",
            ));
        }
        if self.connection_timeout.is_zero() {
            return Err(SshError::configuration(
                "forwarding connection_timeout must be greater than zero",
            ));
        }
        Ok(())
    }
}

/// Snapshot of relay lifecycle and traffic counters.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ForwardingRelayStatsSnapshot {
    pub accepted_connections: u64,
    pub rejected_connections: u64,
    pub active_connections: u64,
    pub completed_connections: u64,
    pub failed_connections: u64,
    pub bytes_local_to_remote: u64,
    pub bytes_remote_to_local: u64,
    pub elapsed: Duration,
}

impl ForwardingRelayStatsSnapshot {
    pub fn total_bytes(&self) -> u64 {
        self.bytes_local_to_remote
            .saturating_add(self.bytes_remote_to_local)
    }

    pub fn bytes_per_second(&self) -> f64 {
        let seconds = self.elapsed.as_secs_f64();
        if seconds == 0.0 {
            0.0
        } else {
            self.total_bytes() as f64 / seconds
        }
    }
}

struct RelayStats {
    started_at: Instant,
    accepted_connections: AtomicU64,
    rejected_connections: AtomicU64,
    active_connections: AtomicU64,
    completed_connections: AtomicU64,
    failed_connections: AtomicU64,
    bytes_local_to_remote: AtomicU64,
    bytes_remote_to_local: AtomicU64,
}

impl RelayStats {
    fn new() -> Self {
        Self {
            started_at: Instant::now(),
            accepted_connections: AtomicU64::new(0),
            rejected_connections: AtomicU64::new(0),
            active_connections: AtomicU64::new(0),
            completed_connections: AtomicU64::new(0),
            failed_connections: AtomicU64::new(0),
            bytes_local_to_remote: AtomicU64::new(0),
            bytes_remote_to_local: AtomicU64::new(0),
        }
    }

    fn snapshot(&self) -> ForwardingRelayStatsSnapshot {
        ForwardingRelayStatsSnapshot {
            accepted_connections: self.accepted_connections.load(Ordering::Relaxed),
            rejected_connections: self.rejected_connections.load(Ordering::Relaxed),
            active_connections: self.active_connections.load(Ordering::Relaxed),
            completed_connections: self.completed_connections.load(Ordering::Relaxed),
            failed_connections: self.failed_connections.load(Ordering::Relaxed),
            bytes_local_to_remote: self.bytes_local_to_remote.load(Ordering::Relaxed),
            bytes_remote_to_local: self.bytes_remote_to_local.load(Ordering::Relaxed),
            elapsed: self.started_at.elapsed(),
        }
    }
}

/// A reusable local listener and SSH relay manager.
pub struct SshForwardingRelay {
    listener: RelayListener,
    session: Arc<SshSession>,
    target: ForwardingTarget,
    options: ForwardingRelayOptions,
    stats: Arc<RelayStats>,
}

impl SshForwardingRelay {
    pub async fn bind_tcp<A>(
        session: Arc<SshSession>,
        address: A,
        target: ForwardingTarget,
        options: ForwardingRelayOptions,
    ) -> Result<Self, SshError>
    where
        A: ToSocketAddrs,
    {
        options.validate()?;
        target.validate()?;
        let listener = TcpListener::bind(address).await.map_err(|error| {
            SshError::from_source(
                ErrorKind::Connection,
                "failed to bind forwarding listener",
                error,
            )
        })?;
        Self::from_tcp_listener(session, listener, target, options)
    }

    pub fn from_tcp_listener(
        session: Arc<SshSession>,
        listener: TcpListener,
        target: ForwardingTarget,
        options: ForwardingRelayOptions,
    ) -> Result<Self, SshError> {
        options.validate()?;
        target.validate()?;
        Ok(Self {
            listener: RelayListener::Tcp(listener),
            session,
            target,
            options,
            stats: Arc::new(RelayStats::new()),
        })
    }

    #[cfg(unix)]
    pub async fn bind_unix(
        session: Arc<SshSession>,
        path: impl AsRef<Path>,
        target: ForwardingTarget,
        options: ForwardingRelayOptions,
    ) -> Result<Self, SshError> {
        options.validate()?;
        target.validate()?;
        let path = path.as_ref().to_path_buf();
        let listener = UnixListener::bind(&path).map_err(|error| {
            SshError::from_source(
                ErrorKind::Connection,
                "failed to bind Unix forwarding listener",
                error,
            )
        })?;
        Self::from_unix_listener(session, listener, path, target, options)
    }

    #[cfg(unix)]
    pub fn from_unix_listener(
        session: Arc<SshSession>,
        listener: UnixListener,
        path: PathBuf,
        target: ForwardingTarget,
        options: ForwardingRelayOptions,
    ) -> Result<Self, SshError> {
        options.validate()?;
        target.validate()?;
        Ok(Self {
            listener: RelayListener::Unix { listener, path },
            session,
            target,
            options,
            stats: Arc::new(RelayStats::new()),
        })
    }

    pub fn target(&self) -> &ForwardingTarget {
        &self.target
    }

    pub fn options(&self) -> &ForwardingRelayOptions {
        &self.options
    }

    pub fn stats(&self) -> ForwardingRelayStatsSnapshot {
        self.stats.snapshot()
    }

    pub fn local_addr(&self) -> Result<SocketAddr, SshError> {
        match &self.listener {
            RelayListener::Tcp(listener) => listener.local_addr().map_err(|error| {
                SshError::from_source(
                    ErrorKind::Connection,
                    "failed to inspect forwarding listener address",
                    error,
                )
            }),
            #[cfg(unix)]
            RelayListener::Unix { .. } => Err(SshError::configuration(
                "Unix forwarding listener does not have an IP socket address",
            )),
        }
    }

    #[cfg(unix)]
    pub fn local_unix_path(&self) -> Option<&Path> {
        match &self.listener {
            RelayListener::Tcp(_) => None,
            RelayListener::Unix { path, .. } => Some(path),
        }
    }

    pub async fn run(&self, cancellation: CancellationToken) -> Result<(), SshError> {
        let context = OperationContext::new().with_cancellation(cancellation);
        self.run_with_context(&context).await
    }

    pub async fn run_with_context(&self, context: &OperationContext) -> Result<(), SshError> {
        let permits = Arc::new(Semaphore::new(self.options.max_connections));
        loop {
            let (stream, peer_ip) = context
                .run("accept forwarding relay connection", self.listener.accept())
                .await?;
            self.stats
                .accepted_connections
                .fetch_add(1, Ordering::Relaxed);

            if !self.options.access_policy.allows(peer_ip) {
                self.stats
                    .rejected_connections
                    .fetch_add(1, Ordering::Relaxed);
                continue;
            }

            let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                self.stats
                    .rejected_connections
                    .fetch_add(1, Ordering::Relaxed);
                continue;
            };
            self.stats
                .active_connections
                .fetch_add(1, Ordering::Relaxed);
            let session = Arc::clone(&self.session);
            let target = self.target.clone();
            let options = self.options.clone();
            let stats = Arc::clone(&self.stats);
            let connection_context = context.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let _active = ActiveConnectionGuard {
                    stats: Arc::clone(&stats),
                };
                let result = relay_connection(
                    stream,
                    session,
                    target,
                    options,
                    &connection_context,
                    Arc::clone(&stats),
                )
                .await;
                stats.completed_connections.fetch_add(1, Ordering::Relaxed);
                if result
                    .as_ref()
                    .is_err_and(|error| error.kind() != crate::ErrorKind::Cancelled)
                {
                    stats.failed_connections.fetch_add(1, Ordering::Relaxed);
                }
            });
        }
    }
}

struct ActiveConnectionGuard {
    stats: Arc<RelayStats>,
}

impl Drop for ActiveConnectionGuard {
    fn drop(&mut self) {
        self.stats
            .active_connections
            .fetch_sub(1, Ordering::Relaxed);
    }
}

enum RelayListener {
    Tcp(TcpListener),
    #[cfg(unix)]
    Unix {
        listener: UnixListener,
        path: PathBuf,
    },
}

impl RelayListener {
    async fn accept(&self) -> Result<(BoxedRelayIo, Option<IpAddr>), SshError> {
        match self {
            Self::Tcp(listener) => {
                let (stream, peer) = listener.accept().await.map_err(|error| {
                    SshError::from_source(
                        ErrorKind::Connection,
                        "failed to accept forwarding TCP connection",
                        error,
                    )
                })?;
                Ok((Box::new(stream), Some(peer.ip())))
            }
            #[cfg(unix)]
            Self::Unix { listener, .. } => {
                let (stream, _) = listener.accept().await.map_err(|error| {
                    SshError::from_source(
                        ErrorKind::Connection,
                        "failed to accept forwarding Unix connection",
                        error,
                    )
                })?;
                Ok((Box::new(stream), None))
            }
        }
    }
}

trait RelayIo: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> RelayIo for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

type BoxedRelayIo = Box<dyn RelayIo>;

async fn relay_connection(
    local: BoxedRelayIo,
    session: Arc<SshSession>,
    target: ForwardingTarget,
    options: ForwardingRelayOptions,
    context: &OperationContext,
    stats: Arc<RelayStats>,
) -> Result<(), SshError> {
    let open_context = context
        .clone()
        .with_timeout_from_now(options.connection_timeout);
    let channel = match target {
        ForwardingTarget::Tcp { host, port } => {
            session
                .open_direct_tcpip_with_context(host, port, &open_context)
                .await?
        }
        ForwardingTarget::Streamlocal { socket_path } => {
            session
                .open_direct_streamlocal_with_context(socket_path, &open_context)
                .await?
        }
    };
    let remote = channel.into_stream();
    let mut local = CountingStream::local(local, Arc::clone(&stats));
    let mut remote = CountingStream::remote(remote, Arc::clone(&stats));
    let cancellation = context.cancellation_token();
    context
        .run("relay forwarding connection", async {
            tokio::select! {
                _ = cancellation.cancelled() => {
                    let _ = local.shutdown().await;
                    let _ = remote.shutdown().await;
                    Err(SshError::cancelled("forwarding relay was cancelled"))
                }
                result = tokio::io::copy_bidirectional(&mut local, &mut remote) => {
                    result
                        .map(|_| ())
                        .map_err(|error| SshError::from_source(
                            ErrorKind::Channel,
                            "forwarding relay failed",
                            error,
                        ))
                }
            }
        })
        .await
}

#[derive(Clone, Copy)]
enum CounterDirection {
    LocalToRemote,
    RemoteToLocal,
}

struct CountingStream<S> {
    inner: S,
    stats: Arc<RelayStats>,
    read_direction: CounterDirection,
}

impl<S> CountingStream<S> {
    fn local(inner: S, stats: Arc<RelayStats>) -> Self {
        Self {
            inner,
            stats,
            read_direction: CounterDirection::LocalToRemote,
        }
    }

    fn remote(inner: S, stats: Arc<RelayStats>) -> Self {
        Self {
            inner,
            stats,
            read_direction: CounterDirection::RemoteToLocal,
        }
    }

    fn add_bytes(&self, direction: &CounterDirection, bytes: usize) {
        let bytes = bytes as u64;
        match direction {
            CounterDirection::LocalToRemote => self
                .stats
                .bytes_local_to_remote
                .fetch_add(bytes, Ordering::Relaxed),
            CounterDirection::RemoteToLocal => self
                .stats
                .bytes_remote_to_local
                .fetch_add(bytes, Ordering::Relaxed),
        };
    }
}

impl<S> AsyncRead for CountingStream<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buffer.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(context, buffer);
        if let Poll::Ready(Ok(())) = &result {
            let bytes = buffer.filled().len().saturating_sub(before);
            self.add_bytes(&self.read_direction, bytes);
        }
        result
    }
}

impl<S> AsyncWrite for CountingStream<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

fn validate_socket_path(socket_path: &str) -> Result<(), SshError> {
    if socket_path.trim().is_empty() {
        return Err(SshError::configuration(
            "forwarding streamlocal socket path must not be empty",
        ));
    }
    if socket_path.contains('\0') {
        return Err(SshError::configuration(
            "forwarding streamlocal socket path must not contain NUL",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_policy_matches_exact_peer_ips() {
        let policy = ForwardingAccessPolicy::allow_peer_ips(["127.0.0.1".parse().unwrap()]);
        assert!(policy.allows(Some("127.0.0.1".parse().unwrap())));
        assert!(!policy.allows(Some("127.0.0.2".parse().unwrap())));
        assert!(!policy.allows(None));
    }

    #[test]
    fn target_and_options_reject_invalid_values() {
        assert!(ForwardingTarget::tcp("", 22).is_err());
        assert!(ForwardingTarget::tcp("server", 0).is_err());
        assert!(ForwardingTarget::streamlocal("/tmp/a\0b").is_err());
        assert!(ForwardingTarget::streamlocal(" ").is_err());
        assert!(ForwardingRelayOptions {
            max_connections: 0,
            ..Default::default()
        }
        .validate()
        .is_err());
    }
}
