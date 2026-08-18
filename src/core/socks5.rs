use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};
use tokio::sync::Semaphore;

use super::auth::SecretString;
use super::operation::CancellationToken;
use crate::{ErrorKind, OperationContext, SshError, SshSession};

const SOCKS5_VERSION: u8 = 5;
const SOCKS5_NO_AUTH: u8 = 0;
const SOCKS5_USER_PASSWORD: u8 = 2;
const SOCKS5_NO_ACCEPTABLE_METHOD: u8 = 0xff;
const SOCKS5_USER_PASSWORD_VERSION: u8 = 1;
const SOCKS5_CONNECT: u8 = 1;
const SOCKS5_ATYP_IPV4: u8 = 1;
const SOCKS5_ATYP_DOMAIN: u8 = 3;
const SOCKS5_ATYP_IPV6: u8 = 4;

/// Authentication methods accepted by the local SOCKS5 listener.
#[derive(Clone, Debug)]
pub enum Socks5Authentication {
    /// Allow clients that advertise the SOCKS5 no-auth method.
    NoAuth,
    /// Require the SOCKS5 username/password sub-negotiation.
    UsernamePassword {
        username: String,
        password: SecretString,
    },
}

impl Socks5Authentication {
    pub fn no_auth() -> Self {
        Self::NoAuth
    }

    pub fn username_password(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self::UsernamePassword {
            username: username.into(),
            password: SecretString::new(password),
        }
    }
}

/// Runtime limits for an [`Socks5Proxy`].
#[derive(Clone, Debug)]
pub struct Socks5ProxyOptions {
    /// Maximum number of client connections handled concurrently.
    pub max_connections: usize,
    /// Deadline for the SOCKS5 handshake and SSH channel open request.
    pub handshake_timeout: Duration,
    /// Authentication required before a client can issue a CONNECT request.
    pub authentication: Socks5Authentication,
}

impl Default for Socks5ProxyOptions {
    fn default() -> Self {
        Self {
            max_connections: 128,
            handshake_timeout: Duration::from_secs(30),
            authentication: Socks5Authentication::NoAuth,
        }
    }
}

impl Socks5ProxyOptions {
    fn validate(&self) -> Result<(), SshError> {
        if self.max_connections == 0 {
            return Err(SshError::configuration(
                "SOCKS5 max_connections must be greater than zero",
            ));
        }
        if self.handshake_timeout.is_zero() {
            return Err(SshError::configuration(
                "SOCKS5 handshake_timeout must be greater than zero",
            ));
        }
        if let Socks5Authentication::UsernamePassword { username, password } = &self.authentication
        {
            if username.is_empty() || username.len() > u8::MAX as usize {
                return Err(SshError::configuration(
                    "SOCKS5 username must contain between 1 and 255 bytes",
                ));
            }
            if password.as_str().len() > u8::MAX as usize {
                return Err(SshError::configuration(
                    "SOCKS5 password must contain at most 255 bytes",
                ));
            }
        }
        Ok(())
    }
}

/// A local SOCKS5 dynamic proxy backed by SSH `direct-tcpip` channels.
///
/// The proxy only supports the SOCKS5 `CONNECT` command. DNS names are sent
/// to the SSH server unchanged, so name resolution happens from the server's
/// network position rather than on the local machine.
pub struct Socks5Proxy {
    listener: TcpListener,
    session: Arc<SshSession>,
    options: Socks5ProxyOptions,
}

impl Socks5Proxy {
    /// Bind a local SOCKS5 listener with default options.
    pub async fn bind<A>(session: Arc<SshSession>, address: A) -> Result<Self, SshError>
    where
        A: ToSocketAddrs,
    {
        Self::bind_with_options(session, address, Socks5ProxyOptions::default()).await
    }

    /// Bind a local SOCKS5 listener with explicit limits and authentication.
    pub async fn bind_with_options<A>(
        session: Arc<SshSession>,
        address: A,
        options: Socks5ProxyOptions,
    ) -> Result<Self, SshError>
    where
        A: ToSocketAddrs,
    {
        options.validate()?;
        let listener = TcpListener::bind(address).await.map_err(|error| {
            SshError::from_source(
                ErrorKind::Connection,
                "failed to bind SOCKS5 listener",
                error,
            )
        })?;
        Ok(Self {
            listener,
            session,
            options,
        })
    }

    /// Build a proxy around an already-bound listener.
    pub fn from_listener(session: Arc<SshSession>, listener: TcpListener) -> Self {
        Self {
            listener,
            session,
            options: Socks5ProxyOptions::default(),
        }
    }

    /// Build a proxy around an already-bound listener with explicit options.
    pub fn from_listener_with_options(
        session: Arc<SshSession>,
        listener: TcpListener,
        options: Socks5ProxyOptions,
    ) -> Result<Self, SshError> {
        options.validate()?;
        Ok(Self {
            listener,
            session,
            options,
        })
    }

    /// Return the effective local listener address.
    pub fn local_addr(&self) -> Result<SocketAddr, SshError> {
        self.listener.local_addr().map_err(|error| {
            SshError::from_source(
                ErrorKind::Connection,
                "failed to inspect SOCKS5 listener address",
                error,
            )
        })
    }

    pub fn options(&self) -> &Socks5ProxyOptions {
        &self.options
    }

    /// Serve clients until the supplied cancellation token is signalled.
    pub async fn run(&self, cancellation: CancellationToken) -> Result<(), SshError> {
        let context = OperationContext::new().with_cancellation(cancellation);
        self.run_with_context(&context).await
    }

    /// Serve clients until the context is cancelled or its deadline expires.
    pub async fn run_with_context(&self, context: &OperationContext) -> Result<(), SshError> {
        let permits = Arc::new(Semaphore::new(self.options.max_connections));
        loop {
            let (stream, _) = context
                .run("accept SOCKS5 proxy connection", async {
                    self.listener.accept().await.map_err(|error| {
                        SshError::from_source(
                            ErrorKind::Connection,
                            "failed to accept SOCKS5 proxy connection",
                            error,
                        )
                    })
                })
                .await?;

            let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                // Refuse excess connections by closing the socket. This keeps
                // the accept loop responsive and avoids unbounded task growth.
                continue;
            };

            let session = Arc::clone(&self.session);
            let options = self.options.clone();
            let connection_context = context.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let _ = handle_connection(stream, session, options, &connection_context).await;
            });
        }
    }
}

#[derive(Clone, Copy, Debug)]
#[repr(u8)]
enum ReplyCode {
    Succeeded = 0x00,
    GeneralFailure = 0x01,
    CommandNotSupported = 0x07,
    AddressTypeNotSupported = 0x08,
}

struct ConnectRequest {
    host: String,
    port: u16,
    command: u8,
}

#[derive(Debug)]
struct RequestError {
    code: ReplyCode,
    error: SshError,
}

impl From<SshError> for RequestError {
    fn from(error: SshError) -> Self {
        Self {
            code: ReplyCode::GeneralFailure,
            error,
        }
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    session: Arc<SshSession>,
    options: Socks5ProxyOptions,
    context: &OperationContext,
) -> Result<(), SshError> {
    let handshake_context = context
        .clone()
        .with_timeout_from_now(options.handshake_timeout);
    authenticate(&mut stream, &options.authentication, &handshake_context).await?;

    let request = match read_connect_request(&mut stream, &handshake_context).await {
        Ok(request) => request,
        Err(request_error) => {
            let _ = write_reply(&mut stream, request_error.code, &handshake_context).await;
            return Err(request_error.error);
        }
    };
    if request.command != SOCKS5_CONNECT {
        write_reply(
            &mut stream,
            ReplyCode::CommandNotSupported,
            &handshake_context,
        )
        .await?;
        return Ok(());
    }

    let channel = match session
        .open_direct_tcpip_with_context(request.host, request.port, &handshake_context)
        .await
    {
        Ok(channel) => channel,
        Err(error) => {
            let _ = write_reply(&mut stream, ReplyCode::GeneralFailure, &handshake_context).await;
            return Err(error);
        }
    };
    write_reply(&mut stream, ReplyCode::Succeeded, &handshake_context).await?;

    let mut remote = channel.into_stream();
    let cancellation = context.cancellation_token();
    context
        .run("relay SOCKS5 connection", async {
            tokio::select! {
                _ = cancellation.cancelled() => {
                    let _ = stream.shutdown().await;
                    let _ = remote.shutdown().await;
                    Err(SshError::cancelled("SOCKS5 relay was cancelled"))
                }
                result = tokio::io::copy_bidirectional(&mut stream, &mut remote) => {
                    result
                        .map(|_| ())
                        .map_err(|error| SshError::from_source(
                            ErrorKind::Channel,
                            "SOCKS5 relay failed",
                            error,
                        ))
                }
            }
        })
        .await
}

async fn authenticate<R>(
    stream: &mut R,
    authentication: &Socks5Authentication,
    context: &OperationContext,
) -> Result<(), SshError>
where
    R: AsyncRead + AsyncWrite + Unpin,
{
    let mut header = [0_u8; 2];
    read_exact(stream, &mut header, context, "read SOCKS5 methods").await?;
    if header[0] != SOCKS5_VERSION {
        return Err(SshError::protocol(
            "SOCKS5 client sent an unsupported version",
        ));
    }

    let mut methods = vec![0_u8; header[1] as usize];
    read_exact(stream, &mut methods, context, "read SOCKS5 methods").await?;
    match authentication {
        Socks5Authentication::NoAuth => {
            if !methods.contains(&SOCKS5_NO_AUTH) {
                write_all(
                    stream,
                    &[SOCKS5_VERSION, SOCKS5_NO_ACCEPTABLE_METHOD],
                    context,
                    "reject SOCKS5 authentication",
                )
                .await?;
                return Err(SshError::authentication(
                    "SOCKS5 client does not offer the no-auth method",
                ));
            }
            write_all(
                stream,
                &[SOCKS5_VERSION, SOCKS5_NO_AUTH],
                context,
                "select SOCKS5 no-auth",
            )
            .await
        }
        Socks5Authentication::UsernamePassword { username, password } => {
            if !methods.contains(&SOCKS5_USER_PASSWORD) {
                write_all(
                    stream,
                    &[SOCKS5_VERSION, SOCKS5_NO_ACCEPTABLE_METHOD],
                    context,
                    "reject SOCKS5 authentication",
                )
                .await?;
                return Err(SshError::authentication(
                    "SOCKS5 client does not offer username/password authentication",
                ));
            }
            write_all(
                stream,
                &[SOCKS5_VERSION, SOCKS5_USER_PASSWORD],
                context,
                "select SOCKS5 username/password",
            )
            .await?;

            let mut auth_header = [0_u8; 2];
            read_exact(stream, &mut auth_header, context, "read SOCKS5 credentials").await?;
            if auth_header[0] != SOCKS5_USER_PASSWORD_VERSION {
                return Err(SshError::protocol(
                    "SOCKS5 client sent an unsupported credential version",
                ));
            }
            let mut received_username = vec![0_u8; auth_header[1] as usize];
            read_exact(
                stream,
                &mut received_username,
                context,
                "read SOCKS5 username",
            )
            .await?;
            let mut password_length = [0_u8; 1];
            read_exact(
                stream,
                &mut password_length,
                context,
                "read SOCKS5 password length",
            )
            .await?;
            let mut received_password = vec![0_u8; password_length[0] as usize];
            read_exact(
                stream,
                &mut received_password,
                context,
                "read SOCKS5 password",
            )
            .await?;

            let accepted = received_username == username.as_bytes()
                && received_password == password.as_str().as_bytes();
            write_all(
                stream,
                &[SOCKS5_USER_PASSWORD_VERSION, if accepted { 0 } else { 1 }],
                context,
                "reply to SOCKS5 credentials",
            )
            .await?;
            if accepted {
                Ok(())
            } else {
                Err(SshError::authentication("invalid SOCKS5 credentials"))
            }
        }
    }
}

async fn read_connect_request<R>(
    stream: &mut R,
    context: &OperationContext,
) -> Result<ConnectRequest, RequestError>
where
    R: AsyncRead + AsyncWrite + Unpin,
{
    let mut header = [0_u8; 4];
    read_exact(stream, &mut header, context, "read SOCKS5 connect request").await?;
    if header[0] != SOCKS5_VERSION || header[2] != 0 {
        return Err(SshError::protocol("invalid SOCKS5 connect request header").into());
    }

    let host = match header[3] {
        SOCKS5_ATYP_IPV4 => {
            let mut bytes = [0_u8; 4];
            read_exact(stream, &mut bytes, context, "read SOCKS5 IPv4 target").await?;
            Ipv4Addr::from(bytes).to_string()
        }
        SOCKS5_ATYP_DOMAIN => {
            let mut length = [0_u8; 1];
            read_exact(stream, &mut length, context, "read SOCKS5 domain length").await?;
            if length[0] == 0 {
                return Err(SshError::protocol("SOCKS5 domain target must not be empty").into());
            }
            let mut bytes = vec![0_u8; length[0] as usize];
            read_exact(stream, &mut bytes, context, "read SOCKS5 domain target").await?;
            String::from_utf8(bytes)
                .map_err(|_| SshError::protocol("SOCKS5 domain target is not valid UTF-8"))?
        }
        SOCKS5_ATYP_IPV6 => {
            let mut bytes = [0_u8; 16];
            read_exact(stream, &mut bytes, context, "read SOCKS5 IPv6 target").await?;
            Ipv6Addr::from(bytes).to_string()
        }
        _ => {
            return Err(RequestError {
                code: ReplyCode::AddressTypeNotSupported,
                error: SshError::protocol("SOCKS5 target address type is not supported"),
            });
        }
    };

    let mut port = [0_u8; 2];
    read_exact(stream, &mut port, context, "read SOCKS5 target port").await?;
    let port = u16::from_be_bytes(port);
    if port == 0 {
        return Err(SshError::protocol("SOCKS5 target port must be greater than zero").into());
    }

    Ok(ConnectRequest {
        host,
        port,
        command: header[1],
    })
}

async fn write_reply<W>(
    stream: &mut W,
    reply: ReplyCode,
    context: &OperationContext,
) -> Result<(), SshError>
where
    W: AsyncWrite + Unpin,
{
    // The SSH channel does not expose a local socket binding. RFC 1928 allows
    // an unspecified IPv4 address and port in this response.
    write_all(
        stream,
        &[
            SOCKS5_VERSION,
            reply as u8,
            0,
            SOCKS5_ATYP_IPV4,
            0,
            0,
            0,
            0,
            0,
            0,
        ],
        context,
        "write SOCKS5 reply",
    )
    .await
}

async fn read_exact<R>(
    reader: &mut R,
    buffer: &mut [u8],
    context: &OperationContext,
    operation: &'static str,
) -> Result<(), SshError>
where
    R: AsyncRead + Unpin,
{
    context
        .run(operation, async {
            reader
                .read_exact(buffer)
                .await
                .map(|_| ())
                .map_err(|error| {
                    SshError::from_source(ErrorKind::Protocol, "invalid SOCKS5 client data", error)
                })
        })
        .await
}

async fn write_all<W>(
    writer: &mut W,
    buffer: &[u8],
    context: &OperationContext,
    operation: &'static str,
) -> Result<(), SshError>
where
    W: AsyncWrite + Unpin,
{
    context
        .run(operation, async {
            writer.write_all(buffer).await.map_err(|error| {
                SshError::from_source(ErrorKind::Channel, "failed to write SOCKS5 data", error)
            })
        })
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn username_password_authentication_is_negotiated() {
        let (mut client, mut server) = duplex(256);
        let authentication = Socks5Authentication::username_password("alice", "secret");
        let context = OperationContext::with_timeout(Duration::from_secs(1));
        let server_task =
            tokio::spawn(async move { authenticate(&mut server, &authentication, &context).await });

        client
            .write_all(&[SOCKS5_VERSION, 1, SOCKS5_USER_PASSWORD])
            .await
            .unwrap();
        let mut method = [0_u8; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [SOCKS5_VERSION, SOCKS5_USER_PASSWORD]);
        client
            .write_all(&[SOCKS5_USER_PASSWORD_VERSION, 5])
            .await
            .unwrap();
        client.write_all(b"alice").await.unwrap();
        client.write_all(&[6]).await.unwrap();
        client.write_all(b"secret").await.unwrap();
        let mut result = [0_u8; 2];
        client.read_exact(&mut result).await.unwrap();
        assert_eq!(result, [SOCKS5_USER_PASSWORD_VERSION, 0]);
        server_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn domain_connect_requests_are_parsed_without_local_dns() {
        let (mut client, mut server) = duplex(256);
        let context = OperationContext::with_timeout(Duration::from_secs(1));
        let server_task =
            tokio::spawn(async move { read_connect_request(&mut server, &context).await });

        client
            .write_all(&[SOCKS5_VERSION, SOCKS5_CONNECT, 0, SOCKS5_ATYP_DOMAIN, 13])
            .await
            .unwrap();
        client.write_all(b"echo.internal").await.unwrap();
        client.write_all(&7_u16.to_be_bytes()).await.unwrap();

        let request = server_task.await.unwrap().unwrap();
        assert_eq!(request.host, "echo.internal");
        assert_eq!(request.port, 7);
        assert_eq!(request.command, SOCKS5_CONNECT);
    }
}
