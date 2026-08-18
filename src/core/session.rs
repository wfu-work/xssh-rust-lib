use std::sync::Arc;

use russh::client::{self, Handler};
use russh::keys::{PrivateKeyWithHashAlg, PublicKey};
use russh::Disconnect;

use crate::{AuthMethod, HostKeyDecision, HostKeyVerifier, OperationContext, SshConfig, SshError};

struct ClientHandler {
    host: String,
    port: u16,
    verifier: Arc<dyn HostKeyVerifier>,
}

impl Handler for ClientHandler {
    type Error = SshError;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKey,
    ) -> Result<bool, Self::Error> {
        match self
            .verifier
            .verify(&self.host, self.port, server_public_key)?
        {
            HostKeyDecision::Trusted => Ok(true),
            HostKeyDecision::Unknown => Err(SshError::host_key(format!(
                "unknown host key for {}:{} (fingerprint: {})",
                self.host,
                self.port,
                server_public_key.fingerprint(russh::keys::HashAlg::Sha256)
            ))),
            HostKeyDecision::Changed => Err(SshError::host_key(format!(
                "host key changed for {}:{}",
                self.host, self.port
            ))),
        }
    }
}

/// An authenticated SSH transport session.
pub struct SshSession {
    handle: client::Handle<ClientHandler>,
    config: SshConfig,
    operation_context: OperationContext,
}

impl SshSession {
    /// Connect, verify the server key, and authenticate the session.
    pub async fn connect<V>(
        config: SshConfig,
        verifier: V,
        auth: AuthMethod,
    ) -> Result<Self, SshError>
    where
        V: HostKeyVerifier + 'static,
    {
        Self::connect_with_context(config, verifier, auth, OperationContext::new()).await
    }

    /// Connect with an explicit cancellation token or parent deadline.
    pub async fn connect_with_context<V>(
        config: SshConfig,
        verifier: V,
        auth: AuthMethod,
        context: OperationContext,
    ) -> Result<Self, SshError>
    where
        V: HostKeyVerifier + 'static,
    {
        config.validate()?;
        let host = config.host.clone();
        let port = config.port;
        let handler = ClientHandler {
            host: host.clone(),
            port,
            verifier: Arc::new(verifier),
        };
        let client_config = client::Config {
            keepalive_interval: config.keepalive_interval,
            nodelay: true,
            ..Default::default()
        };

        let address = config.socket_address();
        let connect_context = context
            .clone()
            .with_timeout_from_now(config.connect_timeout);
        let mut handle = connect_context
            .run("ssh connect and handshake", async move {
                client::connect(Arc::new(client_config), address, handler)
                    .await
                    .map_err(classify_connect_error)
            })
            .await
            .map_err(|error| error.with_endpoint(host.clone(), port))?;

        let authentication_context = context
            .clone()
            .with_timeout_from_now(config.authentication_timeout);
        authentication_context
            .run(
                "ssh authentication",
                authenticate(&mut handle, &config.username, auth),
            )
            .await
            .map_err(|error| error.with_endpoint(host, port))?;

        Ok(Self {
            handle,
            operation_context: context,
            config,
        })
    }

    pub fn is_closed(&self) -> bool {
        self.handle.is_closed()
    }

    pub fn config(&self) -> &SshConfig {
        &self.config
    }

    pub fn operation_context(&self) -> OperationContext {
        self.operation_context
            .clone()
            .with_timeout_from_now(self.config.operation_timeout)
    }

    pub(crate) fn base_context(&self) -> OperationContext {
        self.operation_context.clone()
    }

    pub(crate) async fn open_raw_session_channel_with_context(
        &self,
        context: &OperationContext,
    ) -> Result<russh::Channel<russh::client::Msg>, SshError> {
        context
            .run_with_timeout(
                "open SSH session channel",
                self.config.operation_timeout,
                async {
                    self.handle.channel_open_session().await.map_err(|error| {
                        SshError::from_source(crate::ErrorKind::Channel, error.to_string(), error)
                    })
                },
            )
            .await
    }

    pub async fn disconnect(&self) -> Result<(), SshError> {
        let context = self.operation_context();
        self.disconnect_with_context(&context).await
    }

    pub async fn disconnect_with_context(
        &self,
        context: &OperationContext,
    ) -> Result<(), SshError> {
        context
            .run("disconnect SSH session", async {
                self.handle
                    .disconnect(Disconnect::ByApplication, "client closed session", "")
                    .await
                    .map_err(|error| {
                        SshError::from_source(crate::ErrorKind::Channel, error.to_string(), error)
                    })
            })
            .await
    }
}

async fn authenticate(
    handle: &mut client::Handle<ClientHandler>,
    username: &str,
    auth: AuthMethod,
) -> Result<(), SshError> {
    let result = match auth {
        AuthMethod::Password(password) => handle
            .authenticate_password(username, password.as_str().to_owned())
            .await
            .map_err(|error| {
                SshError::from_source(crate::ErrorKind::Authentication, error.to_string(), error)
            })?,
        AuthMethod::PrivateKey { key, passphrase } => {
            let key = if key.is_encrypted() {
                let Some(passphrase) = passphrase else {
                    return Err(SshError::configuration(
                        "encrypted private key requires a passphrase",
                    ));
                };
                key.decrypt(passphrase.as_str()).map_err(|error| {
                    SshError::authentication(format!("failed to decrypt private key: {error}"))
                })?
            } else {
                *key
            };
            handle
                .authenticate_publickey(username, PrivateKeyWithHashAlg::new(Arc::new(key), None))
                .await
                .map_err(|error| {
                    SshError::from_source(
                        crate::ErrorKind::Authentication,
                        error.to_string(),
                        error,
                    )
                })?
        }
    };

    if result.success() {
        Ok(())
    } else {
        Err(SshError::authentication("SSH authentication failed"))
    }
}

fn classify_connect_error(error: SshError) -> SshError {
    match error.kind() {
        crate::ErrorKind::HostKey | crate::ErrorKind::Timeout => error,
        _ if error
            .message()
            .to_ascii_lowercase()
            .contains("key exchange")
            || error.message().to_ascii_lowercase().contains("ssh id") =>
        {
            error.reclassify(crate::ErrorKind::Handshake)
        }
        _ => error.reclassify(crate::ErrorKind::Connection),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use russh::keys::{Algorithm, PrivateKey};
    use russh::server::{self, Auth};
    use tokio::net::TcpListener;

    use super::SshSession;
    use crate::{AuthMethod, KnownHostKeyVerifier, SshConfig};

    struct PasswordServer;

    impl server::Handler for PasswordServer {
        type Error = russh::Error;

        async fn auth_password(
            &mut self,
            _user: &str,
            password: &str,
        ) -> Result<Auth, Self::Error> {
            if password == "test-password" {
                Ok(Auth::Accept)
            } else {
                Ok(Auth::reject())
            }
        }
    }

    struct SlowPasswordServer;

    impl server::Handler for SlowPasswordServer {
        type Error = russh::Error;

        async fn auth_password(
            &mut self,
            _user: &str,
            _password: &str,
        ) -> Result<Auth, Self::Error> {
            tokio::time::sleep(Duration::from_millis(100)).await;
            Ok(Auth::Accept)
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn connects_verifies_host_key_and_authenticates() {
        let server_key = PrivateKey::random(
            &mut russh::keys::ssh_key::rand_core::OsRng,
            Algorithm::Ed25519,
        )
        .unwrap();
        let mut server_config = server::Config::default();
        server_config.keys.push(server_key.clone());
        let server_config = Arc::new(server_config);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            server::run_stream(server_config, socket, PasswordServer)
                .await
                .unwrap();
        });

        let mut verifier = KnownHostKeyVerifier::new();
        verifier.insert_key("127.0.0.1", address.port(), server_key.public_key());
        let mut config = SshConfig::new("127.0.0.1", "alice").unwrap();
        config.port = address.port();
        config.connect_timeout = Duration::from_secs(5);

        let session = SshSession::connect(config, verifier, AuthMethod::password("test-password"))
            .await
            .unwrap();
        assert!(!session.is_closed());
        let first_deadline = session.operation_context().deadline().unwrap();
        tokio::time::sleep(Duration::from_millis(1)).await;
        let second_deadline = session.operation_context().deadline().unwrap();
        assert!(second_deadline > first_deadline);
        session.disconnect().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn authentication_honors_its_own_timeout() {
        let server_key = PrivateKey::random(
            &mut russh::keys::ssh_key::rand_core::OsRng,
            Algorithm::Ed25519,
        )
        .unwrap();
        let mut server_config = server::Config::default();
        server_config.keys.push(server_key.clone());
        let server_config = Arc::new(server_config);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            server::run_stream(server_config, socket, SlowPasswordServer)
                .await
                .unwrap();
        });

        let mut verifier = KnownHostKeyVerifier::new();
        verifier.insert_key("127.0.0.1", address.port(), server_key.public_key());
        let mut config = SshConfig::new("127.0.0.1", "alice").unwrap();
        config.port = address.port();
        config.connect_timeout = Duration::from_secs(5);
        config.authentication_timeout = Duration::from_millis(10);

        let error =
            match SshSession::connect(config, verifier, AuthMethod::password("password")).await {
                Ok(_) => panic!("authentication unexpectedly succeeded"),
                Err(error) => error,
            };
        assert_eq!(error.kind(), crate::ErrorKind::Timeout);
        assert_eq!(error.operation(), Some("ssh authentication"));
    }
}
