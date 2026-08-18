use std::sync::Arc;

use russh::client::{self, Handler};
use russh::keys::{PrivateKeyWithHashAlg, PublicKey};
use russh::Disconnect;

use crate::{AuthMethod, HostKeyDecision, HostKeyVerifier, SshConfig, SshError};

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
        config.validate()?;
        let handler = ClientHandler {
            host: config.host.clone(),
            port: config.port,
            verifier: Arc::new(verifier),
        };
        let client_config = client::Config {
            keepalive_interval: config.keepalive_interval,
            nodelay: true,
            ..Default::default()
        };

        let address = config.socket_address();
        let mut handle = tokio::time::timeout(
            config.connect_timeout,
            client::connect(Arc::new(client_config), address, handler),
        )
        .await
        .map_err(|_| SshError::timeout("SSH connection or handshake timed out"))?
        .map_err(classify_connect_error)?;

        authenticate(&mut handle, &config.username, auth).await?;

        Ok(Self { handle, config })
    }

    pub fn is_closed(&self) -> bool {
        self.handle.is_closed()
    }

    pub fn config(&self) -> &SshConfig {
        &self.config
    }

    pub(crate) async fn open_raw_session_channel(
        &self,
    ) -> Result<russh::Channel<russh::client::Msg>, SshError> {
        self.handle
            .channel_open_session()
            .await
            .map_err(|error| SshError::channel(error.to_string()))
    }

    pub async fn disconnect(&self) -> Result<(), SshError> {
        self.handle
            .disconnect(Disconnect::ByApplication, "client closed session", "")
            .await
            .map_err(|error| SshError::channel(error.to_string()))
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
            .map_err(|error| SshError::authentication(error.to_string()))?,
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
                .map_err(|error| SshError::authentication(error.to_string()))?
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
            SshError::handshake(error.message().to_owned())
        }
        _ => SshError::connection(error.message().to_owned()),
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
        session.disconnect().await.unwrap();
    }
}
