use std::sync::Arc;

use russh::client::{self, AuthResult, Handler, KeyboardInteractiveAuthResponse};
use russh::keys::agent::client::{AgentClient, AgentStream};
use russh::keys::{Algorithm, HashAlg, PrivateKeyWithHashAlg, PublicKey};
use russh::Disconnect;

use crate::{
    AuthMethod, AuthenticationObservation, AuthenticationPlan, HostKeyDecision, HostKeyVerifier,
    KeyboardInteractiveChallenge, KeyboardInteractivePrompt, OperationContext, RsaHashAlgorithm,
    ServerAuthMethod, SshConfig, SshError,
};

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
        let decision = self
            .verifier
            .verify(&self.host, self.port, server_public_key)?;
        if decision == HostKeyDecision::Trusted {
            return Ok(true);
        }

        let mut observation = self
            .verifier
            .check(&self.host, self.port, server_public_key)?;
        observation.decision = decision;
        match decision {
            HostKeyDecision::Trusted => Ok(true),
            HostKeyDecision::Unknown => Err(SshError::host_key(format!(
                "unknown host key for {}:{} (presented fingerprint: {})",
                self.host, self.port, observation.presented_fingerprint
            ))
            .with_host_key_observation(observation)),
            HostKeyDecision::Changed => Err(SshError::host_key(format!(
                "host key changed for {}:{} (expected: {}; presented: {}; lines: {:?})",
                self.host,
                self.port,
                if observation.expected_fingerprints.is_empty() {
                    "<none>".to_owned()
                } else {
                    observation.expected_fingerprints.join(", ")
                },
                observation.presented_fingerprint,
                observation.matched_lines
            ))
            .with_host_key_observation(observation)),
            HostKeyDecision::Revoked => Err(SshError::host_key(format!(
                "revoked host key for {}:{} (fingerprint: {}; lines: {:?})",
                self.host, self.port, observation.presented_fingerprint, observation.matched_lines
            ))
            .with_host_key_observation(observation)),
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
    pub async fn connect<V, A>(config: SshConfig, verifier: V, auth: A) -> Result<Self, SshError>
    where
        V: HostKeyVerifier + 'static,
        A: Into<AuthenticationPlan>,
    {
        Self::connect_with_context(config, verifier, auth, OperationContext::new()).await
    }

    /// Connect with an explicit cancellation token or parent deadline.
    pub async fn connect_with_context<V, A>(
        config: SshConfig,
        verifier: V,
        auth: A,
        context: OperationContext,
    ) -> Result<Self, SshError>
    where
        V: HostKeyVerifier + 'static,
        A: Into<AuthenticationPlan>,
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
        let authentication_plan = auth.into();
        authentication_context
            .run(
                "ssh authentication",
                authenticate(&mut handle, &config.username, authentication_plan),
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

    pub(crate) async fn open_raw_direct_tcpip_with_context(
        &self,
        target_host: String,
        target_port: u16,
        originator_address: String,
        originator_port: u16,
        context: &OperationContext,
    ) -> Result<russh::Channel<russh::client::Msg>, SshError> {
        context
            .run("open direct-tcpip channel", async {
                self.handle
                    .channel_open_direct_tcpip(
                        target_host,
                        u32::from(target_port),
                        originator_address,
                        u32::from(originator_port),
                    )
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
    plan: AuthenticationPlan,
) -> Result<(), SshError> {
    if plan.is_empty() {
        return Err(SshError::configuration(
            "SSH authentication plan must contain at least one method",
        ));
    }

    let mut observation = AuthenticationObservation::default();
    let mut last_error = None;
    for method in plan.into_methods() {
        let kind = method.kind();
        match authenticate_method(handle, username, method).await {
            Ok(outcome) if outcome.accepted => return Ok(()),
            Ok(outcome) => {
                last_error = None;
                observation.record_failure(kind, outcome.remaining_methods, outcome.partial_success)
            }
            Err(error) => {
                observation.record_error(kind, &error);
                last_error = Some(error);
                if handle.is_closed() {
                    break;
                }
            }
        }
    }

    let error = last_error.unwrap_or_else(|| SshError::authentication("SSH authentication failed"));
    Err(error.with_authentication_observation(observation))
}

#[derive(Debug, Default)]
struct AuthOutcome {
    accepted: bool,
    remaining_methods: Vec<ServerAuthMethod>,
    partial_success: bool,
}

async fn authenticate_method(
    handle: &mut client::Handle<ClientHandler>,
    username: &str,
    method: AuthMethod,
) -> Result<AuthOutcome, SshError> {
    match method {
        AuthMethod::Password(password) => {
            let result = handle
                .authenticate_password(username, password.as_str().to_owned())
                .await
                .map_err(|error| authentication_source_error(error.to_string(), error))?;
            Ok(auth_outcome(result))
        }
        AuthMethod::PrivateKey {
            key,
            passphrase,
            rsa_hash,
        } => authenticate_private_key(handle, username, key, passphrase, rsa_hash).await,
        AuthMethod::OpenSshCertificate {
            key,
            certificate,
            passphrase,
        } => {
            let key = decrypt_private_key(key, passphrase)?;
            if !certificate.cert_type().is_user() {
                return Err(SshError::configuration(
                    "OpenSSH authentication requires a user certificate",
                ));
            }
            if key.public_key().key_data() != certificate.public_key() {
                return Err(SshError::configuration(
                    "OpenSSH certificate does not match the private key",
                ));
            }
            let result = handle
                .authenticate_openssh_cert(username, Arc::new(key), *certificate)
                .await
                .map_err(|error| authentication_source_error(error.to_string(), error))?;
            Ok(auth_outcome(result))
        }
        AuthMethod::KeyboardInteractive {
            submethods,
            handler,
        } => authenticate_keyboard_interactive(handle, username, submethods, handler).await,
        AuthMethod::Agent { socket, rsa_hash } => {
            authenticate_agent(handle, username, socket, rsa_hash).await
        }
    }
}

async fn authenticate_private_key(
    handle: &mut client::Handle<ClientHandler>,
    username: &str,
    key: Box<russh::keys::PrivateKey>,
    passphrase: Option<crate::SecretString>,
    rsa_hash: RsaHashAlgorithm,
) -> Result<AuthOutcome, SshError> {
    let key = decrypt_private_key(key, passphrase)?;
    let hash_algorithms = rsa_hash_candidates(handle, key.algorithm(), rsa_hash).await?;
    let key = Arc::new(key);
    let mut last_outcome = AuthOutcome::default();
    for hash_alg in hash_algorithms {
        let result = handle
            .authenticate_publickey(
                username,
                PrivateKeyWithHashAlg::new(Arc::clone(&key), hash_alg),
            )
            .await
            .map_err(|error| authentication_source_error(error.to_string(), error))?;
        last_outcome = auth_outcome(result);
        if last_outcome.accepted {
            return Ok(last_outcome);
        }
    }
    Ok(last_outcome)
}

fn decrypt_private_key(
    key: Box<russh::keys::PrivateKey>,
    passphrase: Option<crate::SecretString>,
) -> Result<russh::keys::PrivateKey, SshError> {
    if !key.is_encrypted() {
        return Ok(*key);
    }
    let Some(passphrase) = passphrase else {
        return Err(SshError::configuration(
            "encrypted private key requires a passphrase",
        ));
    };
    key.decrypt(passphrase.as_str()).map_err(|error| {
        SshError::from_source(
            crate::ErrorKind::Configuration,
            format!("failed to decrypt private key: {error}"),
            error,
        )
    })
}

async fn rsa_hash_candidates(
    handle: &client::Handle<ClientHandler>,
    algorithm: Algorithm,
    selection: RsaHashAlgorithm,
) -> Result<Vec<Option<HashAlg>>, SshError> {
    if !matches!(algorithm, Algorithm::Rsa { .. }) {
        return Ok(vec![None]);
    }
    match selection {
        RsaHashAlgorithm::Sha256 => Ok(vec![Some(HashAlg::Sha256)]),
        RsaHashAlgorithm::Sha512 => Ok(vec![Some(HashAlg::Sha512)]),
        RsaHashAlgorithm::LegacySha1 => Ok(vec![None]),
        RsaHashAlgorithm::Auto => {
            let supported = handle
                .best_supported_rsa_hash()
                .await
                .map_err(|error| authentication_source_error(error.to_string(), error))?;
            Ok(match supported {
                Some(Some(hash_alg)) => vec![Some(hash_alg)],
                Some(None) => vec![None],
                None => vec![Some(HashAlg::Sha512), Some(HashAlg::Sha256)],
            })
        }
    }
}

async fn authenticate_keyboard_interactive(
    handle: &mut client::Handle<ClientHandler>,
    username: &str,
    submethods: Option<String>,
    handler: Arc<dyn crate::KeyboardInteractiveHandler>,
) -> Result<AuthOutcome, SshError> {
    let mut response = handle
        .authenticate_keyboard_interactive_start(username, submethods)
        .await
        .map_err(|error| authentication_source_error(error.to_string(), error))?;
    loop {
        response = match response {
            KeyboardInteractiveAuthResponse::Success => {
                return Ok(AuthOutcome {
                    accepted: true,
                    ..AuthOutcome::default()
                });
            }
            KeyboardInteractiveAuthResponse::Failure {
                remaining_methods,
                partial_success,
            } => {
                return Ok(AuthOutcome {
                    remaining_methods: server_auth_methods(&remaining_methods),
                    partial_success,
                    ..AuthOutcome::default()
                });
            }
            KeyboardInteractiveAuthResponse::InfoRequest {
                name,
                instructions,
                prompts,
            } => {
                let challenge = KeyboardInteractiveChallenge {
                    name,
                    instructions,
                    prompts: prompts
                        .iter()
                        .map(|prompt| KeyboardInteractivePrompt {
                            text: prompt.prompt.clone(),
                            echo: prompt.echo,
                        })
                        .collect(),
                };
                let prompt_count = challenge.prompts.len();
                let responses = handler.respond(challenge).await?;
                if responses.len() != prompt_count {
                    return Err(SshError::configuration(format!(
                        "keyboard-interactive handler returned {} responses for {prompt_count} prompts",
                        responses.len()
                    )));
                }
                let responses = responses
                    .iter()
                    .map(|response| response.as_str().to_owned())
                    .collect();
                handle
                    .authenticate_keyboard_interactive_respond(responses)
                    .await
                    .map_err(|error| authentication_source_error(error.to_string(), error))?
            }
        };
    }
}

type DynamicAgent = AgentClient<Box<dyn AgentStream + Send + Unpin + 'static>>;

#[cfg(unix)]
async fn connect_agent(socket: Option<std::path::PathBuf>) -> Result<DynamicAgent, SshError> {
    let agent = match socket {
        Some(path) => AgentClient::connect_uds(path).await,
        None => AgentClient::connect_env().await,
    }
    .map_err(|error| authentication_source_error(error.to_string(), error))?;
    Ok(agent.dynamic())
}

#[cfg(windows)]
async fn connect_agent(socket: Option<std::path::PathBuf>) -> Result<DynamicAgent, SshError> {
    let agent = match socket {
        Some(path) => AgentClient::connect_named_pipe(path)
            .await
            .map_err(|error| authentication_source_error(error.to_string(), error))?
            .dynamic(),
        None => AgentClient::connect_pageant().await.dynamic(),
    };
    Ok(agent)
}

async fn authenticate_agent(
    handle: &mut client::Handle<ClientHandler>,
    username: &str,
    socket: Option<std::path::PathBuf>,
    rsa_hash: RsaHashAlgorithm,
) -> Result<AuthOutcome, SshError> {
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (handle, username, socket, rsa_hash);
        return Err(SshError::configuration(
            "SSH agent authentication is currently supported on Unix and Windows only",
        ));
    }

    #[cfg(any(unix, windows))]
    {
        let mut agent = connect_agent(socket).await?;
        let identities = agent
            .request_identities()
            .await
            .map_err(|error| authentication_source_error(error.to_string(), error))?;
        let mut last_outcome = AuthOutcome::default();
        for public_key in identities {
            let hash_algorithms =
                rsa_hash_candidates(handle, public_key.algorithm(), rsa_hash).await?;
            for hash_alg in hash_algorithms {
                let result = handle
                    .authenticate_publickey_with(username, public_key.clone(), hash_alg, &mut agent)
                    .await
                    .map_err(|error| authentication_source_error(error.to_string(), error))?;
                last_outcome = auth_outcome(result);
                if last_outcome.accepted {
                    return Ok(last_outcome);
                }
            }
        }
        Ok(last_outcome)
    }
}

fn auth_outcome(result: AuthResult) -> AuthOutcome {
    match result {
        AuthResult::Success => AuthOutcome {
            accepted: true,
            ..AuthOutcome::default()
        },
        AuthResult::Failure {
            remaining_methods,
            partial_success,
        } => AuthOutcome {
            remaining_methods: server_auth_methods(&remaining_methods),
            partial_success,
            ..AuthOutcome::default()
        },
    }
}

fn server_auth_methods(methods: &russh::MethodSet) -> Vec<ServerAuthMethod> {
    methods
        .iter()
        .map(|method| match method {
            russh::MethodKind::None => ServerAuthMethod::None,
            russh::MethodKind::Password => ServerAuthMethod::Password,
            russh::MethodKind::PublicKey => ServerAuthMethod::PublicKey,
            russh::MethodKind::HostBased => ServerAuthMethod::HostBased,
            russh::MethodKind::KeyboardInteractive => ServerAuthMethod::KeyboardInteractive,
        })
        .collect()
}

fn authentication_source_error<E>(message: String, source: E) -> SshError
where
    E: std::error::Error + Send + Sync + 'static,
{
    SshError::from_source(crate::ErrorKind::Authentication, message, source)
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
    use std::borrow::Cow;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use russh::client::Handler as _;
    use russh::keys::ssh_key::certificate::Builder as CertificateBuilder;
    use russh::keys::{Algorithm, PrivateKey, PublicKey};
    use russh::server::{self, Auth, Response};
    use russh::{ChannelMsg, CryptoVec};
    use tokio::net::TcpListener;

    use super::{ClientHandler, SshSession};
    use crate::{
        AuthMethod, AuthMethodKind, AuthenticationPlan, ErrorKind, HostKeyDecision,
        HostKeyVerifier, KnownHostKeyVerifier, RsaHashAlgorithm, SecretString, ServerAuthMethod,
        SshConfig, SshError, TofuHostKeyVerifier,
    };

    const TEST_RSA_PRIVATE_KEY: &str = r#"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEAvgVmS5nz+Mc5HfPp5Kr4O+gReoQoWPrMNJB4NFTN/vRn/js1aaLc
TEEwvxqBdoGbPOtq7S5nDHLkqNoczVciG9/NPndrSU+Gr87JDqvrOpCvoi7XRGo3QXtO9f
QbyPD5JdDaDknMQhj5oyz0jNCMv6pesii/r3u4t5X6iSUVxIhgbRAy9t2uldw0OjBDt1yU
8bRwWveGmKs49F9SmzbB1AbqDVNwmqVfzpB0L37OzlECqHDggo6LO+RqEccNFZPNMcuCNi
OeOsYaDQ2ukjd5S90/tUW7xAGk6KkCYQEqwf0Ob+zd1wHhsXZBGq3CdDwTIXvym/AoIIXN
I9JMdRIwqQAAA9BzwvaJc8L2iQAAAAdzc2gtcnNhAAABAQC+BWZLmfP4xzkd8+nkqvg76B
F6hChY+sw0kHg0VM3+9Gf+OzVpotxMQTC/GoF2gZs862rtLmcMcuSo2hzNVyIb380+d2tJ
T4avzskOq+s6kK+iLtdEajdBe0719BvI8Pkl0NoOScxCGPmjLPSM0Iy/ql6yKL+ve7i3lf
qJJRXEiGBtEDL23a6V3DQ6MEO3XJTxtHBa94aYqzj0X1KbNsHUBuoNU3CapV/OkHQvfs7O
UQKocOCCjos75GoRxw0Vk80xy4I2I546xhoNDa6SN3lL3T+1RbvEAaToqQJhASrB/Q5v7N
3XAeGxdkEarcJ0PBMhe/Kb8Cgghc0j0kx1EjCpAAAAAwEAAQAAAQAnqhjgTxKOK4fQqMl5
4fZPCvIbENsbN77Ieh+dTNZzEbFjcBiGJGi3wiPawD2l7wfof3uiZr076/+u/1hjxHxqNR
0ynNrYQrFqoU92sIw5fVosEHr+3O0LziF9Vac3GpXnPuFFekIYyf3SAeBKRH4cxANgTQE2
MC0upS/W0NbqXvEtxBfBWxXXfYFJXJh/NPo6wIGhUaruFLkA9YjabfshRZZ7xMXFaFQgSF
lyiUFC/Q3m5Q51aBETdShIE7xAcd8HXS8/DeoZU/HB9nGgHeMMfpFpuojeGjjg1DDFt8sk
1OKxelTpzp+qhe2UKH/yS61U6B4Pa5k6Cr90TwMXzCMBAAAAgF8UJVRR4hWdkvfxjDTR7m
LCyvsLNSdQuDMK35mxb1Sr9L9GrtVIW8s6M4dgiMBgkHE5gy9X4n2WeO6UNMNxmhT2Yu6D
HoCE6pIcB8w3a7OybhAmMQFYcsvZbqYKmzxDmPLng5nn05CzWIpSEteIofwBBfDrwebUcJ
KrutbWWDemAAAAgQDc4skOOA5c3IU10NhgRYDK8p30rQcQWLh5cCaXS7rPZZRR24T+BcDm
rBmDK26ONP5lrEeiGhxg9MKy39otfhRoM2FPlYc5DFbyLahFh0LqZV9uDHghq4oWdNEc9v
pSfIHJSRZBOzEWwILO3iy6Up44DUV2uLoXFlVD8Ux5PkeuFQAAAIEA3DqI6VvzHUczMvrm
E24Db0dYbBNhHLq3CCsF8mdPOudl37q6W6KzfXb3NWDU5aWhV78GaVP2r01Ngoy4/lpzui
eBba68j5AUhmCXC81I7x4nBxl1hnjSJgyZlnuILRGuoPP+UHrQUOh2cEBIXY/iISGVpHeK
Vv9WFaQHofuFcUUAAAAaeHNzaC1ydXN0LWxpYiB0ZXN0IGZpeHR1cmUB
-----END OPENSSH PRIVATE KEY-----"#;

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

    struct DirectTcpipServer;

    impl server::Handler for DirectTcpipServer {
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

        async fn channel_open_direct_tcpip(
            &mut self,
            mut channel: russh::Channel<russh::server::Msg>,
            host_to_connect: &str,
            port_to_connect: u32,
            _originator_address: &str,
            _originator_port: u32,
            session: &mut server::Session,
        ) -> Result<bool, Self::Error> {
            if host_to_connect != "echo.internal" || port_to_connect != 7 {
                return Ok(false);
            }

            let channel_id = channel.id();
            let handle = session.handle();
            tokio::spawn(async move {
                while let Some(message) = channel.wait().await {
                    match message {
                        ChannelMsg::Data { data } => {
                            let _ = handle
                                .data(channel_id, CryptoVec::from(data.to_vec()))
                                .await;
                        }
                        ChannelMsg::Eof => {
                            let _ = handle.eof(channel_id).await;
                            let _ = handle.close(channel_id).await;
                            break;
                        }
                        ChannelMsg::Close => break,
                        _ => {}
                    }
                }
            });
            Ok(true)
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

    struct PublicKeyServer {
        expected: PublicKey,
    }

    impl server::Handler for PublicKeyServer {
        type Error = russh::Error;

        async fn auth_publickey(
            &mut self,
            _user: &str,
            public_key: &PublicKey,
        ) -> Result<Auth, Self::Error> {
            Ok(if public_key.key_data() == self.expected.key_data() {
                Auth::Accept
            } else {
                Auth::reject()
            })
        }
    }

    struct CertificateServer;

    impl server::Handler for CertificateServer {
        type Error = russh::Error;

        async fn auth_openssh_certificate(
            &mut self,
            user: &str,
            certificate: &russh::keys::Certificate,
        ) -> Result<Auth, Self::Error> {
            Ok(
                if certificate.cert_type().is_user()
                    && certificate
                        .valid_principals()
                        .iter()
                        .any(|principal| principal == user)
                {
                    Auth::Accept
                } else {
                    Auth::reject()
                },
            )
        }
    }

    struct KeyboardInteractiveServer;

    impl server::Handler for KeyboardInteractiveServer {
        type Error = russh::Error;

        async fn auth_keyboard_interactive<'a>(
            &'a mut self,
            _user: &str,
            _submethods: &str,
            response: Option<Response<'a>>,
        ) -> Result<Auth, Self::Error> {
            let Some(mut response) = response else {
                return Ok(Auth::Partial {
                    name: Cow::Borrowed("Verification"),
                    instructions: Cow::Borrowed("Enter the one-time code"),
                    prompts: Cow::Owned(vec![(Cow::Borrowed("Code: "), false)]),
                });
            };
            let accepted = response
                .next()
                .is_some_and(|answer| answer.as_ref() == b"654321")
                && response.next().is_none();
            Ok(if accepted {
                Auth::Accept
            } else {
                Auth::reject()
            })
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
    async fn direct_tcpip_channel_round_trips_data() {
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
            server::run_stream(server_config, socket, DirectTcpipServer)
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
        let channel = session.open_direct_tcpip("echo.internal", 7).await.unwrap();
        let mut stream = channel.into_stream();
        stream.write(b"hello through ssh\n").await.unwrap();
        let mut buffer = [0_u8; 18];
        let read = stream.read(&mut buffer).await.unwrap();
        assert_eq!(&buffer[..read], b"hello through ssh\n");
        session.disconnect().await.unwrap();
    }

    #[tokio::test]
    async fn changed_key_error_exposes_a_structured_observation() {
        let expected_key = PrivateKey::random(
            &mut russh::keys::ssh_key::rand_core::OsRng,
            Algorithm::Ed25519,
        )
        .unwrap()
        .public_key()
        .clone();
        let presented_key = PrivateKey::random(
            &mut russh::keys::ssh_key::rand_core::OsRng,
            Algorithm::Ed25519,
        )
        .unwrap()
        .public_key()
        .clone();
        let mut verifier = KnownHostKeyVerifier::new();
        verifier.insert_key("server.example.com", 22, &expected_key);
        let mut handler = ClientHandler {
            host: "server.example.com".to_owned(),
            port: 22,
            verifier: Arc::new(verifier),
        };

        let error = handler.check_server_key(&presented_key).await.unwrap_err();
        let observation = error.host_key_observation().unwrap();
        assert_eq!(observation.decision, HostKeyDecision::Changed);
        assert_eq!(observation.host, "server.example.com");
        assert_eq!(observation.expected_fingerprints.len(), 1);
        assert!(observation.presented_fingerprint.starts_with("SHA256:"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tofu_accepts_and_records_the_first_server_key() {
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

        let verifier = TofuHostKeyVerifier::default();
        let retained_verifier = verifier.clone();
        let mut config = SshConfig::new("127.0.0.1", "alice").unwrap();
        config.port = address.port();
        config.connect_timeout = Duration::from_secs(5);

        let session = SshSession::connect(config, verifier, AuthMethod::password("test-password"))
            .await
            .unwrap();
        let snapshot = retained_verifier.snapshot().unwrap();
        assert_eq!(
            snapshot
                .verify("127.0.0.1", address.port(), server_key.public_key())
                .unwrap(),
            HostKeyDecision::Trusted
        );
        session.disconnect().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn keyboard_interactive_answers_server_challenges() {
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
            server::run_stream(server_config, socket, KeyboardInteractiveServer)
                .await
                .unwrap();
        });

        let mut verifier = KnownHostKeyVerifier::new();
        verifier.insert_key("127.0.0.1", address.port(), server_key.public_key());
        let mut config = SshConfig::new("127.0.0.1", "alice").unwrap();
        config.port = address.port();
        config.connect_timeout = Duration::from_secs(5);
        let challenged = Arc::new(AtomicBool::new(false));
        let challenged_in_handler = Arc::clone(&challenged);
        let auth = AuthMethod::keyboard_interactive(move |challenge| {
            let challenged = Arc::clone(&challenged_in_handler);
            async move {
                assert_eq!(challenge.name, "Verification");
                assert_eq!(challenge.prompts.len(), 1);
                assert!(!challenge.prompts[0].echo);
                challenged.store(true, Ordering::SeqCst);
                Ok::<_, SshError>(vec![SecretString::new("654321")])
            }
        });

        let session = SshSession::connect(config, verifier, auth).await.unwrap();
        assert!(challenged.load(Ordering::SeqCst));
        session.disconnect().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rsa_sha512_private_key_authenticates() {
        let server_key = PrivateKey::random(
            &mut russh::keys::ssh_key::rand_core::OsRng,
            Algorithm::Ed25519,
        )
        .unwrap();
        let client_key = PrivateKey::from_openssh(TEST_RSA_PRIVATE_KEY).unwrap();
        let expected = client_key.public_key().clone();
        let mut server_config = server::Config::default();
        server_config.keys.push(server_key.clone());
        let server_config = Arc::new(server_config);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            server::run_stream(server_config, socket, PublicKeyServer { expected })
                .await
                .unwrap();
        });

        let mut verifier = KnownHostKeyVerifier::new();
        verifier.insert_key("127.0.0.1", address.port(), server_key.public_key());
        let mut config = SshConfig::new("127.0.0.1", "alice").unwrap();
        config.port = address.port();
        config.connect_timeout = Duration::from_secs(5);
        let auth = AuthMethod::private_key_with_rsa_hash(client_key, RsaHashAlgorithm::Sha512);

        let session = SshSession::connect(config, verifier, auth).await.unwrap();
        session.disconnect().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn openssh_user_certificate_authenticates() {
        let server_key = PrivateKey::random(
            &mut russh::keys::ssh_key::rand_core::OsRng,
            Algorithm::Ed25519,
        )
        .unwrap();
        let ca_key = PrivateKey::random(
            &mut russh::keys::ssh_key::rand_core::OsRng,
            Algorithm::Ed25519,
        )
        .unwrap();
        let client_key = PrivateKey::random(
            &mut russh::keys::ssh_key::rand_core::OsRng,
            Algorithm::Ed25519,
        )
        .unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut builder = CertificateBuilder::new(
            vec![7; CertificateBuilder::RECOMMENDED_NONCE_SIZE],
            client_key.public_key(),
            now.saturating_sub(1),
            now + 60,
        )
        .unwrap();
        builder.key_id("alice-test").unwrap();
        builder.valid_principal("alice").unwrap();
        let certificate = builder.sign(&ca_key).unwrap();

        let mut server_config = server::Config::default();
        server_config.keys.push(server_key.clone());
        let server_config = Arc::new(server_config);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            server::run_stream(server_config, socket, CertificateServer)
                .await
                .unwrap();
        });

        let mut verifier = KnownHostKeyVerifier::new();
        verifier.insert_key("127.0.0.1", address.port(), server_key.public_key());
        let mut config = SshConfig::new("127.0.0.1", "alice").unwrap();
        config.port = address.port();
        config.connect_timeout = Duration::from_secs(5);
        let auth = AuthMethod::openssh_certificate(client_key, certificate);

        let session = SshSession::connect(config, verifier, auth).await.unwrap();
        session.disconnect().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn authentication_plan_falls_back_after_an_unavailable_agent() {
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
        let auth = AuthenticationPlan::new([
            AuthMethod::agent_from_socket("/tmp/xssh-rust-lib-missing-agent.sock"),
            AuthMethod::password("test-password"),
        ]);

        let session = SshSession::connect(config, verifier, auth).await.unwrap();
        session.disconnect().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn failed_authentication_exposes_attempts_and_remaining_methods() {
        let server_key = PrivateKey::random(
            &mut russh::keys::ssh_key::rand_core::OsRng,
            Algorithm::Ed25519,
        )
        .unwrap();
        let mut server_config = server::Config::default();
        server_config.keys.push(server_key.clone());
        server_config.auth_rejection_time = Duration::from_millis(1);
        let server_config = Arc::new(server_config);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let _ = server::run_stream(server_config, socket, PasswordServer).await;
        });

        let mut verifier = KnownHostKeyVerifier::new();
        verifier.insert_key("127.0.0.1", address.port(), server_key.public_key());
        let mut config = SshConfig::new("127.0.0.1", "alice").unwrap();
        config.port = address.port();
        config.connect_timeout = Duration::from_secs(5);
        let error =
            match SshSession::connect(config, verifier, AuthMethod::password("wrong-password"))
                .await
            {
                Ok(_) => panic!("authentication unexpectedly succeeded"),
                Err(error) => error,
            };

        assert_eq!(error.kind(), ErrorKind::Authentication);
        let observation = error.authentication_observation().unwrap();
        assert_eq!(observation.attempts.len(), 1);
        assert_eq!(observation.attempts[0].method, AuthMethodKind::Password);
        assert!(observation
            .remaining_methods
            .contains(&ServerAuthMethod::PublicKey));
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
