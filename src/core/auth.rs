use std::fmt;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;

use russh::keys::{Certificate, PrivateKey};
use zeroize::{Zeroize, Zeroizing};

use crate::SshError;

/// A string that is cleared when dropped and never displayed in clear text.
pub struct SecretString(Zeroizing<String>);

impl SecretString {
    pub fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    pub(crate) fn as_str(&self) -> &str {
        self.0.as_str()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Clone for SecretString {
    fn clone(&self) -> Self {
        Self::new(self.as_str())
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretString(REDACTED)")
    }
}

impl fmt::Display for SecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// RSA signature hash selection for public-key authentication.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum RsaHashAlgorithm {
    /// Ask the server for its best supported RSA signature algorithm.
    #[default]
    Auto,
    Sha256,
    Sha512,
    /// The legacy `ssh-rsa` SHA-1 signature algorithm.
    LegacySha1,
}

/// Authentication material passed to an SSH session.
pub enum AuthMethod {
    Password(SecretString),
    PrivateKey {
        key: Box<PrivateKey>,
        passphrase: Option<SecretString>,
        rsa_hash: RsaHashAlgorithm,
    },
    OpenSshCertificate {
        key: Box<PrivateKey>,
        certificate: Box<Certificate>,
        passphrase: Option<SecretString>,
    },
    KeyboardInteractive {
        submethods: Option<String>,
        handler: Arc<dyn KeyboardInteractiveHandler>,
    },
    Agent {
        socket: Option<PathBuf>,
        rsa_hash: RsaHashAlgorithm,
    },
}

impl AuthMethod {
    pub fn password(password: impl Into<String>) -> Self {
        Self::Password(SecretString::new(password))
    }

    pub fn private_key(key: PrivateKey) -> Self {
        Self::PrivateKey {
            key: Box::new(key),
            passphrase: None,
            rsa_hash: RsaHashAlgorithm::Auto,
        }
    }

    pub fn private_key_with_passphrase(key: PrivateKey, passphrase: impl Into<String>) -> Self {
        Self::with_key_options(
            key,
            Some(SecretString::new(passphrase)),
            RsaHashAlgorithm::Auto,
        )
    }

    pub fn private_key_with_rsa_hash(key: PrivateKey, rsa_hash: RsaHashAlgorithm) -> Self {
        Self::with_key_options(key, None, rsa_hash)
    }

    pub fn private_key_with_passphrase_and_rsa_hash(
        key: PrivateKey,
        passphrase: impl Into<String>,
        rsa_hash: RsaHashAlgorithm,
    ) -> Self {
        Self::with_key_options(key, Some(SecretString::new(passphrase)), rsa_hash)
    }

    fn with_key_options(
        key: PrivateKey,
        passphrase: Option<SecretString>,
        rsa_hash: RsaHashAlgorithm,
    ) -> Self {
        Self::PrivateKey {
            key: Box::new(key),
            passphrase,
            rsa_hash,
        }
    }

    pub fn openssh_certificate(key: PrivateKey, certificate: Certificate) -> Self {
        Self::OpenSshCertificate {
            key: Box::new(key),
            certificate: Box::new(certificate),
            passphrase: None,
        }
    }

    pub fn openssh_certificate_with_passphrase(
        key: PrivateKey,
        certificate: Certificate,
        passphrase: impl Into<String>,
    ) -> Self {
        Self::OpenSshCertificate {
            key: Box::new(key),
            certificate: Box::new(certificate),
            passphrase: Some(SecretString::new(passphrase)),
        }
    }

    pub fn keyboard_interactive<F, Fut>(handler: F) -> Self
    where
        F: Fn(KeyboardInteractiveChallenge) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Vec<SecretString>, SshError>> + Send + 'static,
    {
        Self::KeyboardInteractive {
            submethods: None,
            handler: Arc::new(handler),
        }
    }

    pub fn keyboard_interactive_with_submethods<F, Fut>(
        submethods: impl Into<String>,
        handler: F,
    ) -> Self
    where
        F: Fn(KeyboardInteractiveChallenge) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Vec<SecretString>, SshError>> + Send + 'static,
    {
        Self::KeyboardInteractive {
            submethods: Some(submethods.into()),
            handler: Arc::new(handler),
        }
    }

    pub fn keyboard_interactive_handler<H>(handler: H) -> Self
    where
        H: KeyboardInteractiveHandler + 'static,
    {
        Self::KeyboardInteractive {
            submethods: None,
            handler: Arc::new(handler),
        }
    }

    /// Use `SSH_AUTH_SOCK` on Unix or Pageant on Windows.
    pub fn agent() -> Self {
        Self::Agent {
            socket: None,
            rsa_hash: RsaHashAlgorithm::Auto,
        }
    }

    pub fn agent_from_socket(path: impl Into<PathBuf>) -> Self {
        Self::Agent {
            socket: Some(path.into()),
            rsa_hash: RsaHashAlgorithm::Auto,
        }
    }

    pub fn agent_with_rsa_hash(rsa_hash: RsaHashAlgorithm) -> Self {
        Self::Agent {
            socket: None,
            rsa_hash,
        }
    }

    pub fn kind(&self) -> AuthMethodKind {
        match self {
            Self::Password(_) => AuthMethodKind::Password,
            Self::PrivateKey { .. } => AuthMethodKind::PrivateKey,
            Self::OpenSshCertificate { .. } => AuthMethodKind::OpenSshCertificate,
            Self::KeyboardInteractive { .. } => AuthMethodKind::KeyboardInteractive,
            Self::Agent { .. } => AuthMethodKind::Agent,
        }
    }
}

/// A method supplied by the SSH server after an authentication rejection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServerAuthMethod {
    None,
    Password,
    PublicKey,
    HostBased,
    KeyboardInteractive,
}

/// A method from the local authentication plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthMethodKind {
    Password,
    PrivateKey,
    OpenSshCertificate,
    KeyboardInteractive,
    Agent,
}

/// One keyboard-interactive prompt supplied by the SSH server.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyboardInteractivePrompt {
    pub text: String,
    pub echo: bool,
}

/// A keyboard-interactive challenge suitable for a GPUI prompt surface.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyboardInteractiveChallenge {
    pub name: String,
    pub instructions: String,
    pub prompts: Vec<KeyboardInteractivePrompt>,
}

/// Async callback used to answer keyboard-interactive challenges.
pub trait KeyboardInteractiveHandler: Send + Sync {
    fn respond(
        &self,
        challenge: KeyboardInteractiveChallenge,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<SecretString>, SshError>> + Send>>;
}

impl<F, Fut> KeyboardInteractiveHandler for F
where
    F: Fn(KeyboardInteractiveChallenge) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<Vec<SecretString>, SshError>> + Send + 'static,
{
    fn respond(
        &self,
        challenge: KeyboardInteractiveChallenge,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<SecretString>, SshError>> + Send>> {
        Box::pin(self(challenge))
    }
}

/// Ordered authentication methods attempted by [`crate::SshSession`].
#[derive(Debug, Default)]
pub struct AuthenticationPlan {
    methods: Vec<AuthMethod>,
}

impl AuthenticationPlan {
    pub fn new(methods: impl IntoIterator<Item = AuthMethod>) -> Self {
        Self {
            methods: methods.into_iter().collect(),
        }
    }

    pub fn single(method: AuthMethod) -> Self {
        Self::new([method])
    }

    pub fn push(&mut self, method: AuthMethod) {
        self.methods.push(method);
    }

    pub fn is_empty(&self) -> bool {
        self.methods.is_empty()
    }

    pub(crate) fn into_methods(self) -> Vec<AuthMethod> {
        self.methods
    }
}

impl From<AuthMethod> for AuthenticationPlan {
    fn from(method: AuthMethod) -> Self {
        Self::single(method)
    }
}

/// One non-secret result from an authentication attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticationAttempt {
    pub method: AuthMethodKind,
    pub accepted: bool,
    pub partial_success: bool,
    pub remaining_methods: Vec<ServerAuthMethod>,
    pub error: Option<String>,
}

/// Structured authentication state attached to an [`SshError`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AuthenticationObservation {
    pub attempts: Vec<AuthenticationAttempt>,
    pub remaining_methods: Vec<ServerAuthMethod>,
    pub partial_success: bool,
}

impl AuthenticationObservation {
    pub(crate) fn record_failure(
        &mut self,
        method: AuthMethodKind,
        remaining_methods: Vec<ServerAuthMethod>,
        partial_success: bool,
    ) {
        self.remaining_methods = remaining_methods.clone();
        self.partial_success = partial_success;
        self.attempts.push(AuthenticationAttempt {
            method,
            accepted: false,
            partial_success,
            remaining_methods,
            error: None,
        });
    }

    pub(crate) fn record_error(&mut self, method: AuthMethodKind, error: &SshError) {
        self.attempts.push(AuthenticationAttempt {
            method,
            accepted: false,
            partial_success: false,
            remaining_methods: Vec::new(),
            error: Some(error.message().to_owned()),
        });
    }
}

impl fmt::Debug for AuthMethod {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Password(_) => formatter.write_str("Password(REDACTED)"),
            Self::PrivateKey {
                key,
                passphrase,
                rsa_hash,
            } => formatter
                .debug_struct("PrivateKey")
                .field("algorithm", &key.algorithm())
                .field("encrypted", &key.is_encrypted())
                .field("rsa_hash", rsa_hash)
                .field("passphrase", &passphrase.as_ref().map(|_| "REDACTED"))
                .finish(),
            Self::OpenSshCertificate {
                key,
                certificate,
                passphrase,
            } => formatter
                .debug_struct("OpenSshCertificate")
                .field("key_algorithm", &key.algorithm())
                .field("certificate_algorithm", &certificate.algorithm())
                .field("certificate_key_id", &certificate.key_id())
                .field("encrypted", &key.is_encrypted())
                .field("passphrase", &passphrase.as_ref().map(|_| "REDACTED"))
                .finish(),
            Self::KeyboardInteractive { submethods, .. } => formatter
                .debug_struct("KeyboardInteractive")
                .field("submethods", submethods)
                .field("handler", &"configured")
                .finish(),
            Self::Agent { socket, rsa_hash } => formatter
                .debug_struct("Agent")
                .field("socket", socket)
                .field("rsa_hash", rsa_hash)
                .finish(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AuthMethod, AuthenticationPlan, RsaHashAlgorithm, SecretString};

    #[test]
    fn secrets_are_redacted() {
        let secret = SecretString::new("correct horse battery staple");
        assert!(!format!("{secret:?}").contains("correct"));
        assert!(!format!("{}", secret).contains("correct"));
        assert!(format!("{:?}", AuthMethod::password("password")).contains("REDACTED"));
        assert!(format!("{:?}", AuthMethod::agent()).contains("Agent"));
    }

    #[test]
    fn authentication_plan_preserves_fallback_order() {
        let plan = AuthenticationPlan::new([
            AuthMethod::password("password"),
            AuthMethod::agent_with_rsa_hash(RsaHashAlgorithm::Sha512),
        ]);
        assert!(!plan.is_empty());
        assert_eq!(plan.into_methods().len(), 2);
    }
}
