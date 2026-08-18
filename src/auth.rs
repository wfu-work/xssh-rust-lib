use std::fmt;

use russh::keys::PrivateKey;
use zeroize::{Zeroize, Zeroizing};

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

/// Authentication material passed to an SSH session.
pub enum AuthMethod {
    Password(SecretString),
    PrivateKey {
        key: Box<PrivateKey>,
        passphrase: Option<SecretString>,
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
        }
    }

    pub fn private_key_with_passphrase(key: PrivateKey, passphrase: impl Into<String>) -> Self {
        Self::PrivateKey {
            key: Box::new(key),
            passphrase: Some(SecretString::new(passphrase)),
        }
    }
}

impl fmt::Debug for AuthMethod {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Password(_) => formatter.write_str("Password(REDACTED)"),
            Self::PrivateKey { key, passphrase } => formatter
                .debug_struct("PrivateKey")
                .field("algorithm", &key.algorithm())
                .field("encrypted", &key.is_encrypted())
                .field("passphrase", &passphrase.as_ref().map(|_| "REDACTED"))
                .finish(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AuthMethod, SecretString};

    #[test]
    fn secrets_are_redacted() {
        let secret = SecretString::new("correct horse battery staple");
        assert!(!format!("{secret:?}").contains("correct"));
        assert!(!format!("{}", secret).contains("correct"));
        assert!(format!("{:?}", AuthMethod::password("password")).contains("REDACTED"));
    }
}
