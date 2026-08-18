use std::collections::HashMap;

use russh::keys::{HashAlg, PublicKey};

use crate::SshError;

/// Result of checking a server key against the caller's trust policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostKeyDecision {
    Trusted,
    Unknown,
    Changed,
}

/// Host-key policy implemented by the application or a persistence adapter.
pub trait HostKeyVerifier: Send + Sync {
    fn verify(&self, host: &str, port: u16, key: &PublicKey) -> Result<HostKeyDecision, SshError>;
}

/// Strict in-memory known-hosts verifier.
///
/// It deliberately does not persist keys. A desktop application can load and
/// save these fingerprints through its own encrypted storage adapter.
#[derive(Clone, Debug, Default)]
pub struct KnownHostKeyVerifier {
    entries: HashMap<(String, u16), String>,
}

impl KnownHostKeyVerifier {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, host: impl Into<String>, port: u16, fingerprint: impl Into<String>) {
        self.entries.insert((host.into(), port), fingerprint.into());
    }

    pub fn insert_key(&mut self, host: impl Into<String>, port: u16, key: &PublicKey) {
        self.insert(host, port, fingerprint_sha256(key));
    }

    pub fn expected_fingerprint(&self, host: &str, port: u16) -> Option<&str> {
        self.entries
            .get(&(host.to_owned(), port))
            .map(String::as_str)
    }
}

impl HostKeyVerifier for KnownHostKeyVerifier {
    fn verify(&self, host: &str, port: u16, key: &PublicKey) -> Result<HostKeyDecision, SshError> {
        let Some(expected) = self.expected_fingerprint(host, port) else {
            return Ok(HostKeyDecision::Unknown);
        };

        if expected == fingerprint_sha256(key) {
            Ok(HostKeyDecision::Trusted)
        } else {
            Ok(HostKeyDecision::Changed)
        }
    }
}

pub(crate) fn fingerprint_sha256(key: &PublicKey) -> String {
    key.fingerprint(HashAlg::Sha256).to_string()
}

#[cfg(test)]
mod tests {
    use russh::keys::{Algorithm, PrivateKey};

    use super::{fingerprint_sha256, HostKeyDecision, HostKeyVerifier, KnownHostKeyVerifier};

    #[test]
    fn known_key_can_be_trusted_and_changed_keys_are_rejected() {
        let key = PrivateKey::random(
            &mut russh::keys::ssh_key::rand_core::OsRng,
            Algorithm::Ed25519,
        )
        .unwrap()
        .public_key()
        .clone();
        let other_key = PrivateKey::random(
            &mut russh::keys::ssh_key::rand_core::OsRng,
            Algorithm::Ed25519,
        )
        .unwrap()
        .public_key()
        .clone();
        let mut verifier = KnownHostKeyVerifier::new();
        verifier.insert_key("example.com", 22, &key);

        assert_eq!(
            verifier.verify("example.com", 22, &key).unwrap(),
            HostKeyDecision::Trusted
        );
        assert_eq!(
            verifier.verify("example.com", 22, &other_key).unwrap(),
            HostKeyDecision::Changed
        );
        assert_eq!(
            verifier.verify("other.example.com", 22, &key).unwrap(),
            HostKeyDecision::Unknown
        );
        assert!(fingerprint_sha256(&key).starts_with("SHA256:"));
    }
}
