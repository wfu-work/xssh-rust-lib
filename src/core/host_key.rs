use std::fs;
use std::path::Path;
use std::str::FromStr;
use std::sync::{Arc, RwLock};

use base64ct::{Base64, Base64Unpadded, Encoding};
use hmac::{Hmac, Mac};
use russh::keys::ssh_key::known_hosts::{Entry, Marker};
use russh::keys::{HashAlg, PublicKey};
use sha1::Sha1;

use crate::SshError;

/// Result of checking a server key against the caller's trust policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostKeyDecision {
    Trusted,
    Unknown,
    Changed,
    Revoked,
}

/// A structured result that can be shown in a trust/TOFU confirmation UI.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostKeyObservation {
    pub host: String,
    pub port: u16,
    pub decision: HostKeyDecision,
    pub presented_fingerprint: String,
    pub expected_fingerprints: Vec<String>,
    pub matched_lines: Vec<usize>,
}

impl HostKeyObservation {
    fn new(host: &str, port: u16, key: &PublicKey, decision: HostKeyDecision) -> Self {
        Self {
            host: host.to_owned(),
            port,
            decision,
            presented_fingerprint: fingerprint_sha256(key),
            expected_fingerprints: Vec::new(),
            matched_lines: Vec::new(),
        }
    }
}

/// Marker used by an OpenSSH `known_hosts` entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KnownHostMarker {
    CertificateAuthority,
    Revoked,
}

/// One parsed OpenSSH `known_hosts` entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KnownHostEntry {
    host_patterns: String,
    marker: Option<KnownHostMarker>,
    fingerprint: String,
    public_key: String,
    line: usize,
}

impl KnownHostEntry {
    pub fn host_patterns(&self) -> &str {
        &self.host_patterns
    }

    pub fn marker(&self) -> Option<KnownHostMarker> {
        self.marker
    }

    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    pub fn line(&self) -> usize {
        self.line
    }

    pub fn public_key(&self) -> Option<&str> {
        (!self.public_key.is_empty()).then_some(self.public_key.as_str())
    }

    fn to_line(&self) -> Option<String> {
        if self.public_key.is_empty() {
            return None;
        }
        let marker = match self.marker {
            Some(KnownHostMarker::CertificateAuthority) => "@cert-authority ",
            Some(KnownHostMarker::Revoked) => "@revoked ",
            None => "",
        };
        Some(format!(
            "{marker}{} {}",
            self.host_patterns, self.public_key
        ))
    }
}

/// Parsed known-hosts data owned by the caller.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct KnownHosts {
    entries: Vec<KnownHostEntry>,
}

impl KnownHosts {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn parse(input: &str) -> Result<Self, SshError> {
        let mut entries = Vec::new();
        for (line_index, raw_line) in input.lines().enumerate() {
            let line_number = line_index + 1;
            let line = raw_line
                .split_once('#')
                .map_or(raw_line, |(content, _)| content)
                .trim();
            if line.is_empty() {
                continue;
            }

            let entry = Entry::from_str(line).map_err(|error| {
                SshError::configuration(format!(
                    "invalid known_hosts entry on line {line_number}: {error}"
                ))
                .with_path(format!("known_hosts:{line_number}"))
            })?;
            let marker = match entry.marker() {
                Some(Marker::CertAuthority) => Some(KnownHostMarker::CertificateAuthority),
                Some(Marker::Revoked) => Some(KnownHostMarker::Revoked),
                None => None,
            };
            let public_key = entry.public_key().to_openssh().map_err(|error| {
                SshError::configuration(format!(
                    "invalid known_hosts public key on line {line_number}: {error}"
                ))
                .with_path(format!("known_hosts:{line_number}"))
            })?;
            entries.push(KnownHostEntry {
                host_patterns: entry.host_patterns().to_string(),
                marker,
                fingerprint: fingerprint_sha256(entry.public_key()),
                public_key,
                line: line_number,
            });
        }
        Ok(Self { entries })
    }

    pub fn read_file(path: impl AsRef<Path>) -> Result<Self, SshError> {
        let path = path.as_ref();
        let input = fs::read_to_string(path).map_err(|error| {
            SshError::configuration(format!("failed to read known_hosts: {error}"))
                .with_path(path.display().to_string())
        })?;
        Self::parse(&input).map_err(|error| error.with_path(path.display().to_string()))
    }

    pub fn entries(&self) -> &[KnownHostEntry] {
        &self.entries
    }

    pub fn push_key(&mut self, host: &str, port: u16, key: &PublicKey) {
        let host_patterns = host_token(host, port);
        let public_key = key
            .to_openssh()
            .expect("SSH public key encoding should be infallible for a verified key");
        self.entries.push(KnownHostEntry {
            host_patterns,
            marker: None,
            fingerprint: fingerprint_sha256(key),
            public_key,
            line: 0,
        });
    }

    fn replace_entry(&mut self, entry: KnownHostEntry) {
        self.entries.retain(|existing| {
            existing.marker.is_some() || existing.host_patterns != entry.host_patterns
        });
        self.entries.push(entry);
    }

    /// Render entries that contain a public key in OpenSSH format.
    pub fn to_openssh(&self) -> String {
        let lines: Vec<String> = self
            .entries
            .iter()
            .filter_map(KnownHostEntry::to_line)
            .collect();
        if lines.is_empty() {
            String::new()
        } else {
            format!("{}\n", lines.join("\n"))
        }
    }
}

/// Host-key policy implemented by the application or a persistence adapter.
pub trait HostKeyVerifier: Send + Sync {
    fn verify(&self, host: &str, port: u16, key: &PublicKey) -> Result<HostKeyDecision, SshError>;

    /// Return details suitable for a confirmation UI. Custom verifiers that
    /// only implement `verify` get a conservative observation without
    /// expected fingerprints; known-hosts verifiers override this method.
    fn check(
        &self,
        host: &str,
        port: u16,
        key: &PublicKey,
    ) -> Result<HostKeyObservation, SshError> {
        Ok(HostKeyObservation::new(
            host,
            port,
            key,
            self.verify(host, port, key)?,
        ))
    }
}

/// Strict in-memory known-hosts verifier with OpenSSH pattern and hash support.
#[derive(Clone, Debug, Default)]
pub struct KnownHostKeyVerifier {
    known_hosts: KnownHosts,
}

impl KnownHostKeyVerifier {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_known_hosts(input: &str) -> Result<Self, SshError> {
        Ok(Self {
            known_hosts: KnownHosts::parse(input)?,
        })
    }

    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, SshError> {
        Ok(Self {
            known_hosts: KnownHosts::read_file(path)?,
        })
    }

    pub fn known_hosts(&self) -> &KnownHosts {
        &self.known_hosts
    }

    pub fn insert(&mut self, host: impl Into<String>, port: u16, fingerprint: impl Into<String>) {
        let host = host.into();
        self.known_hosts.replace_entry(KnownHostEntry {
            host_patterns: host_token(&host, port),
            marker: None,
            fingerprint: fingerprint.into(),
            public_key: String::new(),
            line: 0,
        });
    }

    pub fn insert_key(&mut self, host: impl Into<String>, port: u16, key: &PublicKey) {
        let host = host.into();
        self.known_hosts.replace_entry(KnownHostEntry {
            host_patterns: host_token(&host, port),
            marker: None,
            fingerprint: fingerprint_sha256(key),
            public_key: key
                .to_openssh()
                .expect("SSH public key encoding should be infallible for a verified key"),
            line: 0,
        });
    }

    /// Explicitly accept a first-seen key, which is the persistence boundary
    /// used by a confirmation-based TOFU workflow.
    pub fn accept_key(&mut self, host: &str, port: u16, key: &PublicKey) {
        self.known_hosts.push_key(host, port, key);
    }

    pub fn expected_fingerprint(&self, host: &str, port: u16) -> Option<&str> {
        self.known_hosts
            .entries
            .iter()
            .find(|entry| {
                entry.marker.is_none() && host_patterns_match(&entry.host_patterns, host, port)
            })
            .map(|entry| entry.fingerprint.as_str())
    }

    pub fn check(
        &self,
        host: &str,
        port: u16,
        key: &PublicKey,
    ) -> Result<HostKeyObservation, SshError> {
        let presented_fingerprint = fingerprint_sha256(key);
        let mut observation = HostKeyObservation::new(host, port, key, HostKeyDecision::Unknown);
        let mut has_expected_key = false;
        let mut trusted = false;

        for entry in &self.known_hosts.entries {
            if !host_patterns_match(&entry.host_patterns, host, port) {
                continue;
            }
            if entry.line != 0 {
                observation.matched_lines.push(entry.line);
            }
            if entry.marker == Some(KnownHostMarker::Revoked) {
                has_expected_key = true;
                observation
                    .expected_fingerprints
                    .push(entry.fingerprint.clone());
                if entry.fingerprint == presented_fingerprint {
                    observation.decision = HostKeyDecision::Revoked;
                }
                continue;
            }
            if entry.marker == Some(KnownHostMarker::CertificateAuthority) {
                continue;
            }
            has_expected_key = true;
            observation
                .expected_fingerprints
                .push(entry.fingerprint.clone());
            if entry.fingerprint == presented_fingerprint {
                trusted = true;
            }
        }

        if observation.decision == HostKeyDecision::Revoked {
            return Ok(observation);
        }
        observation.decision = if trusted {
            HostKeyDecision::Trusted
        } else if has_expected_key {
            HostKeyDecision::Changed
        } else {
            HostKeyDecision::Unknown
        };
        Ok(observation)
    }
}

impl HostKeyVerifier for KnownHostKeyVerifier {
    fn verify(&self, host: &str, port: u16, key: &PublicKey) -> Result<HostKeyDecision, SshError> {
        Ok(self.check(host, port, key)?.decision)
    }

    fn check(
        &self,
        host: &str,
        port: u16,
        key: &PublicKey,
    ) -> Result<HostKeyObservation, SshError> {
        KnownHostKeyVerifier::check(self, host, port, key)
    }
}

/// Automatic in-memory TOFU verifier.
///
/// The first key for a host is recorded and trusted. A changed or revoked key
/// is never accepted automatically. Call [`TofuHostKeyVerifier::snapshot`] to
/// persist the updated store through an application-owned secure adapter.
#[derive(Clone, Debug)]
pub struct TofuHostKeyVerifier {
    inner: Arc<RwLock<KnownHostKeyVerifier>>,
}

impl Default for TofuHostKeyVerifier {
    fn default() -> Self {
        Self::new(KnownHostKeyVerifier::new())
    }
}

impl TofuHostKeyVerifier {
    pub fn new(verifier: KnownHostKeyVerifier) -> Self {
        Self {
            inner: Arc::new(RwLock::new(verifier)),
        }
    }

    pub fn snapshot(&self) -> Result<KnownHostKeyVerifier, SshError> {
        self.inner
            .read()
            .map(|verifier| verifier.clone())
            .map_err(|_| SshError::configuration("TOFU verifier lock poisoned"))
    }
}

impl HostKeyVerifier for TofuHostKeyVerifier {
    fn verify(&self, host: &str, port: u16, key: &PublicKey) -> Result<HostKeyDecision, SshError> {
        let mut verifier = self
            .inner
            .write()
            .map_err(|_| SshError::configuration("TOFU verifier lock poisoned"))?;
        let observation = verifier.check(host, port, key)?;
        if observation.decision == HostKeyDecision::Unknown {
            verifier.accept_key(host, port, key);
            Ok(HostKeyDecision::Trusted)
        } else {
            Ok(observation.decision)
        }
    }

    fn check(
        &self,
        host: &str,
        port: u16,
        key: &PublicKey,
    ) -> Result<HostKeyObservation, SshError> {
        self.inner
            .read()
            .map_err(|_| SshError::configuration("TOFU verifier lock poisoned"))?
            .check(host, port, key)
    }
}

fn host_token(host: &str, port: u16) -> String {
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    if port == 22 {
        host.to_owned()
    } else {
        format!("[{host}]:{port}")
    }
}

fn host_patterns_match(patterns: &str, host: &str, port: u16) -> bool {
    let candidate = host_token(host, port);
    let mut positive = false;
    for pattern in patterns.split(',') {
        if pattern.is_empty() {
            continue;
        }
        let (negative, pattern) = pattern
            .strip_prefix('!')
            .map_or((false, pattern), |pattern| (true, pattern));
        if single_host_pattern_matches(pattern, &candidate) {
            if negative {
                return false;
            }
            positive = true;
        }
    }
    positive
}

fn single_host_pattern_matches(pattern: &str, candidate: &str) -> bool {
    let Some(hashed) = pattern.strip_prefix("|1|") else {
        return glob_match(pattern, candidate);
    };
    let Some((salt, expected)) = hashed.split_once('|') else {
        return false;
    };
    let (Ok(salt), Ok(expected)) = (decode_base64(salt), decode_base64(expected)) else {
        return false;
    };
    let Ok(mut mac) = Hmac::<Sha1>::new_from_slice(&salt) else {
        return false;
    };
    mac.update(candidate.as_bytes());
    mac.verify_slice(&expected).is_ok()
}

fn decode_base64(value: &str) -> Result<Vec<u8>, base64ct::Error> {
    Base64::decode_vec(value).or_else(|_| Base64Unpadded::decode_vec(value))
}

fn glob_match(pattern: &str, candidate: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let candidate: Vec<char> = candidate.chars().collect();
    let mut table = vec![vec![false; candidate.len() + 1]; pattern.len() + 1];
    table[0][0] = true;
    for (row, character) in pattern.iter().enumerate() {
        for column in 0..=candidate.len() {
            if !table[row][column] {
                continue;
            }
            if *character == '*' {
                table[row + 1][column] = true;
                if column < candidate.len() {
                    table[row][column + 1] = true;
                }
            } else if column < candidate.len()
                && (*character == '?' || *character == candidate[column])
            {
                table[row + 1][column + 1] = true;
            }
        }
    }
    table[pattern.len()][candidate.len()]
}

pub(crate) fn fingerprint_sha256(key: &PublicKey) -> String {
    key.fingerprint(HashAlg::Sha256).to_string()
}

#[cfg(test)]
mod tests {
    use base64ct::{Base64, Encoding};
    use hmac::{Hmac, Mac};
    use russh::keys::{Algorithm, PrivateKey};
    use sha1::Sha1;

    use super::{
        fingerprint_sha256, HostKeyDecision, HostKeyVerifier, KnownHostKeyVerifier, KnownHosts,
        TofuHostKeyVerifier,
    };

    fn key() -> russh::keys::PublicKey {
        PrivateKey::random(
            &mut russh::keys::ssh_key::rand_core::OsRng,
            Algorithm::Ed25519,
        )
        .unwrap()
        .public_key()
        .clone()
    }

    #[test]
    fn known_key_can_be_trusted_and_changed_keys_are_rejected() {
        let first_key = key();
        let other_key = key();
        let mut verifier = KnownHostKeyVerifier::new();
        verifier.insert_key("example.com", 22, &first_key);

        assert_eq!(
            verifier.verify("example.com", 22, &first_key).unwrap(),
            HostKeyDecision::Trusted
        );
        assert_eq!(
            verifier.verify("example.com", 22, &other_key).unwrap(),
            HostKeyDecision::Changed
        );
        assert_eq!(
            verifier
                .verify("other.example.com", 22, &first_key)
                .unwrap(),
            HostKeyDecision::Unknown
        );
        assert!(fingerprint_sha256(&first_key).starts_with("SHA256:"));
    }

    #[test]
    fn parses_nonstandard_ports_wildcards_and_changed_details() {
        let first_key = key();
        let other_key = key();
        let line = format!("[*.example.com]:2200 {}\n", first_key.to_openssh().unwrap());
        let verifier = KnownHostKeyVerifier::from_known_hosts(&line).unwrap();
        let observation = verifier.check("db.example.com", 2200, &other_key).unwrap();
        assert_eq!(observation.decision, HostKeyDecision::Changed);
        assert_eq!(observation.matched_lines, vec![1]);
        assert_eq!(observation.expected_fingerprints.len(), 1);
        assert_eq!(observation.host, "db.example.com");
    }

    #[test]
    fn matches_openssh_hashed_hosts() {
        let key = key();
        let host = "hashed.example.com";
        let salt = b"known-host-salt";
        let mut mac = Hmac::<Sha1>::new_from_slice(salt).unwrap();
        mac.update(host.as_bytes());
        let line = format!(
            "|1|{}|{} {}\n",
            Base64::encode_string(salt),
            Base64::encode_string(&mac.finalize().into_bytes()),
            key.to_openssh().unwrap()
        );
        let verifier = KnownHostKeyVerifier::from_known_hosts(&line).unwrap();
        assert_eq!(
            verifier.verify(host, 22, &key).unwrap(),
            HostKeyDecision::Trusted
        );
    }

    #[test]
    fn revoked_keys_are_never_trusted() {
        let key = key();
        let line = format!("@revoked example.com {}\n", key.to_openssh().unwrap());
        let verifier = KnownHostKeyVerifier::from_known_hosts(&line).unwrap();
        assert_eq!(
            verifier.verify("example.com", 22, &key).unwrap(),
            HostKeyDecision::Revoked
        );
    }

    #[test]
    fn a_different_key_is_changed_when_only_the_old_key_is_revoked() {
        let revoked_key = key();
        let current_key = key();
        let line = format!(
            "@revoked example.com {}\n",
            revoked_key.to_openssh().unwrap()
        );
        let verifier = KnownHostKeyVerifier::from_known_hosts(&line).unwrap();
        assert_eq!(
            verifier.verify("example.com", 22, &current_key).unwrap(),
            HostKeyDecision::Changed
        );
    }

    #[test]
    fn tofu_records_unknown_keys_and_exposes_a_snapshot() {
        let first_key = key();
        let other_key = key();
        let verifier = TofuHostKeyVerifier::default();
        assert_eq!(
            verifier
                .verify("first.example.com", 22, &first_key)
                .unwrap(),
            HostKeyDecision::Trusted
        );
        let snapshot = verifier.snapshot().unwrap();
        assert_eq!(
            snapshot
                .verify("first.example.com", 22, &first_key)
                .unwrap(),
            HostKeyDecision::Trusted
        );
        assert_eq!(
            snapshot
                .verify("first.example.com", 22, &other_key)
                .unwrap(),
            HostKeyDecision::Changed
        );
        assert!(!snapshot.known_hosts().to_openssh().is_empty());
    }

    #[test]
    fn insert_replaces_the_legacy_host_entry() {
        let first_key = key();
        let second_key = key();
        let mut verifier = KnownHostKeyVerifier::new();
        verifier.insert_key("example.com", 22, &first_key);
        verifier.insert_key("example.com", 22, &second_key);
        assert_eq!(
            verifier.verify("example.com", 22, &first_key).unwrap(),
            HostKeyDecision::Changed
        );
        assert_eq!(
            verifier.verify("example.com", 22, &second_key).unwrap(),
            HostKeyDecision::Trusted
        );
    }

    #[test]
    fn bracketed_ipv6_hosts_use_the_openssh_host_token() {
        let key = key();
        let mut verifier = KnownHostKeyVerifier::new();
        verifier.insert_key("2001:db8::1", 2200, &key);
        assert_eq!(
            verifier.verify("[2001:db8::1]", 2200, &key).unwrap(),
            HostKeyDecision::Trusted
        );
        assert!(verifier
            .known_hosts()
            .to_openssh()
            .starts_with("[2001:db8::1]:2200 "));
    }

    #[test]
    fn known_hosts_render_round_trips_entries() {
        let key = key();
        let input = format!("example.com {}\n", key.to_openssh().unwrap());
        let parsed = KnownHosts::parse(&input).unwrap();
        assert_eq!(parsed.entries().len(), 1);
        assert!(parsed.to_openssh().contains("example.com"));
    }
}
