use std::time::Duration;

use crate::SshError;

/// Connection-level settings shared by all SSH frontends.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SshConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub connect_timeout: Duration,
    pub authentication_timeout: Duration,
    pub operation_timeout: Duration,
    pub keepalive_interval: Option<Duration>,
}

impl SshConfig {
    pub fn new(host: impl Into<String>, username: impl Into<String>) -> Result<Self, SshError> {
        let config = Self {
            host: host.into(),
            port: 22,
            username: username.into(),
            connect_timeout: Duration::from_secs(15),
            authentication_timeout: Duration::from_secs(15),
            operation_timeout: Duration::from_secs(30),
            keepalive_interval: Some(Duration::from_secs(30)),
        };
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), SshError> {
        if self.host.trim().is_empty() {
            return Err(SshError::configuration("SSH host must not be empty"));
        }
        if self.username.trim().is_empty() {
            return Err(SshError::configuration("SSH username must not be empty"));
        }
        if self.port == 0 {
            return Err(SshError::configuration(
                "SSH port must be between 1 and 65535",
            ));
        }
        if self.connect_timeout.is_zero() {
            return Err(SshError::configuration(
                "SSH connect timeout must be positive",
            ));
        }
        if self.authentication_timeout.is_zero() {
            return Err(SshError::configuration(
                "SSH authentication timeout must be positive",
            ));
        }
        if self.operation_timeout.is_zero() {
            return Err(SshError::configuration(
                "SSH operation timeout must be positive",
            ));
        }
        if self
            .keepalive_interval
            .is_some_and(|interval| interval.is_zero())
        {
            return Err(SshError::configuration(
                "SSH keepalive interval must be positive when configured",
            ));
        }
        Ok(())
    }

    pub(crate) fn socket_address(&self) -> String {
        if self.host.contains(':') && !self.host.starts_with('[') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::SshConfig;

    #[test]
    fn defaults_are_suitable_for_an_ssh_client() {
        let config = SshConfig::new("example.com", "alice").unwrap();
        assert_eq!(config.port, 22);
        assert_eq!(config.connect_timeout, Duration::from_secs(15));
        assert_eq!(config.authentication_timeout, Duration::from_secs(15));
        assert_eq!(config.operation_timeout, Duration::from_secs(30));
        assert_eq!(config.keepalive_interval, Some(Duration::from_secs(30)));
    }

    #[test]
    fn invalid_config_is_rejected() {
        let mut config = SshConfig::new("example.com", "alice").unwrap();
        config.port = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn ipv6_addresses_are_bracketed() {
        let mut config = SshConfig::new("2001:db8::1", "alice").unwrap();
        config.port = 2200;
        assert_eq!(config.socket_address(), "[2001:db8::1]:2200");
    }
}
