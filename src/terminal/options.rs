use crate::core::SshError;

/// PTY and shell settings for a terminal session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TerminalOptions {
    pub term: String,
    pub columns: u32,
    pub rows: u32,
    pub pixel_width: u32,
    pub pixel_height: u32,
    pub want_reply: bool,
}

impl Default for TerminalOptions {
    fn default() -> Self {
        Self {
            term: "xterm-256color".to_owned(),
            columns: 80,
            rows: 24,
            pixel_width: 0,
            pixel_height: 0,
            want_reply: true,
        }
    }
}

impl TerminalOptions {
    pub fn validate(&self) -> Result<(), SshError> {
        if self.term.trim().is_empty() {
            return Err(SshError::configuration("terminal type must not be empty"));
        }
        if self.columns == 0 || self.rows == 0 {
            return Err(SshError::configuration(
                "terminal dimensions must be positive",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::TerminalOptions;

    #[test]
    fn terminal_defaults_are_usable() {
        let options = TerminalOptions::default();
        assert_eq!(options.term, "xterm-256color");
        assert_eq!((options.columns, options.rows), (80, 24));
        assert!(options.validate().is_ok());
    }
}
