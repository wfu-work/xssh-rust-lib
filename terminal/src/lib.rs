//! Interactive SSH terminal primitives built on top of `xssh-rust-core`.

use xssh_rust_core::{SshChannel, SshChannelEvent, SshChannelStream, SshError, SshSession};

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

/// Events emitted by an interactive terminal channel.
#[derive(Debug, PartialEq, Eq)]
pub enum TerminalEvent {
    Data(Vec<u8>),
    ExtendedData {
        ext: u32,
        data: Vec<u8>,
    },
    Eof,
    Close,
    ExitStatus(u32),
    ExitSignal {
        signal: String,
        core_dumped: bool,
        error_message: String,
        language_tag: String,
    },
    Success,
    Failure,
    OpenFailure(String),
}

/// An authenticated interactive SSH terminal.
pub struct TerminalSession {
    channel: SshChannel,
}

impl TerminalSession {
    /// Open a session channel, allocate a PTY, and start the remote shell.
    pub async fn open(session: &SshSession, options: TerminalOptions) -> Result<Self, SshError> {
        options.validate()?;
        let channel = session.open_session_channel().await?;
        channel
            .request_pty(
                options.want_reply,
                &options.term,
                options.columns,
                options.rows,
                options.pixel_width,
                options.pixel_height,
                &[],
            )
            .await?;
        channel.request_shell(options.want_reply).await?;
        Ok(Self { channel })
    }

    /// Send terminal input to the remote shell.
    pub async fn write(&self, data: &[u8]) -> Result<(), SshError> {
        self.channel.write(data).await
    }

    /// Send EOF to the remote shell.
    pub async fn eof(&self) -> Result<(), SshError> {
        self.channel.eof().await
    }

    /// Notify the remote PTY about a new terminal size.
    pub async fn resize(&self, columns: u32, rows: u32) -> Result<(), SshError> {
        if columns == 0 || rows == 0 {
            return Err(SshError::configuration(
                "terminal dimensions must be positive",
            ));
        }
        self.channel.window_change(columns, rows).await
    }

    /// Wait for the next terminal event.
    pub async fn next_event(&mut self) -> Option<TerminalEvent> {
        self.channel.next_event().await.map(Into::into)
    }

    /// Close the remote channel.
    pub async fn close(&self) -> Result<(), SshError> {
        self.channel.close().await
    }

    /// Convert the terminal into a bidirectional async byte stream.
    pub fn into_stream(self) -> SshChannelStream {
        self.channel.into_stream()
    }
}

impl From<SshChannelEvent> for TerminalEvent {
    fn from(event: SshChannelEvent) -> Self {
        match event {
            SshChannelEvent::Data(data) => Self::Data(data),
            SshChannelEvent::ExtendedData { ext, data } => Self::ExtendedData { ext, data },
            SshChannelEvent::Eof => Self::Eof,
            SshChannelEvent::Close => Self::Close,
            SshChannelEvent::ExitStatus(code) => Self::ExitStatus(code),
            SshChannelEvent::ExitSignal {
                signal,
                core_dumped,
                error_message,
                language_tag,
            } => Self::ExitSignal {
                signal,
                core_dumped,
                error_message,
                language_tag,
            },
            SshChannelEvent::Success => Self::Success,
            SshChannelEvent::Failure => Self::Failure,
            SshChannelEvent::OpenFailure(message) => Self::OpenFailure(message),
        }
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
