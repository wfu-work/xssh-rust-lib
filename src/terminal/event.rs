use crate::core::SshChannelEvent;

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
