use crate::core::{OperationContext, SshChannel, SshChannelStream, SshError, SshSession};

use super::{TerminalEvent, TerminalOptions};

/// An authenticated interactive SSH terminal.
pub struct TerminalSession {
    channel: SshChannel,
}

impl TerminalSession {
    /// Open a session channel, allocate a PTY, and start the remote shell.
    pub async fn open(session: &SshSession, options: TerminalOptions) -> Result<Self, SshError> {
        Self::open_with_context(session, options, session.base_context()).await
    }

    /// Open a terminal with an explicit deadline or cancellation signal.
    pub async fn open_with_context(
        session: &SshSession,
        options: TerminalOptions,
        context: OperationContext,
    ) -> Result<Self, SshError> {
        options.validate()?;
        let setup_context = context
            .clone()
            .with_timeout_from_now(session.config().operation_timeout);
        let channel = session
            .open_session_channel_with_context(context.clone())
            .await?;
        channel
            .request_pty_with_context(
                options.want_reply,
                &options.term,
                options.columns,
                options.rows,
                options.pixel_width,
                options.pixel_height,
                &[],
                &setup_context,
            )
            .await?;
        channel
            .request_shell_with_context(options.want_reply, &setup_context)
            .await?;
        Ok(Self { channel })
    }

    pub fn with_context(self, context: OperationContext) -> Self {
        Self {
            channel: self.channel.with_context(context),
        }
    }

    /// Send terminal input to the remote shell.
    pub async fn write(&self, data: &[u8]) -> Result<(), SshError> {
        self.channel.write(data).await
    }

    pub async fn write_with_context(
        &self,
        data: &[u8],
        context: &OperationContext,
    ) -> Result<(), SshError> {
        self.channel.write_with_context(data, context).await
    }

    /// Send EOF to the remote shell.
    pub async fn eof(&self) -> Result<(), SshError> {
        self.channel.eof().await
    }

    pub async fn eof_with_context(&self, context: &OperationContext) -> Result<(), SshError> {
        self.channel.eof_with_context(context).await
    }

    /// Notify the remote PTY about a new terminal size.
    pub async fn resize(&self, columns: u32, rows: u32) -> Result<(), SshError> {
        validate_dimensions(columns, rows)?;
        self.channel.window_change(columns, rows).await
    }

    pub async fn resize_with_context(
        &self,
        columns: u32,
        rows: u32,
        context: &OperationContext,
    ) -> Result<(), SshError> {
        validate_dimensions(columns, rows)?;
        self.channel
            .window_change_with_context(columns, rows, context)
            .await
    }

    /// Wait for the next terminal event.
    pub async fn next_event(&mut self) -> Option<TerminalEvent> {
        self.channel.next_event().await.map(Into::into)
    }

    pub async fn next_event_with_context(
        &mut self,
        context: &OperationContext,
    ) -> Result<Option<TerminalEvent>, SshError> {
        self.channel
            .next_event_with_context(context)
            .await
            .map(|event| event.map(Into::into))
    }

    /// Close the remote channel.
    pub async fn close(&self) -> Result<(), SshError> {
        self.channel.close().await
    }

    pub async fn close_with_context(&self, context: &OperationContext) -> Result<(), SshError> {
        self.channel.close_with_context(context).await
    }

    /// Convert the terminal into a bidirectional async byte stream.
    pub fn into_stream(self) -> SshChannelStream {
        self.channel.into_stream()
    }
}

fn validate_dimensions(columns: u32, rows: u32) -> Result<(), SshError> {
    if columns == 0 || rows == 0 {
        return Err(SshError::configuration(
            "terminal dimensions must be positive",
        ));
    }
    Ok(())
}
