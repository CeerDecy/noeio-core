use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use tokio_stream::Stream;

/// A [`Stream`] of named pipe connections, analogous to
/// `tokio_stream::wrappers::UnixListenerStream` but for Windows named pipes.
pub struct NamedPipeStream {
    pipe_name: String,
    current: NamedPipeServer,
}

impl NamedPipeStream {
    pub fn bind(pipe_name: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let current = ServerOptions::new()
            .first_pipe_instance(true)
            .create(pipe_name)?;
        Ok(Self {
            pipe_name: pipe_name.to_string(),
            current,
        })
    }
}

impl Stream for NamedPipeStream {
    type Item = Result<NamedPipeServer, std::io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.current.poll_connect(cx) {
            Poll::Ready(Ok(())) => {
                // Connection established — swap in a fresh server instance for
                // the next caller and yield the connected one.
                let next = match ServerOptions::new().create(&self.pipe_name) {
                    Ok(s) => s,
                    Err(e) => return Poll::Ready(Some(Err(e))),
                };
                let connected = std::mem::replace(&mut self.current, next);
                Poll::Ready(Some(Ok(connected)))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Some(Err(e))),
            Poll::Pending => Poll::Pending,
        }
    }
}
