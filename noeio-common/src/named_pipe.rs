use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use tokio_stream::Stream;
use tonic::transport::server::Connected;

/// A connected named pipe server end that can be served by tonic via
/// `serve_with_incoming` (it implements [`Connected`]).
pub struct NamedPipeConnection(NamedPipeServer);

impl Connected for NamedPipeConnection {
    // Named pipes have no peer address to expose.
    type ConnectInfo = ();

    fn connect_info(&self) -> Self::ConnectInfo {}
}

impl AsyncRead for NamedPipeConnection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for NamedPipeConnection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

/// Future that owns the server instance while waiting for a client, then
/// hands it back together with the connect result.
type ConnectFuture =
    Pin<Box<dyn Future<Output = (NamedPipeServer, std::io::Result<()>)> + Send>>;

fn connect_future(server: NamedPipeServer) -> ConnectFuture {
    Box::pin(async move {
        let result = server.connect().await;
        (server, result)
    })
}

/// A [`Stream`] of named pipe connections, analogous to
/// `tokio_stream::wrappers::UnixListenerStream` but for Windows named pipes.
pub struct NamedPipeStream {
    pipe_name: String,
    connecting: ConnectFuture,
}

impl NamedPipeStream {
    pub fn bind(pipe_name: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let current = ServerOptions::new()
            .first_pipe_instance(true)
            .create(pipe_name)?;
        Ok(Self {
            pipe_name: pipe_name.to_string(),
            connecting: connect_future(current),
        })
    }
}

impl Stream for NamedPipeStream {
    type Item = Result<NamedPipeConnection, std::io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.connecting.as_mut().poll(cx) {
            Poll::Ready((connected, Ok(()))) => {
                // Connection established — swap in a fresh server instance for
                // the next caller and yield the connected one.
                let next = match ServerOptions::new().create(&self.pipe_name) {
                    Ok(s) => s,
                    Err(e) => return Poll::Ready(Some(Err(e))),
                };
                self.connecting = connect_future(next);
                Poll::Ready(Some(Ok(NamedPipeConnection(connected))))
            }
            Poll::Ready((server, Err(e))) => {
                // Keep the same instance and retry connecting on the next poll.
                self.connecting = connect_future(server);
                Poll::Ready(Some(Err(e)))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}
