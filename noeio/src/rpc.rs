pub mod client;
pub mod service;

#[cfg(unix)]
const SOCK_PATH: &str = "/var/run/noeio.sock";

/// The RPC socket has no authentication: whoever can connect can create
/// nics, rewrite the routing table, and (on Linux) turn on forwarding and
/// NAT. The file mode is the whole trust boundary, so it is forced to
/// owner-only right after bind, before the listener is handed out.
#[cfg(unix)]
pub(crate) async fn incoming()
-> Result<tokio_stream::wrappers::UnixListenerStream, Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::remove_file(SOCK_PATH);
    let uds = tokio::net::UnixListener::bind(SOCK_PATH)?;
    std::fs::set_permissions(SOCK_PATH, std::fs::Permissions::from_mode(0o600))?;
    let mode = std::fs::metadata(SOCK_PATH)?.permissions().mode() & 0o777;
    if mode != 0o600 {
        return Err(format!(
            "refusing to serve RPC: {SOCK_PATH} has mode {mode:o}, expected 600 (the socket is unauthenticated)"
        )
        .into());
    }
    Ok(tokio_stream::wrappers::UnixListenerStream::new(uds))
}

#[cfg(unix)]
pub(crate) async fn outgoing() -> Result<tonic::transport::Channel, Box<dyn std::error::Error>> {
    let channel = tonic::transport::Endpoint::try_from("http://[::]:50051")?
        .connect_with_connector(tower::service_fn(|_: tonic::transport::Uri| async {
            let stream = tokio::net::UnixStream::connect(SOCK_PATH).await?;
            Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(stream))
        }))
        .await?;
    Ok(channel)
}

#[cfg(windows)]
const PIPE_NAME: &str = r"\\.\pipe\noeio";

#[cfg(windows)]
pub(crate) async fn incoming()
-> Result<noeio_common::named_pipe::NamedPipeStream, Box<dyn std::error::Error>> {
    noeio_common::named_pipe::NamedPipeStream::bind(PIPE_NAME)
}

#[cfg(windows)]
pub(crate) async fn outgoing() -> Result<tonic::transport::Channel, Box<dyn std::error::Error>> {
    let channel = tonic::transport::Endpoint::try_from("http://[::]:50051")?
        .connect_with_connector(tower::service_fn(|_: tonic::transport::Uri| async {
            let pipe = tokio::net::windows::named_pipe::ClientOptions::new().open(PIPE_NAME)?;
            Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(pipe))
        }))
        .await?;
    Ok(channel)
}
