pub mod client;
pub mod service;

#[cfg(unix)]
const SOCK_PATH: &str = "/var/run/noeio-derp.sock";

#[cfg(unix)]
pub(crate) async fn incoming()
-> Result<tokio_stream::wrappers::UnixListenerStream, Box<dyn std::error::Error>> {
    let _ = std::fs::remove_file(SOCK_PATH);
    let uds = tokio::net::UnixListener::bind(SOCK_PATH)?;
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
const PIPE_NAME: &str = r"\\.\pipe\noeio-derp";

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
