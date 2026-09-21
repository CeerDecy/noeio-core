use crate::daemon::NoeioDaemon;
use crate::rpc::incoming;
use crate::rpc::service::daemon::DaemonServiceImpl;
use crate::rpc::service::nic::VirtualNicServiceImpl;
use noeio_proto::proto::noeio::v1::daemon_service_server::DaemonServiceServer;
use noeio_proto::proto::noeio::v1::virtual_nic_service_server::VirtualNicServiceServer;
use std::sync::Arc;
use tonic::transport::Server;

mod daemon;
mod nic;

pub async fn run(state: Arc<NoeioDaemon>) -> Result<(), Box<dyn std::error::Error>> {
    let incoming = incoming().await?;
    let daemon_service = DaemonServiceImpl::new(state.clone());
    let vnic_service = VirtualNicServiceImpl::new(state);

    Server::builder()
        .add_service(DaemonServiceServer::new(daemon_service))
        .add_service(VirtualNicServiceServer::new(vnic_service))
        .serve_with_incoming(incoming)
        .await?;

    Ok(())
}
