use std::sync::Arc;
use crate::rpc::service::daemon::DaemonServiceImpl;
use crate::rpc::service::network::NetworkServiceImpl;
use crate::daemon::NoeioDaemon;
use noeio_proto::proto::noeio::v1::daemon_service_server::DaemonServiceServer;
use noeio_proto::proto::noeio::v1::network_service_server::NetworkServiceServer;
use tonic::transport::Server;
use noeio_proto::proto::noeio::v1::virtual_nic_service_server::VirtualNicServiceServer;
use crate::rpc::incoming;
use crate::rpc::service::nic::VirtualNicServiceImpl;

mod daemon;
mod network;
mod nic;

pub async fn run(state: Arc<NoeioDaemon>) -> Result<(), Box<dyn std::error::Error>> {
    let incoming = incoming().await?;
    let daemon_service = DaemonServiceImpl::new(state.clone());
    let network_service = NetworkServiceImpl::new(state.clone());
    let vnic_service = VirtualNicServiceImpl::new(state);

    Server::builder()
        .add_service(DaemonServiceServer::new(daemon_service))
        .add_service(NetworkServiceServer::new(network_service))
        .add_service(VirtualNicServiceServer::new(vnic_service))
        .serve_with_incoming(incoming)
        .await?;

    Ok(())
}
