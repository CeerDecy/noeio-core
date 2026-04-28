use crate::daemon::NoeioDaemon;
use crate::interface::virtual_nic::VirtualNic;
use noeio_proto::proto::nic::virtual_nic_service_server::VirtualNicService;
use noeio_proto::proto::nic::{CreateVirtualNicRequest, CreateVirtualNicResponse};
use std::net::Ipv4Addr;
use std::sync::Arc;
use tonic::{Request, Response, Status};

pub struct VirtualNicServiceImpl {
    state: Arc<NoeioDaemon>,
}

impl VirtualNicServiceImpl {
    pub fn new(state: Arc<NoeioDaemon>) -> Self {
        Self { state }
    }
}

#[tonic::async_trait]
impl VirtualNicService for VirtualNicServiceImpl {
    async fn create_virtual_nic(
        &self,
        request: Request<CreateVirtualNicRequest>,
    ) -> Result<Response<CreateVirtualNicResponse>, Status> {
        let req = request.get_ref();
        let ip_addr = req
            .ip
            .parse::<Ipv4Addr>()
            .map_err(|_| Status::invalid_argument(format!("invalid ip address: '{}'", req.ip)))?;

        let (nic, reader) = VirtualNic::create_ipv4_nic(ip_addr).await;
        let tun_name = nic.tun_name.clone();

        self.state
            .register_nic(self.state.clone(), nic, reader, req.network_id.clone())
            .await
            .map_err(|e| Status::failed_precondition(e))?;

        Ok(Response::from(CreateVirtualNicResponse { tun_name }))
    }
}
