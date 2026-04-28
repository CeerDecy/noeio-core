use crate::interface::virtual_nic::VirtualNic;
use crate::daemon::NoeioDaemon;
use noeio_proto::proto::network::network_service_server::NetworkService;
use noeio_proto::proto::network::{CreateNetworkRequest, CreateNetworkResponse, ListNetworkRequest, ListNetworkResponse, Network};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use tonic::{Request, Response, Status};

pub struct NetworkServiceImpl {
    state: Arc<NoeioDaemon>,
}

impl NetworkServiceImpl {
    pub fn new(state: Arc<NoeioDaemon>) -> Self {
        Self { state }
    }
}

#[tonic::async_trait]
impl NetworkService for NetworkServiceImpl {
    async fn list_networks(
        &self,
        request: Request<ListNetworkRequest>,
    ) -> Result<Response<ListNetworkResponse>, Status> {
        println!("Got a request: {:?}", request);
        Ok(Response::from(ListNetworkResponse { networks: vec![
            Network{
                name: "test".to_string(),
            }
        ] }))
    }
    async fn create_network(
        &self,
        request: Request<CreateNetworkRequest>,
    ) -> Result<Response<CreateNetworkResponse>, Status> {
        println!("Got a request: {:?}", request);
        let req = request.get_ref();
        let ip_addr = req
            .ip
            .parse::<Ipv4Addr>()
            .map_err(|_| Status::invalid_argument(format!("invalid ip address: '{}'", req.ip)))?;

        let name = req.name.clone();

        let nic = VirtualNic::create_ipv4_nic(ip_addr).await;

        Ok(Response::from(CreateNetworkResponse {
            id: String::from(""),
        }))
    }
}

fn validate_create_network_request(req: &CreateNetworkRequest) -> Result<(), Status> {
    req.ip
        .parse::<IpAddr>()
        .map_err(|_| Status::invalid_argument(format!("invalid ip address: '{}'", req.ip)))?;
    Ok(())
}
