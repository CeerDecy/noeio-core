use noeio_proto::proto::nic::virtual_nic_service_client::VirtualNicServiceClient;
use noeio_proto::proto::nic::CreateVirtualNicRequest;
use noeio_proto::proto::network::network_service_client::NetworkServiceClient;
use noeio_proto::proto::network::{CreateNetworkRequest, ListNetworkRequest};
use tonic::transport::Channel;
use crate::rpc::outgoing;

pub struct CliRpcClient {
    vnic_client: VirtualNicServiceClient<Channel>,
    network_client: NetworkServiceClient<Channel>,
}

impl CliRpcClient {
    pub async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let channel = outgoing().await?;

        Ok(Self {
            vnic_client: VirtualNicServiceClient::new(channel.clone()),
            network_client: NetworkServiceClient::new(channel),
        })
    }

    pub async fn list_networks(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let resp = self.network_client.list_networks(ListNetworkRequest {}).await?;
        let networks = &resp.get_ref().networks;
        if networks.is_empty() {
            println!("No networks found.");
        } else {
            for net in networks {
                println!("{}", net.name);
            }
        }
        Ok(())
    }

    pub async fn list_vnics(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // TODO: VirtualNicService 暂无 list 接口，待 proto 补充
        println!("Not implemented yet.");
        Ok(())
    }

    pub async fn create_network(&mut self, name: String, ip: String, ip_version: String, cidr: String) -> Result<(), Box<dyn std::error::Error>> {
        let resp = self.network_client.create_network(CreateNetworkRequest {
            name, ip, ip_version, cidr,
        }).await?;
        println!("Network created, id: {}", resp.get_ref().id);
        Ok(())
    }

    pub async fn create_vnic(&mut self, ip: String, ip_version: String, network_id: String) -> Result<(), Box<dyn std::error::Error>> {
        let resp = self.vnic_client.create_virtual_nic(CreateVirtualNicRequest {
            ip, ip_version,
            network_id,
        }).await?;
        println!("Vnic created, tun: {}", resp.get_ref().tun_name);
        Ok(())
    }
}
