use crate::rpc::outgoing;
use noeio_proto::proto::noeio::v1::CreateVirtualNicRequest;
use noeio_proto::proto::noeio::v1::NetCheckRequest;
use noeio_proto::proto::noeio::v1::daemon_service_client::DaemonServiceClient;
use noeio_proto::proto::noeio::v1::virtual_nic_service_client::VirtualNicServiceClient;
use tonic::transport::Channel;

pub struct CliRpcClient {
    daemon_client: DaemonServiceClient<Channel>,
    vnic_client: VirtualNicServiceClient<Channel>,
}

impl CliRpcClient {
    pub async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let channel = outgoing().await?;

        Ok(Self {
            daemon_client: DaemonServiceClient::new(channel.clone()),
            vnic_client: VirtualNicServiceClient::new(channel.clone()),
        })
    }

    pub async fn net_check(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let resp = self.daemon_client.net_check(NetCheckRequest {}).await?;
        let derpers = &resp.get_ref().derpers;
        if derpers.is_empty() {
            println!("No Derper servers configured.");
        } else {
            println!(
                "Derper server RTT latency. noeio selects the lowest-latency Derper server for relay forwarding."
            );
            println!();
            for d in derpers {
                match d.rtt_ms {
                    0 => println!("{}\t-", d.address),
                    ms => println!("{}\t{}ms", d.address, ms),
                }
            }
        }
        Ok(())
    }

    pub async fn create_vnic(
        &mut self,
        ip: String,
        ip_version: String,
        network_id: String,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let resp = self
            .vnic_client
            .create_virtual_nic(CreateVirtualNicRequest {
                ip,
                ip_version,
                network_id,
            })
            .await?;
        println!("Vnic created, tun: {}", resp.get_ref().tun_name);
        Ok(())
    }
}
