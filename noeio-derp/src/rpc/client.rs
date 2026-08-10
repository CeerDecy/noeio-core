use crate::rpc::outgoing;
use noeio_proto::proto::derper::v1::token_service_client::TokenServiceClient;
use noeio_proto::proto::derper::v1::{
    CreateTokenRequest, CreateTokenResponse, VerifyTokenRequest, VerifyTokenResponse,
};
use tonic::transport::Channel;

pub struct CliRpcClient {
    token_client: TokenServiceClient<Channel>,
}

impl CliRpcClient {
    pub async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let channel = outgoing().await?;

        Ok(Self {
            token_client: TokenServiceClient::new(channel),
        })
    }

    pub async fn create_token(
        &mut self,
        network_id: String,
        ttl_seconds: Option<u64>,
    ) -> Result<CreateTokenResponse, Box<dyn std::error::Error>> {
        let resp = self
            .token_client
            .create_token(CreateTokenRequest {
                network_id,
                ttl_seconds,
            })
            .await?;

        Ok(resp.into_inner())
    }

    pub async fn verify_token(
        &mut self,
        token: String,
    ) -> Result<VerifyTokenResponse, Box<dyn std::error::Error>> {
        let resp = self
            .token_client
            .verify_token(VerifyTokenRequest { token })
            .await?;

        Ok(resp.into_inner())
    }
}
