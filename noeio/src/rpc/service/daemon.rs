use std::sync::Arc;

use noeio_proto::proto::noeio::v1::daemon_service_server::DaemonService;
use noeio_proto::proto::noeio::v1::{DerperRtt, NetCheckRequest, NetCheckResponse};
use tonic::{Request, Response, Status};

use crate::daemon::NoeioDaemon;

pub struct DaemonServiceImpl {
    state: Arc<NoeioDaemon>,
}

impl DaemonServiceImpl {
    pub fn new(state: Arc<NoeioDaemon>) -> Self {
        Self { state }
    }
}

#[tonic::async_trait]
impl DaemonService for DaemonServiceImpl {
    async fn net_check(
        &self,
        _request: Request<NetCheckRequest>,
    ) -> Result<Response<NetCheckResponse>, Status> {
        let derpers = self.state.derper.list().await;
        let result = derpers
            .into_iter()
            .map(|d| DerperRtt {
                address: d.address,
                rtt_ms: d.rtt_ms.unwrap_or(0),
            })
            .collect();
        Ok(Response::new(NetCheckResponse { derpers: result }))
    }
}
