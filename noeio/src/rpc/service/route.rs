use crate::daemon::NoeioDaemon;
use crate::daemon::routes::{self, Protected, Rejection, RouteError};
use noeio_proto::proto::noeio::v1::route_service_server::RouteService;
use noeio_proto::proto::noeio::v1::{
    AdvertiseRouteRequest, AdvertiseRouteResponse, ListRoutesRequest, ListRoutesResponse, PathKind,
    RouteEntry, RouteSource, RouteState, WithdrawRouteRequest, WithdrawRouteResponse,
};
use smoltcp::wire::Ipv4Cidr;
use std::sync::Arc;
use tonic::{Request, Response, Status};

pub struct RouteServiceImpl {
    state: Arc<NoeioDaemon>,
}

impl RouteServiceImpl {
    pub fn new(state: Arc<NoeioDaemon>) -> Self {
        Self { state }
    }

    fn protected(&self) -> Protected {
        Protected {
            overlay_ips: self.state.nics.ips(),
            control_plane: self.state.control_plane.clone(),
        }
    }

    fn advertised_strings(&self) -> Vec<String> {
        self.state
            .advertised_routes()
            .iter()
            .map(ToString::to_string)
            .collect()
    }
}

/// A rejected advertisement is the caller's problem, not the daemon's: the
/// node keeps serving. Platform refusal is FAILED_PRECONDITION (FR-9.5); a
/// bad CIDR is INVALID_ARGUMENT.
fn status_for(errors: &[RouteError]) -> Status {
    let msg = errors
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("; ");
    if errors
        .iter()
        .any(|e| matches!(e, RouteError::PlatformConsumerOnly { .. }))
    {
        Status::failed_precondition(msg)
    } else {
        Status::invalid_argument(msg)
    }
}

#[tonic::async_trait]
impl RouteService for RouteServiceImpl {
    async fn advertise_route(
        &self,
        request: Request<AdvertiseRouteRequest>,
    ) -> Result<Response<AdvertiseRouteResponse>, Status> {
        let protected = self.protected();
        let mut accepted = Vec::new();
        let mut errors = Vec::new();
        for raw in &request.get_ref().cidrs {
            match routes::validate_advertisement(raw, &protected) {
                Ok(cidr) => accepted.push(cidr),
                Err(err) => errors.push(err),
            }
        }
        if !errors.is_empty() {
            return Err(status_for(&errors));
        }
        if accepted.is_empty() {
            return Err(Status::invalid_argument("no CIDR given"));
        }

        let mut set = self.state.advertised_routes();
        for cidr in accepted {
            if !set.contains(&cidr) {
                set.push(cidr);
            }
        }
        self.state.set_advertised(set).await;
        Ok(Response::new(AdvertiseRouteResponse {
            advertised: self.advertised_strings(),
        }))
    }

    async fn withdraw_route(
        &self,
        request: Request<WithdrawRouteRequest>,
    ) -> Result<Response<WithdrawRouteResponse>, Status> {
        let mut remove: Vec<Ipv4Cidr> = Vec::new();
        for raw in &request.get_ref().cidrs {
            let cidr =
                routes::parse_cidr(raw).map_err(|e| Status::invalid_argument(e.to_string()))?;
            remove.push(cidr);
        }
        let set: Vec<Ipv4Cidr> = self
            .state
            .advertised_routes()
            .into_iter()
            .filter(|c| !remove.contains(c))
            .collect();
        self.state.set_advertised(set).await;
        Ok(Response::new(WithdrawRouteResponse {
            advertised: self.advertised_strings(),
        }))
    }

    async fn list_routes(
        &self,
        _request: Request<ListRoutesRequest>,
    ) -> Result<Response<ListRoutesResponse>, Status> {
        let mut entries = Vec::new();

        for cidr in self.state.advertised_routes() {
            entries.push(RouteEntry {
                cidr: cidr.to_string(),
                source: RouteSource::Local as i32,
                state: RouteState::Active as i32,
                ..Default::default()
            });
        }

        // Decisions are refreshed on every reconcile; fold in the peer's
        // current path so `route list` answers "which link does it take".
        let decisions = self.state.decisions.read().unwrap().clone();
        for d in decisions {
            let peer = self.state.router.get_by_peer_id(&d.peer_id);
            let (via, path, path_addr) = match &peer {
                Some(p) => {
                    let via = p.info().noeio_ip.to_string();
                    match p.address() {
                        Some(addr) => (via, PathKind::Direct, addr.to_string()),
                        None => (via, PathKind::Relay, String::new()),
                    }
                }
                None => (String::new(), PathKind::None, String::new()),
            };
            let (state, reason) = match d.rejected {
                None => (RouteState::Active, String::new()),
                Some(Rejection::Standby) => (RouteState::Standby, Rejection::Standby.to_string()),
                Some(why) => (RouteState::Rejected, why.to_string()),
            };
            entries.push(RouteEntry {
                cidr: d.cidr.to_string(),
                source: RouteSource::Remote as i32,
                peer_id: d.peer_id,
                via,
                state: state as i32,
                reject_reason: reason,
                path: path as i32,
                path_addr,
            });
        }

        Ok(Response::new(ListRoutesResponse {
            routes: entries,
            can_advertise: routes::platform_can_advertise(),
            platform: routes::platform_name().to_string(),
            accept_routes: self.state.config.router.accept_routes,
            nat_applied: self.state.nat_state.lock().unwrap().applied.is_some(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use tokio::net::UdpSocket;

    async fn service() -> RouteServiceImpl {
        let udp = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        RouteServiceImpl::new(NoeioDaemon::new(udp, Config::default()).await)
    }

    /// AC-16 (2) + FR-9.5: on a consumer-only platform AdvertiseRoute
    /// returns FAILED_PRECONDITION, the daemon keeps serving (ListRoutes
    /// still answers), and nothing reached the advertised set. On Linux
    /// the same call succeeds and shows up in ListRoutes.
    #[tokio::test]
    async fn advertise_rpc_follows_platform_and_never_kills_the_daemon() {
        let svc = service().await;
        let req = Request::new(AdvertiseRouteRequest {
            cidrs: vec!["192.168.10.0/24".into()],
        });
        let result = svc.advertise_route(req).await;

        if routes::platform_can_advertise() {
            let resp = result.expect("linux may advertise");
            assert_eq!(resp.get_ref().advertised, vec!["192.168.10.0/24"]);
        } else {
            let status = result.expect_err("consumer-only platform must refuse");
            assert_eq!(status.code(), tonic::Code::FailedPrecondition);
            assert!(status.message().contains(routes::platform_name()));
            assert!(status.message().contains("192.168.10.0/24"));
            assert!(svc.state.advertised_routes().is_empty());
        }

        let list = svc
            .list_routes(Request::new(ListRoutesRequest {}))
            .await
            .expect("daemon still serves after a refused advertisement");
        assert_eq!(
            list.get_ref().can_advertise,
            routes::platform_can_advertise()
        );
        let local: Vec<_> = list
            .get_ref()
            .routes
            .iter()
            .filter(|r| r.source == RouteSource::Local as i32)
            .collect();
        assert_eq!(local.len(), usize::from(routes::platform_can_advertise()));
    }

    #[tokio::test]
    async fn bad_cidr_is_invalid_argument() {
        let svc = service().await;
        let status = svc
            .advertise_route(Request::new(AdvertiseRouteRequest {
                cidrs: vec!["0.0.0.0/0".into()],
            }))
            .await
            .unwrap_err();
        // The platform gate wins on non-Linux; either way it is a refusal.
        assert!(matches!(
            status.code(),
            tonic::Code::InvalidArgument | tonic::Code::FailedPrecondition
        ));
        assert!(svc.state.advertised_routes().is_empty());
    }

    #[tokio::test]
    async fn withdraw_removes_only_named_cidrs() {
        let svc = service().await;
        svc.state
            .set_advertised(vec![
                "192.168.10.0/24".parse().unwrap(),
                "172.20.0.0/16".parse().unwrap(),
            ])
            .await;
        let resp = svc
            .withdraw_route(Request::new(WithdrawRouteRequest {
                cidrs: vec!["172.20.0.7/16".into()],
            }))
            .await
            .unwrap();
        assert_eq!(resp.get_ref().advertised, vec!["192.168.10.0/24"]);
    }
}
