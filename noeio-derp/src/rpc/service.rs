use crate::config::Auth;
use crate::rpc::incoming;
use crate::token;
use noeio_proto::proto::derper::v1::token_service_server::{TokenService, TokenServiceServer};
use noeio_proto::proto::derper::v1::{
    CreateTokenRequest, CreateTokenResponse, VerifyTokenRequest, VerifyTokenResponse, TokenClaims,
};
use std::time::Duration;
use tonic::transport::Server;
use tonic::{Request, Response, Status};

pub struct TokenServiceImpl {
    auth: Auth,
}

impl TokenServiceImpl {
    pub fn new(auth: Auth) -> Self {
        Self { auth }
    }
}

#[tonic::async_trait]
impl TokenService for TokenServiceImpl {
    async fn create_token(
        &self,
        request: Request<CreateTokenRequest>,
    ) -> Result<Response<CreateTokenResponse>, Status> {
        if !self.auth.local {
            return Err(Status::failed_precondition(
                "local token issuing is disabled (auth.local = false)",
            ));
        }

        let req = request.get_ref();
        let ttl = match req.ttl_seconds {
            None => Some(token::DEFAULT_TTL),
            Some(0) => None, // explicit 0: never expires
            Some(secs) => Some(Duration::from_secs(secs)),
        };

        let (token, claims) = token::issue(&self.auth.secret, &req.network_id, ttl)
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::InvalidData => Status::invalid_argument(e.to_string()),
                _ => Status::internal(e.to_string()),
            })?;

        tracing::info!(network = %claims.sub, exp = ?claims.exp, "issued report token");

        Ok(Response::new(CreateTokenResponse {
            token,
            expires_at: claims.exp,
        }))
    }

    async fn verify_token(
        &self,
        request: Request<VerifyTokenRequest>,
    ) -> Result<Response<VerifyTokenResponse>, Status> {
        let req = request.get_ref();

        let resp = match token::verify(&self.auth.secret, &req.token) {
            Ok(claims) => VerifyTokenResponse {
                valid: true,
                reason: None,
                claims: Some(to_proto_claims(claims)),
            },
            // Expired tokens are authentic, so their claims are still useful.
            Err(token::VerifyError::Expired(claims)) => VerifyTokenResponse {
                valid: false,
                reason: Some(token::VerifyError::Expired(claims.clone()).to_string()),
                claims: Some(to_proto_claims(claims)),
            },
            Err(err) => VerifyTokenResponse {
                valid: false,
                reason: Some(err.to_string()),
                claims: None,
            },
        };

        Ok(Response::new(resp))
    }
}

fn to_proto_claims(claims: token::Claims) -> TokenClaims {
    TokenClaims {
        iss: claims.iss,
        sub: claims.sub,
        iat: claims.iat,
        exp: claims.exp,
    }
}

pub async fn run(auth: Auth) -> Result<(), Box<dyn std::error::Error>> {
    let incoming = incoming().await?;
    let token_service = TokenServiceImpl::new(auth);

    Server::builder()
        .add_service(TokenServiceServer::new(token_service))
        .serve_with_incoming(incoming)
        .await?;

    Ok(())
}
