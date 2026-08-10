use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// `iss` value for tokens signed by the derper itself (`auth.local = true`).
/// Centrally issued tokens will carry their own issuer identifier.
pub const LOCAL_ISSUER: &str = "derper";

/// TTL applied when the caller does not specify one.
pub const DEFAULT_TTL: Duration = Duration::from_secs(90 * 24 * 60 * 60);

/// Claims carried by a network-scoped report token. `sub` is the UUID of the
/// network the holder may report peers into. A token without `exp` never
/// expires.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claims {
    pub iss: String,
    pub sub: String,
    pub iat: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<u64>,
}

/// Sign a token granting Report access to `network_id` for `ttl`, returning
/// the encoded token together with the claims it carries. A `ttl` of `None`
/// produces a token that never expires.
///
/// The secret is used as the raw HS256 key. `network_id` must be a valid UUID;
/// it is normalized to hyphenated form so verification can compare it against
/// `PeerInfo.network_id` without caring about the input format.
pub fn issue(
    secret: &str,
    network_id: &str,
    ttl: Option<Duration>,
) -> Result<(String, Claims), std::io::Error> {
    let invalid = |e| std::io::Error::new(std::io::ErrorKind::InvalidData, e);

    let network = Uuid::parse_str(network_id).map_err(invalid)?;
    let now = unix_now();

    let claims = Claims {
        iss: LOCAL_ISSUER.to_string(),
        sub: network.hyphenated().to_string(),
        iat: now,
        exp: ttl.map(|ttl| now + ttl.as_secs()),
    };

    let token = encode(
        &Header::default(), // HS256
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(std::io::Error::other)?;

    Ok((token, claims))
}

/// Why a token failed verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// Signature is valid but the token is past its `exp`. Carries the
    /// decoded claims since they are still trustworthy.
    Expired(Claims),
    /// Well-formed token signed with a different key.
    InvalidSignature,
    /// Not a JWT, or an undecodable payload.
    Malformed,
    Other(String),
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifyError::Expired(_) => write!(f, "expired"),
            VerifyError::InvalidSignature => write!(f, "invalid signature"),
            VerifyError::Malformed => write!(f, "malformed token"),
            VerifyError::Other(reason) => write!(f, "{}", reason),
        }
    }
}

/// Verify a token's signature and expiry, returning its claims.
///
/// A token without `exp` never expires. Expiry is checked manually (not via
/// [`Validation`]) so an expired-but-authentic token still yields its claims.
pub fn verify(secret: &str, token: &str) -> Result<Claims, VerifyError> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.required_spec_claims.clear();
    validation.validate_exp = false;

    let data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .map_err(|e| match e.kind() {
        ErrorKind::InvalidSignature => VerifyError::InvalidSignature,
        ErrorKind::InvalidToken
        | ErrorKind::Base64(_)
        | ErrorKind::Json(_)
        | ErrorKind::Utf8(_)
        | ErrorKind::MissingRequiredClaim(_) => VerifyError::Malformed,
        _ => VerifyError::Other(e.to_string()),
    })?;

    if let Some(exp) = data.claims.exp
        && exp < unix_now()
    {
        return Err(VerifyError::Expired(data.claims));
    }

    Ok(data.claims)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};

    const SECRET: &str = "test-secret";
    const NETWORK: &str = "0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9";

    fn decode_claims(token: &str) -> jsonwebtoken::TokenData<Claims> {
        decode::<Claims>(
            token,
            &DecodingKey::from_secret(SECRET.as_bytes()),
            &Validation::new(Algorithm::HS256),
        )
        .unwrap()
    }

    #[test]
    fn issued_token_decodes_with_expected_claims() {
        let (token, claims) = issue(SECRET, NETWORK, Some(Duration::from_secs(3600))).unwrap();

        let data = decode_claims(&token);
        assert_eq!(data.claims, claims);
        assert_eq!(data.claims.iss, LOCAL_ISSUER);
        assert_eq!(data.claims.sub, NETWORK);
        assert_eq!(data.claims.exp, Some(data.claims.iat + 3600));
    }

    #[test]
    fn unlimited_token_has_no_exp_and_decodes() {
        let (token, claims) = issue(SECRET, NETWORK, None).unwrap();
        assert_eq!(claims.exp, None);

        // The encoded payload must not carry an `exp` claim at all.
        let mut validation = Validation::new(Algorithm::HS256);
        validation.required_spec_claims.clear();
        validation.validate_exp = false;
        let data = decode::<Claims>(
            &token,
            &DecodingKey::from_secret(SECRET.as_bytes()),
            &validation,
        )
        .unwrap();
        assert_eq!(data.claims.exp, None);
    }

    #[test]
    fn sub_is_normalized_to_hyphenated_uuid() {
        let (token, _) = issue(
            SECRET,
            "0A1B2C3D4E5F60718293A4B5C6D7E8F9",
            Some(Duration::from_secs(3600)),
        )
        .unwrap();

        assert_eq!(decode_claims(&token).claims.sub, NETWORK);
    }

    #[test]
    fn rejects_invalid_network_uuid() {
        assert!(issue(SECRET, "not-a-uuid", Some(Duration::from_secs(60))).is_err());
    }

    #[test]
    fn expired_token_fails_validation() {
        // Sign claims that expired well beyond the default 60s leeway.
        let now = unix_now();
        let claims = Claims {
            iss: LOCAL_ISSUER.to_string(),
            sub: NETWORK.to_string(),
            iat: now - 3600,
            exp: Some(now - 300),
        };
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(SECRET.as_bytes()),
        )
        .unwrap();

        let result = decode::<Claims>(
            &token,
            &DecodingKey::from_secret(SECRET.as_bytes()),
            &Validation::new(Algorithm::HS256),
        );
        assert!(result.is_err());
    }

    #[test]
    fn verify_accepts_valid_token() {
        let (token, claims) = issue(SECRET, NETWORK, Some(Duration::from_secs(3600))).unwrap();
        assert_eq!(verify(SECRET, &token), Ok(claims));
    }

    #[test]
    fn verify_accepts_unlimited_token() {
        let (token, claims) = issue(SECRET, NETWORK, None).unwrap();
        assert_eq!(verify(SECRET, &token), Ok(claims));
    }

    #[test]
    fn verify_reports_expired_with_claims() {
        let now = unix_now();
        let claims = Claims {
            iss: LOCAL_ISSUER.to_string(),
            sub: NETWORK.to_string(),
            iat: now - 3600,
            exp: Some(now - 300),
        };
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(SECRET.as_bytes()),
        )
        .unwrap();

        assert_eq!(verify(SECRET, &token), Err(VerifyError::Expired(claims)));
    }

    #[test]
    fn verify_reports_invalid_signature() {
        let (token, _) = issue("other-secret", NETWORK, None).unwrap();
        assert_eq!(verify(SECRET, &token), Err(VerifyError::InvalidSignature));
    }

    #[test]
    fn verify_reports_malformed_token() {
        assert_eq!(verify(SECRET, "not-a-jwt"), Err(VerifyError::Malformed));
        assert_eq!(verify(SECRET, ""), Err(VerifyError::Malformed));
    }

    #[test]
    fn wrong_secret_fails_validation() {
        let (token, _) = issue(SECRET, NETWORK, Some(Duration::from_secs(3600))).unwrap();

        let result = decode::<Claims>(
            &token,
            &DecodingKey::from_secret(b"other-secret"),
            &Validation::new(Algorithm::HS256),
        );
        assert!(result.is_err());
    }
}
