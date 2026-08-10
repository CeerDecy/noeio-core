use crate::host_info::HostInfo;
use crate::packet::token_frame;

/// Payload of a [`NoeioPacketType::Report`] packet.
///
/// Wire layout: `[u16 token_len (BE)][token bytes][HostInfo bytes]`.
/// The token is an opaque credential string (currently a JWT issued by the
/// derper); an empty token is encoded as `token_len = 0` so that
/// unauthenticated daemons can still report while auth is being rolled out.
///
/// [`NoeioPacketType::Report`]: crate::packet::NoeioPacketType::Report
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportPayload {
    pub token: String,
    pub host_info: HostInfo,
}

impl ReportPayload {
    pub fn new(token: String, host_info: HostInfo) -> Self {
        Self { token, host_info }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        token_frame::encode(&self.token, &self.host_info.to_bytes())
    }
}

impl TryFrom<&[u8]> for ReportPayload {
    type Error = std::io::Error;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        let (token, inner) = token_frame::decode(data)?;
        let host_info = HostInfo::try_from(inner)?;
        Ok(Self { token, host_info })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn sample_host_info() -> HostInfo {
        HostInfo::new(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)),
            41641,
        ))
    }

    #[test]
    fn to_bytes_and_try_from_roundtrip() {
        let payload = ReportPayload::new("eyJhbGciOiJIUzI1NiJ9.e30.sig".to_string(), sample_host_info());

        let bytes = payload.to_bytes();
        let parsed = ReportPayload::try_from(bytes.as_slice()).unwrap();

        assert_eq!(parsed, payload);
    }

    #[test]
    fn empty_token_roundtrip() {
        let payload = ReportPayload::new(String::new(), sample_host_info());

        let bytes = payload.to_bytes();
        assert_eq!(&bytes[..2], &[0, 0]);
        let parsed = ReportPayload::try_from(bytes.as_slice()).unwrap();

        assert_eq!(parsed.token, "");
        assert_eq!(parsed.host_info, payload.host_info);
    }

    #[test]
    fn rejects_truncated_length_prefix() {
        assert!(ReportPayload::try_from([0u8].as_slice()).is_err());
    }

    #[test]
    fn rejects_token_length_beyond_buffer() {
        // Declared token length of 100 but only a few bytes follow.
        let mut bytes = vec![0u8, 100];
        bytes.extend_from_slice(b"short");
        assert!(ReportPayload::try_from(bytes.as_slice()).is_err());
    }

    #[test]
    fn rejects_non_utf8_token() {
        let mut bytes = vec![0u8, 2, 0xFF, 0xFE];
        bytes.extend_from_slice(&sample_host_info().to_bytes());
        assert!(ReportPayload::try_from(bytes.as_slice()).is_err());
    }
}
