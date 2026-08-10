//! Shared framing for payloads that carry a leading credential:
//! `[u16 token_len (BE)][token bytes][inner payload]`.
//!
//! The token is an opaque credential string; an empty token is encoded as
//! `token_len = 0` so unauthenticated senders can still be parsed while auth
//! is being rolled out.

pub(crate) fn encode(token: &str, inner: &[u8]) -> Vec<u8> {
    let token = token.as_bytes();
    let mut out = Vec::with_capacity(2 + token.len() + inner.len());
    out.extend_from_slice(&(token.len() as u16).to_be_bytes());
    out.extend_from_slice(token);
    out.extend_from_slice(inner);
    out
}

/// Split a framed payload into its token and inner payload.
pub(crate) fn decode(data: &[u8]) -> Result<(String, &[u8]), std::io::Error> {
    let invalid = |msg| std::io::Error::new(std::io::ErrorKind::InvalidData, msg);

    let len_bytes: [u8; 2] = data
        .get(..2)
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| invalid("payload shorter than token length prefix"))?;
    let token_len = u16::from_be_bytes(len_bytes) as usize;

    let token_bytes = data
        .get(2..2 + token_len)
        .ok_or_else(|| invalid("payload shorter than declared token length"))?;
    let token = std::str::from_utf8(token_bytes)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?
        .to_string();

    Ok((token, &data[2 + token_len..]))
}
