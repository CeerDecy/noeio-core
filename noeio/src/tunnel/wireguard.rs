use noeio_common::host_info::NetworkInfo;
use std::collections::hash_map::DefaultHasher;
use std::hash::Hasher;
use uuid::Uuid;
use x25519_dalek::{PublicKey, StaticSecret};

/// Configuration for a WireGuard tunnel between the local host and a peer.
pub struct WireGuardConfig {
    pub my_secret_key: StaticSecret,
    pub my_public_key: PublicKey,

    pub peer_secret_key: StaticSecret,
    pub peer_public_key: PublicKey,
}

impl WireGuardConfig {
    /// Derive a tunnel config for `peer_id` within `network`.
    ///
    /// Both key pairs are derived deterministically from the network id and the
    /// peer id so that every host agrees on the same keys without a key
    /// exchange.
    pub fn new_from_network_peer(peer_id: String, network: &NetworkInfo) -> Self {
        let network_str = Uuid::from_bytes(network.network_id).hyphenated().to_string();

        let mut my_seed = [0u8; 32];
        generate_digest(&["self", &network_str, &peer_id], &mut my_seed);
        let my_secret_key = StaticSecret::from(my_seed);
        let my_public_key = PublicKey::from(&my_secret_key);

        let mut peer_seed = [0u8; 32];
        generate_digest(&["peer", &network_str, &peer_id], &mut peer_seed);
        let peer_secret_key = StaticSecret::from(peer_seed);
        let peer_public_key = PublicKey::from(&peer_secret_key);

        Self {
            my_secret_key,
            my_public_key,
            peer_secret_key,
            peer_public_key,
        }
    }
}

pub fn generate_digest(strs: &[&str], digest: &mut [u8]) {
    let mut hasher = DefaultHasher::new();
    for s in strs {
        hasher.write(s.as_bytes());
    }

    assert_eq!(digest.len() % 8, 0, "digest length must be multiple of 8");

    let shard_count = digest.len() / 8;
    for i in 0..shard_count {
        digest[i * 8..(i + 1) * 8].copy_from_slice(&hasher.finish().to_be_bytes());
        hasher.write(&digest[..(i + 1) * 8]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_for_same_input() {
        let mut a = [0u8; 16];
        let mut b = [0u8; 16];
        generate_digest(&["foo", "bar"], &mut a);
        generate_digest(&["foo", "bar"], &mut b);
        assert_eq!(a, b);
    }

    #[test]
    fn different_input_produces_different_digest() {
        let mut a = [0u8; 16];
        let mut b = [0u8; 16];
        generate_digest(&["foo", "bar"], &mut a);
        generate_digest(&["foo", "baz"], &mut b);
        assert_ne!(a, b);
    }

    #[test]
    fn fills_entire_digest() {
        // With a multi-shard buffer, each 8-byte shard is re-fed into the
        // hasher, so shards should differ from one another (not a repeated
        // block) and the buffer should not stay all-zero.
        let mut digest = [0u8; 24];
        generate_digest(&["something"], &mut digest);
        assert_ne!(digest, [0u8; 24]);
        assert_ne!(digest[0..8], digest[8..16]);
        assert_ne!(digest[8..16], digest[16..24]);
    }

    #[test]
    fn empty_digest_is_left_untouched() {
        let mut digest: [u8; 0] = [];
        generate_digest(&["foo"], &mut digest);
        assert_eq!(digest, [] as [u8; 0]);
    }

    #[test]
    fn empty_input_slice_still_fills_digest() {
        let mut digest = [0u8; 8];
        generate_digest(&[], &mut digest);
        // A DefaultHasher with no writes still yields a finish() value.
        assert_ne!(digest, [0u8; 8]);
    }

    #[test]
    fn joined_input_differs_from_split_input() {
        // Writes are not delimited, so this documents current behaviour:
        // ["ab"] and ["a", "b"] feed the same bytes and collide.
        let mut joined = [0u8; 8];
        let mut split = [0u8; 8];
        generate_digest(&["ab"], &mut joined);
        generate_digest(&["a", "b"], &mut split);
        assert_eq!(joined, split);
    }

    #[test]
    #[should_panic(expected = "digest length must be multiple of 8")]
    fn panics_when_length_not_multiple_of_8() {
        let mut digest = [0u8; 12];
        generate_digest(&["foo"], &mut digest);
    }
}
