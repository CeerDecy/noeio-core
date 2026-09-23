use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct Config {
    #[serde(default)]
    pub stun: Stun,
    #[serde(default)]
    pub derper: Derper,
    #[serde(default)]
    pub router: RouterConfig,
}

/// Subnet-router settings. Defaults are "off": nothing advertised, nothing
/// accepted, so a node without this section behaves exactly as before.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct RouterConfig {
    /// CIDRs this node routes for (advertiser role). Linux only.
    #[serde(default)]
    pub advertise_routes: Vec<String>,
    /// Install routes other nodes advertise (consumer role).
    #[serde(default)]
    pub accept_routes: bool,
    /// When advertising, also enable IP forwarding and SNAT for the
    /// advertised subnets. Off means the operator manages that themselves.
    #[serde(default = "default_true")]
    pub auto_nat: bool,
    /// LAN-side interface used for SNAT. Empty picks the interface the
    /// system would route each subnet through.
    #[serde(default)]
    pub lan_interface: String,
}

fn default_true() -> bool {
    true
}

impl Default for RouterConfig {
    fn default() -> Self {
        Self {
            advertise_routes: Vec::new(),
            accept_routes: false,
            auto_nat: true,
            lan_interface: String::new(),
        }
    }
}

impl Config {
    pub fn load(path: Option<PathBuf>) -> Self {
        let config = match path {
            Some(p) => {
                let content = std::fs::read_to_string(&p).unwrap_or_else(|e| {
                    panic!("failed to read config file '{}': {}", p.display(), e)
                });
                toml::from_str(&content).unwrap_or_else(|e| {
                    panic!("failed to parse config file '{}': {}", p.display(), e)
                })
            }
            None => {
                let home = std::env::home_dir().expect("cannot determine home directory");
                let config_dir = home.join(".noeio");
                let config_path = config_dir.join("config.toml");

                if !config_path.exists() {
                    std::fs::create_dir_all(&config_dir).expect("failed to create ~/.noeio");
                    let default_config = toml::to_string_pretty(&Config::default()).unwrap();
                    std::fs::write(&config_path, &default_config)
                        .expect("failed to write config.toml");
                    return Config::default();
                }

                let content =
                    std::fs::read_to_string(&config_path).expect("failed to read config.toml");
                toml::from_str(&content).expect("failed to parse config.toml")
            }
        };

        tracing::debug!("config loaded: \n {:?}", config);

        config
    }

    /// Append CLI-supplied STUN servers to the in-memory config. The config
    /// file on disk is never touched, so flags are per-run additions rather
    /// than edits. Blank entries are skipped and addresses already configured
    /// are not duplicated.
    pub fn append_stuns(&mut self, stun: Vec<String>) {
        for addr in stun {
            let addr = addr.trim();
            if addr.is_empty() {
                continue;
            }
            if !self.stun.servers.iter().any(|s| s == addr) {
                self.stun.servers.push(addr.to_string());
            }
        }
    }

    /// Append CLI-supplied derper servers to the in-memory config, leaving the
    /// file on disk untouched.
    ///
    /// `derper_tokens` pairs positionally with `derper_servers`; a server with
    /// no matching token gets an empty one, which the derper treats as an
    /// unauthenticated report. An address already present in the file keeps its
    /// existing token unless the flag supplies a non-empty one.
    pub fn append_derpers(&mut self, derper_servers: Vec<String>, derper_tokens: Vec<String>) {
        if derper_tokens.len() > derper_servers.len() {
            panic!(
                "--derper-token has {} entries but --derper-server has {}: tokens pair positionally with servers",
                derper_tokens.len(),
                derper_servers.len()
            );
        }

        for (idx, address) in derper_servers.into_iter().enumerate() {
            let address = address.trim().to_string();
            if address.is_empty() {
                continue;
            }
            let token = derper_tokens
                .get(idx)
                .map(|t| t.trim().to_string())
                .unwrap_or_default();

            match self
                .derper
                .servers
                .iter_mut()
                .find(|s| s.address == address)
            {
                // Already configured: only a non-empty flag token overrides the
                // file, so `--derper-server` alone can't wipe a working token.
                Some(existing) => {
                    if !token.is_empty() {
                        existing.token = token;
                    }
                }
                None => self.derper.servers.push(DerperInfo { address, token }),
            }
        }
    }

    /// Append CLI-supplied advertised routes and apply `--accept-routes`,
    /// leaving the file untouched. Same shape as `append_stuns`: blanks
    /// skipped, duplicates dropped. Validation happens in
    /// [`Self::validate_routes`], once, for file and flags together.
    pub fn append_routes(&mut self, advertise: Vec<String>, accept: bool) {
        for cidr in advertise {
            let cidr = cidr.trim();
            if cidr.is_empty() {
                continue;
            }
            if !self.router.advertise_routes.iter().any(|c| c == cidr) {
                self.router.advertise_routes.push(cidr.to_string());
            }
        }
        if accept {
            self.router.accept_routes = true;
        }
    }

    /// Parse, normalize, and validate `router.advertise_routes` (FR-1.4 /
    /// FR-1.5 / FR-9). On success the list is rewritten in normalized form
    /// and returned. Any failure lists every rejected CIDR with its reason;
    /// the caller decides whether that is fatal (start-up) or a rejected
    /// request (RPC).
    ///
    /// `protected` are the addresses no advertised CIDR may contain: our
    /// overlay IPs and the resolved control-plane servers.
    pub fn validate_routes(
        &mut self,
        protected: &crate::daemon::routes::Protected,
    ) -> Result<Vec<smoltcp::wire::Ipv4Cidr>, Vec<crate::daemon::routes::RouteError>> {
        use crate::daemon::routes::validate_advertisement;
        let mut ok = Vec::new();
        let mut errors = Vec::new();
        for raw in &self.router.advertise_routes {
            match validate_advertisement(raw, protected) {
                Ok(cidr) => {
                    if raw.trim() != cidr.to_string() {
                        tracing::warn!("advertise_routes: normalized '{raw}' to {cidr}");
                    }
                    if !ok.contains(&cidr) {
                        ok.push(cidr);
                    }
                }
                Err(err) => errors.push(err),
            }
        }
        if !errors.is_empty() {
            return Err(errors);
        }
        self.router.advertise_routes = ok.iter().map(ToString::to_string).collect();
        Ok(ok)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct Noeio {}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct Derper {
    #[serde(default)]
    pub servers: Vec<DerperInfo>,
}

/// A derper relay endpoint and the credential used when reporting to it.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct DerperInfo {
    pub address: String,
    /// Report token issued by this derper (empty when not configured yet —
    /// the derper decides whether to accept unauthenticated reports).
    #[serde(default)]
    pub token: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct Stun {
    #[serde(default)]
    pub servers: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_with(stun: &[&str], derper: &[(&str, &str)]) -> Config {
        Config {
            stun: Stun {
                servers: stun.iter().map(|s| s.to_string()).collect(),
            },
            derper: Derper {
                servers: derper
                    .iter()
                    .map(|(a, t)| DerperInfo {
                        address: a.to_string(),
                        token: t.to_string(),
                    })
                    .collect(),
            },
            router: RouterConfig::default(),
        }
    }

    fn strs(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn router_section_is_off_by_default_and_parses() {
        // C-2: no section means the pre-subnet-router behaviour.
        let cfg: Config = toml::from_str("").unwrap();
        assert_eq!(cfg.router, RouterConfig::default());
        assert!(!cfg.router.accept_routes);
        assert!(cfg.router.advertise_routes.is_empty());
        assert!(cfg.router.auto_nat);

        let cfg: Config = toml::from_str(
            r#"
[router]
advertise_routes = ["192.168.10.0/24", "172.20.0.0/16"]
accept_routes = true
auto_nat = false
lan_interface = "eth1"
"#,
        )
        .unwrap();
        assert_eq!(
            cfg.router.advertise_routes,
            strs(&["192.168.10.0/24", "172.20.0.0/16"])
        );
        assert!(cfg.router.accept_routes);
        assert!(!cfg.router.auto_nat);
        assert_eq!(cfg.router.lan_interface, "eth1");
    }

    #[test]
    fn routes_append_dedups_and_accept_is_sticky() {
        let mut cfg = Config::default();
        cfg.router.advertise_routes = strs(&["10.0.0.0/8"]);
        cfg.router.accept_routes = true;
        cfg.append_routes(strs(&[" 10.0.0.0/8 ", "192.168.10.0/24", ""]), false);
        assert_eq!(
            cfg.router.advertise_routes,
            strs(&["10.0.0.0/8", "192.168.10.0/24"])
        );
        // A flag that is absent must not turn a configured `true` off.
        assert!(cfg.router.accept_routes);
    }

    /// AC-16 (1): start-up validation collects every bad CIDR; on a
    /// consumer-only platform every CIDR is bad and the message names the
    /// platform.
    #[test]
    fn validate_routes_reports_all_failures_or_normalizes() {
        use crate::daemon::routes::{Protected, RouteError, platform_can_advertise};
        let mut cfg = Config::default();
        cfg.router.advertise_routes = strs(&["192.168.10.7/24", "0.0.0.0/0", "junk"]);
        let errors = cfg.validate_routes(&Protected::default()).unwrap_err();
        if platform_can_advertise() {
            // The first CIDR is merely un-normalized and passes.
            assert_eq!(errors.len(), 2);
            assert!(matches!(errors[0], RouteError::TooBroad(_)));
            assert!(matches!(errors[1], RouteError::Malformed(_)));
        } else {
            assert_eq!(errors.len(), 3);
            assert!(matches!(errors[0], RouteError::PlatformConsumerOnly { .. }));
            assert!(errors[0].to_string().contains(std::env::consts::OS));
        }

        let mut cfg = Config::default();
        cfg.router.advertise_routes = strs(&["192.168.10.7/24", "192.168.10.0/24"]);
        match cfg.validate_routes(&Protected::default()) {
            Ok(list) if platform_can_advertise() => {
                assert_eq!(list.len(), 1);
                assert_eq!(cfg.router.advertise_routes, strs(&["192.168.10.0/24"]));
            }
            Err(errors) if !platform_can_advertise() => {
                assert!(
                    errors
                        .iter()
                        .all(|e| matches!(e, RouteError::PlatformConsumerOnly { .. }))
                );
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn stun_appends_without_dropping_file_entries() {
        let mut cfg = cfg_with(&["stun.a:3478"], &[]);
        cfg.append_stuns(strs(&["stun.b:3478"]));

        assert_eq!(cfg.stun.servers, strs(&["stun.a:3478", "stun.b:3478"]));
    }

    #[test]
    fn stun_duplicates_are_deduped() {
        let mut cfg = cfg_with(&["stun.a:3478"], &[]);
        cfg.append_stuns(strs(&["stun.a:3478", "stun.b:3478"]));

        assert_eq!(cfg.stun.servers, strs(&["stun.a:3478", "stun.b:3478"]));
    }

    #[test]
    fn stun_blank_and_padded_entries_are_normalized() {
        let mut cfg = Config::default();
        cfg.append_stuns(strs(&[" stun.a:3478 ", "", "  "]));

        assert_eq!(cfg.stun.servers, strs(&["stun.a:3478"]));
    }

    #[test]
    fn derper_appends_without_dropping_file_entries() {
        let mut cfg = cfg_with(&[], &[("derp.a:8080", "tok-a")]);
        cfg.append_derpers(strs(&["derp.b:8080"]), strs(&["tok-b"]));

        assert_eq!(cfg.derper.servers.len(), 2);
        assert_eq!(cfg.derper.servers[0].address, "derp.a:8080");
        assert_eq!(cfg.derper.servers[0].token, "tok-a");
        assert_eq!(cfg.derper.servers[1].address, "derp.b:8080");
        assert_eq!(cfg.derper.servers[1].token, "tok-b");
    }

    #[test]
    fn fewer_tokens_than_servers_leaves_the_rest_empty() {
        let mut cfg = Config::default();
        cfg.append_derpers(
            strs(&["derp.a:8080", "derp.b:8080", "derp.c:8080"]),
            strs(&["tok-a"]),
        );

        let tokens: Vec<&str> = cfg
            .derper
            .servers
            .iter()
            .map(|s| s.token.as_str())
            .collect();
        assert_eq!(tokens, vec!["tok-a", "", ""]);
    }

    #[test]
    fn duplicate_addresses_are_deduped_and_tokens_refreshed() {
        let mut cfg = cfg_with(&[], &[("derp.a:8080", "old")]);
        cfg.append_derpers(strs(&["derp.a:8080"]), strs(&["new"]));

        assert_eq!(cfg.derper.servers.len(), 1);
        assert_eq!(cfg.derper.servers[0].token, "new");
    }

    #[test]
    fn empty_flag_token_keeps_the_configured_one() {
        // `--derper-server` alone must not silently de-authenticate a derper
        // that already has a working token in the file.
        let mut cfg = cfg_with(&[], &[("derp.a:8080", "keep-me")]);
        cfg.append_derpers(strs(&["derp.a:8080"]), Vec::new());

        assert_eq!(cfg.derper.servers[0].token, "keep-me");
    }

    #[test]
    fn derper_blank_and_padded_entries_are_normalized() {
        let mut cfg = Config::default();
        cfg.append_derpers(strs(&[" derp.a:8080 ", ""]), strs(&[" tok-a ", "ignored"]));

        assert_eq!(cfg.derper.servers.len(), 1);
        assert_eq!(cfg.derper.servers[0].address, "derp.a:8080");
        assert_eq!(cfg.derper.servers[0].token, "tok-a");
    }

    #[test]
    #[should_panic(expected = "tokens pair positionally with servers")]
    fn more_tokens_than_servers_is_rejected() {
        let mut cfg = Config::default();
        cfg.append_derpers(strs(&["derp.a:8080"]), strs(&["t1", "t2"]));
    }
}
