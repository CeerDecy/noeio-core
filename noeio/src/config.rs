use std::path::PathBuf;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct Config {
    #[serde(default)]
    pub stun: Stun,
    #[serde(default)]
    pub derper: Derper,
}

impl Config {
    pub fn load(path: Option<PathBuf>) -> Self {
        let config = match path {
            Some(p) => {
                let content = std::fs::read_to_string(&p)
                    .unwrap_or_else(|e| panic!("failed to read config file '{}': {}", p.display(), e));
                toml::from_str(&content)
                    .unwrap_or_else(|e| panic!("failed to parse config file '{}': {}", p.display(), e))
            }
            None => {
                let home = std::env::home_dir().expect("cannot determine home directory");
                let config_dir = home.join(".noeio");
                let config_path = config_dir.join("config.toml");

                if !config_path.exists() {
                    std::fs::create_dir_all(&config_dir).expect("failed to create ~/.noeio");
                    let default_config = toml::to_string_pretty(&Config::default()).unwrap();
                    std::fs::write(&config_path, &default_config).expect("failed to write config.toml");
                    return Config::default();
                }

                let content = std::fs::read_to_string(&config_path).expect("failed to read config.toml");
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

            match self.derper.servers.iter_mut().find(|s| s.address == address) {
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
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct Noeio {
}

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
        }
    }

    fn strs(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
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

        let tokens: Vec<&str> = cfg.derper.servers.iter().map(|s| s.token.as_str()).collect();
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
