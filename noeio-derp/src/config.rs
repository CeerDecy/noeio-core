use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct Config {
    #[serde(default)]
    pub auth: Auth,
}

/// Token issuing / verification settings.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Auth {
    /// true: the derper issues and verifies tokens itself (HS256 with
    /// `secret`). false is reserved for centralized issuing, where the derper
    /// only verifies tokens signed by an external control plane.
    #[serde(default = "default_local")]
    pub local: bool,
    /// HS256 signing secret (hex). Auto-generated and persisted back to the
    /// config file when left empty. Rotating it invalidates every issued token.
    #[serde(default)]
    pub secret: String,
}

impl Default for Auth {
    fn default() -> Self {
        Auth {
            local: default_local(),
            secret: String::new(),
        }
    }
}

fn default_local() -> bool {
    true
}

impl Config {
    pub fn load(path: Option<PathBuf>) -> Self {
        let path = path.unwrap_or_else(|| {
            let home = std::env::var("HOME").expect("HOME not set");
            PathBuf::from(&home).join(".noeio").join("derper.toml")
        });

        let mut config = if path.exists() {
            let content = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("failed to read config file '{}': {}", path.display(), e));
            toml::from_str(&content)
                .unwrap_or_else(|e| panic!("failed to parse config file '{}': {}", path.display(), e))
        } else {
            Config::default()
        };

        if config.auth.local && config.auth.secret.is_empty() {
            config.auth.secret = generate_secret();
            tracing::info!("auth secret not configured, generated a new one");
            config.persist(&path);
        }

        tracing::debug!("config loaded: \n {:?}", config);

        config
    }

    /// Write the config back so an auto-generated secret survives restarts.
    fn persist(&self, path: &PathBuf) {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)
                .unwrap_or_else(|e| panic!("failed to create '{}': {}", dir.display(), e));
        }
        let content = toml::to_string_pretty(self).expect("failed to serialize config");
        std::fs::write(path, &content)
            .unwrap_or_else(|e| panic!("failed to write config file '{}': {}", path.display(), e));
        tracing::info!("config persisted to {}", path.display());
    }
}

fn generate_secret() -> String {
    let bytes: [u8; 32] = rand::random();
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_secret_is_64_hex_chars() {
        let secret = generate_secret();
        assert_eq!(secret.len(), 64);
        assert!(secret.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn auth_defaults_to_local_with_empty_secret() {
        let auth = Auth::default();
        assert!(auth.local);
        assert!(auth.secret.is_empty());
    }

    #[test]
    fn parses_full_auth_section() {
        let config: Config = toml::from_str(
            "[auth]\nlocal = true\nsecret = \"deadbeef\"\n",
        )
        .unwrap();
        assert!(config.auth.local);
        assert_eq!(config.auth.secret, "deadbeef");
    }

    #[test]
    fn empty_file_uses_defaults() {
        let config: Config = toml::from_str("").unwrap();
        assert!(config.auth.local);
        assert!(config.auth.secret.is_empty());
    }
}
