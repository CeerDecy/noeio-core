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
                let home = std::env::var("HOME").expect("HOME not set");
                let config_dir = PathBuf::from(&home).join(".noeio");
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
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct Noeio {
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct Derper {
    #[serde(default)]
    pub servers: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct Stun {
    #[serde(default)]
    pub servers: Vec<String>,
}
