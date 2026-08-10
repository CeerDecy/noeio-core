use crate::config;
use crate::config::DerperInfo;
use dashmap::DashMap;
use tokio::sync::RwLock;

pub struct DerperManager {
    /// Known derper servers, keyed by address.
    pub servers: DashMap<String, DerperInfo>,
    pub picked_server: RwLock<Option<DerperInfo>>,
}

impl From<config::Derper> for DerperManager {
    fn from(derper: config::Derper) -> Self {
        let servers = DashMap::new();
        for s in derper.servers {
            servers.insert(s.address.clone(), s);
        }
        let mut manager = Self { servers, picked_server: Default::default() };
        manager.pick_server();

        manager
    }
}

impl DerperManager {
    pub fn append_derper_server(&self, server: DerperInfo) {
        self.servers.insert(server.address.clone(), server);
    }

    pub fn remove_derper_server(&self, address: &str) -> bool {
        self.servers.remove(address).is_some()
    }

    pub fn pick_server(&mut self) -> Option<DerperInfo> {
        let server = self.servers.iter().next().map(|s| s.value().clone());
        if let Some(server) = server.clone() {
            self.picked_server.get_mut().replace(server);
        }

        server
    }

    pub async fn current(&self) -> Option<DerperInfo> {
        let server = self.picked_server.read().await;
        server.clone()
    }
}
