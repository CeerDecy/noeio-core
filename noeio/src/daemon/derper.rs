use crate::config;
use dashmap::DashSet;
use tokio::sync::RwLock;

pub struct DerperManager {
    pub servers: DashSet<String>,
    pub picked_server: RwLock<Option<String>>,
}

impl From<config::Derper> for DerperManager {
    fn from(derper: config::Derper) -> Self {
        let servers = DashSet::new();
        for s in derper.servers {
            servers.insert(s);
        }
        let mut manager = Self { servers, picked_server: Default::default() };
        manager.pick_server();
        
        manager
    }
}

impl DerperManager {
    pub fn append_derper_server(&self, server: String) {
        self.servers.insert(server);
    }

    pub fn remove_derper_server(&self, server: &str) -> bool {
        self.servers.remove(server).is_some()
    }

    pub fn pick_server(&mut self) -> Option<String> {
        let server = self.servers.iter().next().map(|s| s.clone());
        if let Some(server) = server.clone() {
            self.picked_server.get_mut().replace(server);
        }

        server
    }

    pub async fn current(&self) -> Option<String> {
        let server = self.picked_server.read().await;
        server.clone()
    }
}
