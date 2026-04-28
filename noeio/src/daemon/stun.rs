use dashmap::DashSet;
use crate::config;

pub struct StunManager {
    pub servers: DashSet<String>,
}

impl From<config::Stun> for StunManager {
    fn from(stun: config::Stun) -> Self {
        let servers = DashSet::new();
        for s in stun.servers {
            servers.insert(s);
        }
        Self { servers }
    }
}

impl StunManager {
    pub fn append_server(&self, server: String) {
        self.servers.insert(server);
    }

    pub fn remove_server(&self, server: &str) -> bool {
        self.servers.remove(server).is_some()
    }

    pub fn pick_server(&self) -> Option<String> {
        self.servers.iter().next().map(|s| s.clone())
    }
}
