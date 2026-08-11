use crate::interface::virtual_nic::VirtualNic;
use dashmap::DashMap;
use dashmap::mapref::one::RefMut;
use noeio_common::host_info::PeerId;
use std::net::IpAddr;
use tun::DeviceWriter;

pub struct NicManager {
    nics: DashMap<PeerId, VirtualNic>,
}

impl NicManager {
    pub fn new() -> Self {
        Self {
            nics: DashMap::new(),
        }
    }

    pub async fn route(
        &self,
        id: Option<PeerId>,
        target: IpAddr,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(id) = id {
            let nic = match self.nics.get_mut(&id) {
                None => return Err(format!("can't get nic for peer id: {}", id).into()),
                Some(nic) => nic,
            };
            return nic.add_router_rule(target, "255.255.255.255", "7").await;
        };
        for nic in self.nics.iter_mut() {
            nic.add_router_rule(target, "255.255.255.255", "7").await?;
        }
        Ok(())
    }

    pub fn register(&self, ip: PeerId, nic: VirtualNic) {
        self.nics.insert(ip, nic);
    }

    pub fn get(&'_ self, ip: &PeerId) -> Option<dashmap::mapref::one::Ref<'_, PeerId, VirtualNic>> {
        self.nics.get(ip)
    }

    pub fn get_mut(
        &'_ self,
        ip: &PeerId,
    ) -> Option<dashmap::mapref::one::RefMut<'_, PeerId, VirtualNic>> {
        self.nics.get_mut(ip)
    }

    pub fn remove(&self, ip: &PeerId) -> Option<(PeerId, VirtualNic)> {
        self.nics.remove(ip)
    }

    pub fn contains(&self, ip: &PeerId) -> bool {
        self.nics.contains_key(ip)
    }

    pub fn peers(&self) -> Vec<PeerId> {
        self.nics.iter().map(|entry| *entry.key()).collect()
    }

    /// Overlay IPs of every registered virtual nic. Used to keep noeio's own
    /// interfaces out of the LAN addresses reported to the derper.
    pub fn ips(&self) -> Vec<IpAddr> {
        self.nics.iter().map(|entry| entry.value().ip).collect()
    }
}
