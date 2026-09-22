use crate::interface::virtual_nic::VirtualNic;
use dashmap::DashMap;
use noeio_common::host_info::PeerId;
use std::net::IpAddr;

/// The local virtual nics, keyed by our own peer id in the network each nic
/// joined.
///
/// This is a pure registry: it never touches the system routing table. Routes
/// through these nics are owned by [`crate::daemon::reconciler`], which
/// derives them from the router state and converges the kernel toward that —
/// an imperative `add` here with no matching `del` is exactly how zombie
/// routes came about.
#[derive(Default)]
pub struct NicManager {
    nics: DashMap<PeerId, VirtualNic>,
}

impl NicManager {
    pub fn new() -> Self {
        Self {
            nics: DashMap::new(),
        }
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

    /// `(nic id, interface name)` of every registered nic — what the
    /// reconciler needs to name a route's egress without holding a map guard.
    pub fn interfaces(&self) -> Vec<(PeerId, String)> {
        self.nics
            .iter()
            .map(|entry| (*entry.key(), entry.value().tun_name.clone()))
            .collect()
    }
}
