pub mod proto {
    pub mod network {
        tonic::include_proto!("network");
    }
    
    pub mod nic {
        tonic::include_proto!("nic");
    }

    pub const FILE_DESCRIPTOR_SET: &[u8] = tonic::include_file_descriptor_set!("descriptor");
}