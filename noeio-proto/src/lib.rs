pub mod proto {
    #[cfg(feature = "noeio")]
    pub mod noeio {
        pub mod v1 {
            tonic::include_proto!("noeio.v1");
        }
    }

    #[cfg(feature = "noeio-derper")]
    pub mod derper {
        pub mod v1 {
            tonic::include_proto!("noeio.derper.v1");
        }
    }

    #[cfg(any(feature = "noeio", feature = "noeio-derper"))]
    pub const FILE_DESCRIPTOR_SET: &[u8] = tonic::include_file_descriptor_set!("descriptor");
}
