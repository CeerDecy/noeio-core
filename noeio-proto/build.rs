use std::path::{Path, PathBuf};
use std::{env, fs};

fn collect_proto_files(dir: &Path) -> Vec<PathBuf> {
    let mut proto_files = Vec::new();
    if dir.is_dir() {
        let entries = fs::read_dir(dir).unwrap();
        for entry in entries {
            let path = entry.unwrap().path();
            if path.is_dir() {
                proto_files.extend(collect_proto_files(&path));
            } else if path.extension().map_or(false, |ext| ext == "proto") {
                proto_files.push(path);
            }
        }
    }
    proto_files
}

fn main() {
    let proto_dir = PathBuf::from("./protos");

    // Each cargo feature maps to one proto sub-tree.
    let mut proto_files = Vec::new();
    if env::var_os("CARGO_FEATURE_NOEIO").is_some() {
        proto_files.extend(collect_proto_files(&proto_dir.join("noeio")));
    }
    if env::var_os("CARGO_FEATURE_NOEIO_DERPER").is_some() {
        proto_files.extend(collect_proto_files(&proto_dir.join("noeio-derper")));
    }
    println!("Generated files: {:?}", proto_files);

    if proto_files.is_empty() {
        return;
    }

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    // Use the vendored protoc so builds (including `cargo install` on user
    // machines) never depend on a system protoc — distro packages are often
    // too old for proto3 optional fields (needs >= 3.15).
    // SAFETY: build scripts run single-threaded at this point.
    unsafe {
        env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path().unwrap());
        env::set_var(
            "PROTOC_INCLUDE",
            protoc_bin_vendored::include_path().unwrap(),
        );
    }

    tonic_prost_build::configure()
        .file_descriptor_set_path(out_dir.join("descriptor.bin"))
        .compile_protos(&proto_files, &[proto_dir])
        .unwrap();
}
