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
    let proto_files = collect_proto_files(&proto_dir);
    println!("Generated files: {:?}", proto_files);

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    tonic_prost_build::configure()
        .file_descriptor_set_path(out_dir.join("descriptor.bin"))
        .compile_protos(&proto_files, &[proto_dir])
        .unwrap();
}