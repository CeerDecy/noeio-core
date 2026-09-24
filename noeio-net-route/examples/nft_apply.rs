//! Apply / clear the noeio nftables table from the command line, for manual
//! verification against `nft list table ip noeio` on a Linux host.
//! Usage: nft_apply apply <overlay/prefix> <lan_if> <tun_if> | nft_apply clear | nft_apply show
#[cfg(target_os = "linux")]
fn main() {
    use noeio_net_route::nftables::{NfSocket, Ruleset};
    let args: Vec<String> = std::env::args().collect();
    let mut nf = NfSocket::open().expect("open");
    match args.get(1).map(String::as_str) {
        Some("apply") => {
            let (net, prefix) = args[2].split_once('/').expect("overlay/prefix");
            let rules = Ruleset::new(
                (net.parse().unwrap(), prefix.parse().unwrap()),
                &args[3],
                &args[4],
                true,
            )
            .unwrap();
            nf.apply(&rules).expect("apply");
            println!("applied");
        }
        Some("clear") => {
            nf.clear().expect("clear");
            println!("cleared");
        }
        Some("show") => println!("{:#?}", nf.read_back().expect("read_back")),
        _ => eprintln!("usage: nft_apply apply <overlay/prefix> <lan_if> <tun_if> | clear | show"),
    }
}
#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("linux only");
}
