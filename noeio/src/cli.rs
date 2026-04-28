use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "pc-command")]
#[command(subcommand_required = true, arg_required_else_help = true)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Boot the noeio daemon
    Boot {
        /// Path to the configuration file
        #[arg(short, long)]
        config: Option<PathBuf>,
        /// UDP listen port
        #[arg(short, long, default_value_t = 2026)]
        port: u16,
    },
    /// Discover public address via STUN
    Stun,
    /// Run overlay network connectivity test
    OverlayTest,
    /// List resources
    List {
        #[command(subcommand)]
        resource: ListResource,
    },
    /// Create a new resource
    Create {
        #[command(subcommand)]
        resource: CreateResource,
    },
}

#[derive(Subcommand, Debug)]
pub enum ListResource {
    /// List all networks
    Network,
    /// List all virtual NICs
    Vnic,
}

#[derive(Subcommand, Debug)]
pub enum CreateResource {
    /// Create a new overlay network
    Network {
        /// Network name
        #[arg(short, long)]
        name: String,
        /// IP address
        #[arg(short, long)]
        ip: String,
        /// IP version (e.g. "v4", "v6")
        #[arg(long, default_value = "v4")]
        ip_version: String,
        /// CIDR (e.g. "24")
        #[arg(short, long)]
        cidr: String,
    },
    /// Create a new virtual NIC
    Vnic {
        /// IP address
        #[arg(short, long)]
        ip: String,
        /// IP version (e.g. "v4", "v6")
        #[arg(long, default_value = "v4")]
        ip_version: String,
        /// Network ID
        #[arg(short, long)]
        network: String,
    },
}
