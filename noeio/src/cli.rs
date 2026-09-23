use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "noeio", version)]
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
        /// Extra STUN servers; pass several as a comma separated list, e.g.
        /// --stun stun.a.example:3478,stun.b.example:3478
        #[arg(long = "stun", value_delimiter = ',', value_name = "ADDR")]
        stun: Vec<String>,
        /// Extra derper servers; pass several as a comma separated list, e.g.
        /// --derper-server derp.a.example:8080,derp.b.example:8080
        #[arg(long = "derper-server", value_delimiter = ',', value_name = "ADDR")]
        derper_servers: Vec<String>,
        /// Report tokens, comma separated, paired positionally with
        /// --derper-server so the first token belongs to the first derper.
        /// Servers without a token report unauthenticated
        #[arg(long = "derper-token", value_delimiter = ',', value_name = "TOKEN")]
        derper_tokens: Vec<String>,
        /// Subnets this node routes for (subnet router role, Linux only);
        /// comma separated CIDRs, e.g. --advertise-routes 192.168.10.0/24,172.20.0.0/16
        #[arg(long = "advertise-routes", value_delimiter = ',', value_name = "CIDR")]
        advertise_routes: Vec<String>,
        /// Install subnet routes advertised by other nodes
        #[arg(long = "accept-routes")]
        accept_routes: bool,
    },
    /// Check Derper relay server RTT latency
    Netcheck,
    /// Create a new resource
    Create {
        #[command(subcommand)]
        resource: CreateResource,
    },
    /// Manage subnet routes on the running daemon
    Route {
        #[command(subcommand)]
        command: RouteCommand,
    },
}

#[derive(Subcommand, Debug)]
pub enum RouteCommand {
    /// Start routing for one or more subnets (Linux only), e.g.
    /// noeio route advertise 192.168.10.0/24 172.20.0.0/16
    Advertise {
        #[arg(required = true, value_name = "CIDR")]
        cidrs: Vec<String>,
    },
    /// Stop routing for one or more subnets
    Withdraw {
        #[arg(required = true, value_name = "CIDR")]
        cidrs: Vec<String>,
    },
    /// Show advertised and learned subnet routes with their state
    List,
}

#[derive(Subcommand, Debug)]
pub enum CreateResource {
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
