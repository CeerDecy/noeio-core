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
    },
    /// Check Derper relay server RTT latency
    Netcheck,
    /// Create a new resource
    Create {
        #[command(subcommand)]
        resource: CreateResource,
    },
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
