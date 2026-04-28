use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "pc-command")]
#[command(subcommand_required = true, arg_required_else_help = true)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    Boot {
        #[arg(short, long, default_value_t = 8080)]
        port: u16,
    },
}
