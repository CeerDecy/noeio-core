use clap::{Parser, Subcommand, ValueEnum};
use noeio_proto::proto::derper::v1::CreateTokenResponse;
use std::path::PathBuf;
use std::time::Duration;

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
        /// Config file path, defaults to ~/.noeio/derper.toml
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
    /// Manage report tokens (talks to a running derper via its local socket)
    Token {
        #[command(subcommand)]
        command: TokenCommand,
    },
}

#[derive(Subcommand, Debug)]
pub enum TokenCommand {
    /// Issue a token granting Report access to a network
    Create {
        /// Network UUID the token is scoped to
        #[arg(short, long)]
        network: String,
        /// Token lifetime, e.g. "90d", "12h", "30m", or plain seconds.
        /// 0 means the token never expires. Defaults to the server default
        /// (90 days).
        #[arg(short, long)]
        ttl: Option<String>,
        /// Output format
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Text)]
        output: OutputFormat,
    },
    /// Check whether a token is usable
    Verify {
        /// The token to check
        token: String,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Text,
    Json,
    Yaml,
    Toml,
}

/// CLI-facing view of a created token.
#[derive(serde::Serialize)]
pub struct TokenOutput {
    pub token: String,
    pub expires_at: Option<u64>,
}

impl From<&CreateTokenResponse> for TokenOutput {
    fn from(resp: &CreateTokenResponse) -> Self {
        Self {
            token: resp.token.clone(),
            expires_at: resp.expires_at,
        }
    }
}

impl TokenOutput {
    pub fn print(&self, format: OutputFormat) -> Result<(), Box<dyn std::error::Error>> {
        match format {
            OutputFormat::Text => {
                // Bare token on stdout so it can be piped; metadata on stderr.
                println!("{}", self.token);
                match self.expires_at {
                    Some(exp) => eprintln!("expires_at (unix): {}", exp),
                    None => eprintln!("expires_at: never"),
                }
            }
            OutputFormat::Json => println!("{}", serde_json::to_string_pretty(self)?),
            // Both values are YAML-safe plain scalars (a JWT is base64url
            // segments joined by dots), so emit directly instead of pulling
            // in a YAML serializer dependency.
            OutputFormat::Yaml => {
                println!("token: {}", self.token);
                match self.expires_at {
                    Some(exp) => println!("expires_at: {}", exp),
                    None => println!("expires_at: null"),
                }
            }
            // TOML has no null: a never-expiring token simply omits the
            // `expires_at` key (serde skips `None`).
            OutputFormat::Toml => print!("{}", toml::to_string_pretty(self)?),
        }
        Ok(())
    }
}

/// Parse a human-friendly duration: plain seconds or a number with a
/// `s`/`m`/`h`/`d` suffix.
pub fn parse_ttl(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty duration".to_string());
    }

    if s.chars().all(|c| c.is_ascii_digit()) {
        let secs: u64 = s.parse().map_err(|e| format!("invalid duration '{}': {}", s, e))?;
        return Ok(Duration::from_secs(secs));
    }

    let (value, unit) = s.split_at(s.len() - 1);
    let value: u64 = value
        .parse()
        .map_err(|e| format!("invalid duration '{}': {}", s, e))?;

    let secs = match unit {
        "s" => value,
        "m" => value * 60,
        "h" => value * 60 * 60,
        "d" => value * 60 * 60 * 24,
        _ => return Err(format!("invalid duration unit '{}', expected s/m/h/d", unit)),
    };
    Ok(Duration::from_secs(secs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_suffixed_durations() {
        assert_eq!(parse_ttl("90d").unwrap(), Duration::from_secs(90 * 86400));
        assert_eq!(parse_ttl("12h").unwrap(), Duration::from_secs(12 * 3600));
        assert_eq!(parse_ttl("30m").unwrap(), Duration::from_secs(1800));
        assert_eq!(parse_ttl("45s").unwrap(), Duration::from_secs(45));
    }

    #[test]
    fn parses_plain_seconds() {
        assert_eq!(parse_ttl("3600").unwrap(), Duration::from_secs(3600));
    }

    #[test]
    fn rejects_bad_input() {
        assert!(parse_ttl("").is_err());
        assert!(parse_ttl("d").is_err());
        assert!(parse_ttl("10w").is_err());
        assert!(parse_ttl("abc").is_err());
    }
}
