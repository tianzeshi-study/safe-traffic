mod client;
use anyhow::Result;
use clap::{Parser, Subcommand};
use std::net::IpAddr;
use std::path::PathBuf;

use crate::client::TrafficClient;

#[derive(Parser)]
#[command(name = "traffic-cli")]
#[command(about = "A CLI tool for traffic control and firewall management")]
#[command(version = "1.0")]
struct Cli {
    /// Unix socket path to connect to the traffic daemon
    #[arg(short, long, default_value = "/run/traffic.sock")]
    socket: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Limit traffic for a specific IP address
    Limit {
        /// IP address to limit
        #[arg(value_name = "IP")]
        ip: IpAddr,
        /// Speed limit in kbps
        #[arg(short, long)]
        kbps: u64,
        /// Burst limit (optional)
        #[arg(short, long)]
        burst: Option<u64>,
        /// Duration in seconds
        #[arg(short, long)]
        seconds: Option<u64>,
    },
    /// Ban an IP address for a specific duration
    Ban {
        /// IP address to ban
        #[arg(value_name = "IP")]
        ip: IpAddr,
        /// Duration in seconds
        #[arg(short, long)]
        seconds: Option<u64>,
    },

    /// Batch ban several IP addresses for a specific duration, use space separation between IPs
    BatchBan {
        /// IP addresses to ban
        #[arg(value_name = "IPs")]
        ips: Vec<IpAddr>,
        /// Duration in seconds
        #[arg(short, long)]
        seconds: Option<u64>,
    },

    /// Remove a ban or limit rule by rule ID
    Unblock {
        /// Rule ID to remove
        #[arg(value_name = "RULE_ID")]
        rule_id: String,
    },

    /// add exclude ip
    Exclude {
        /// ip to exclude
        #[arg(value_name = "ip")]
        ip: IpAddr,
    },

    /// List all active firewall rules
    List,
    /// Ping the traffic daemon
    Ping,
    /// clean up all rules
    Flush,
    /// stop daemon
    Stop,
    /// pause updating rules  
    Pause,
    /// resume updating rules  
    Resume,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // 连接到 traffic daemon
    let mut client = match TrafficClient::connect(&cli.socket).await {
        Ok(client) => client,
        Err(e) => {
            eprintln!(
                "Failed to connect to traffic daemon at {:?}: {}",
                cli.socket, e
            );
            std::process::exit(1);
        }
    };

    // 执行命令
    match cli.command {
        Commands::Limit {
            ip,
            kbps,
            burst,
            seconds,
        } => match client.limit(ip, kbps, burst, seconds).await {
            Ok(rule_id) => {
                println!("Traffic limit applied successfully!");
                println!("Rule ID: {}", rule_id);
                println!("IP: {}", ip);
                println!("Speed limit: {} kbps", kbps);
                if let Some(burst) = burst {
                    println!("Burst limit: {} kb", burst);
                }
            }
            Err(e) => {
                eprintln!("Failed to apply traffic limit: {}", e);
                std::process::exit(1);
            }
        },

        Commands::Ban { ip, seconds } => match client.ban(ip, seconds).await {
            Ok(rule_id) => {
                println!("IP banned successfully!");
                println!("Rule ID: {}", rule_id);
                println!("IP: {}", ip);
                println!(
                    "Duration: {} seconds",
                    seconds
                        .map(|s| s.to_string())
                        .unwrap_or("infinity".to_string())
                );
            }
            Err(e) => {
                eprintln!("Failed to ban IP: {}", e);
                std::process::exit(1);
            }
        },

        Commands::BatchBan { ips, seconds } => match client.batch_ban(ips.clone(), seconds).await {
            Ok(rule_ids) => {
                println!("IP banned successfully!");
                for (i, rule_id) in rule_ids.iter().enumerate() {
                    print!("Rule ID: {}    ", rule_id);
                    println!("IP: {}", ips[i]);
                }
                println!(
                    "Duration: {} seconds",
                    seconds
                        .map(|s| s.to_string())
                        .unwrap_or("infinity".to_string())
                );
            }
            Err(e) => {
                eprintln!("Failed to ban IP: {}", e);
                std::process::exit(1);
            }
        },

        Commands::Unblock { rule_id } => match client.unblock(rule_id.clone()).await {
            Ok(()) => {
                println!("Rule removed successfully!");
                println!("Rule ID: {}", rule_id);
            }
            Err(e) => {
                eprintln!("Failed to remove rule: {}", e);
                std::process::exit(1);
            }
        },

        Commands::Exclude { ip } => match client.exclude(ip).await {
            Ok(()) => {
                println!("exclude ip {} successfully!", ip);
            }
            Err(e) => {
                eprintln!("Failed to exclude ip: {}", e);
                std::process::exit(1);
            }
        },

        Commands::List => match client.get_active_rules().await {
            Ok(rules) => {
                if let Some(rules) = rules {
                    println!("Active firewall rules:");
                    println!(
                        "{:<36} {:<15} {:<12} {:<20}",
                        "Rule ID", "IP", "Type", "Created At"
                    );
                    println!("{}", "-".repeat(90));

                    for rule in rules {
                        println!(
                            "{:<36} {:<15} {:<12} {:<20}",
                            rule.id, rule.ip, rule.rule_type, rule.created_at
                        );
                    }
                } else {
                    println!("No active rules found.");
                }
            }
            Err(e) => {
                eprintln!("Failed to get active rules: {}", e);
                std::process::exit(1);
            }
        },

        Commands::Ping => match client.ping().await {
            Ok(()) => {
                println!("Pong! Traffic daemon is responding.");
            }
            Err(e) => {
                eprintln!("Failed to ping traffic daemon: {}", e);
                std::process::exit(1);
            }
        },

        Commands::Flush => match client.flush().await {
            Ok(msg) => {
                println!("{}", msg);
            }
            Err(e) => {
                eprintln!("Failed to remove rules: {}", e);
                std::process::exit(1);
            }
        },

        Commands::Stop => match client.stop().await {
            Ok(msg) => {
                println!("{}", msg);
            }
            Err(e) => {
                eprintln!("Failed to stop: {}", e);
                std::process::exit(1);
            }
        },

        Commands::Pause => match client.pause().await {
            Ok(msg) => {
                println!("{}", msg);
            }
            Err(e) => {
                eprintln!("Failed to pause: {}", e);
                std::process::exit(1);
            }
        },

        Commands::Resume => match client.resume().await {
            Ok(msg) => {
                println!("{}", msg);
            }
            Err(e) => {
                eprintln!("Failed to resume: {}", e);
                std::process::exit(1);
            }
        },
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn verify_cli() {
        Cli::command().debug_assert();
    }

    #[test]
    fn test_limit_command_parsing() {
        let args = vec![
            "traffic-cli",
            "limit",
            "192.168.1.1",
            "--kbps",
            "1000",
            "--burst",
            "2000",
        ];

        let cli = Cli::try_parse_from(args).unwrap();
        match cli.command {
            Commands::Limit {
                ip,
                kbps,
                burst,
                seconds: _seconds,
            } => {
                assert_eq!(ip.to_string(), "192.168.1.1");
                assert_eq!(kbps, 1000);
                assert_eq!(burst, Some(2000));
            }
            _ => panic!("Expected Limit command"),
        }
    }

    #[test]
    fn test_ban_command_parsing() {
        let args = vec!["traffic-cli", "ban", "10.0.0.1", "--seconds", "3600"];

        let cli = Cli::try_parse_from(args).unwrap();
        match cli.command {
            Commands::Ban { ip, seconds } => {
                assert_eq!(ip.to_string(), "10.0.0.1");
                assert_eq!(seconds, Some(3600));
            }
            _ => panic!("Expected Ban command"),
        }
    }
}
