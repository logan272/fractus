use clap::{ArgAction, Args, Parser, Subcommand};
use serde_json::Value;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "sss-cli")]
#[command(about = "sss cli for interacting with s3signer system", long_about = None)]
struct Cli {
    /// Specify the configuration file to use
    #[arg(long, short)]
    file: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Args)]
#[command(args_conflicts_with_subcommands = true)]
struct ConfigArgs {
    #[command(subcommand)]
    command: ConfigCommand,
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    #[group(required = true, multiple = false)]
    Get {
        #[arg(conflicts_with = "all")]
        key: Option<String>,
        #[arg(
            long,
            conflicts_with = "key",
            default_missing_value = "true",
            num_args = 0..=1,
            // --all true is not allowed, --all=true is allowed
            require_equals(true),
            action = ArgAction::Set
        )]
        all: Option<bool>,
    },
    Set {
        key: String,
        value: String,
    },
}

#[derive(Debug, Args)]
#[command(args_conflicts_with_subcommands = true)]
struct ListArgs {
    #[command(subcommand)]
    command: ListCommand,
}

#[derive(Debug, Subcommand)]
enum ListCommand {
    #[command(arg_required_else_help = true)]
    User {
        /// The email of the user
        email: String,
    },
    #[command(arg_required_else_help = true)]
    #[group(required = true, multiple = false)]
    Secret {
        /// The label of the secret
        #[arg(conflicts_with = "all")]
        label: Option<String>,
        #[arg(
            long,
            conflicts_with = "label",
            default_missing_value = "true",
            num_args = 0..=1,
            require_equals(true),
            action = ArgAction::Set
        )]
        all: Option<bool>,
    },
    #[command(arg_required_else_help = true)]
    Wallet {
        /// The label of the secret
        label: String,
    },
}

#[derive(Debug, Subcommand)]
enum Command {
    Config(ConfigArgs),
    #[command(arg_required_else_help = true)]
    List(ListArgs),
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let args = Cli::parse();

    if let Some(file) = args.file {
        println!("Using configuration file {:?}", file);
    }

    match args.command {
        Command::Config(args) => match args.command {
            ConfigCommand::Get { key, all } => {
                println!("Get key = {key:?}, all = {all:?}");
            }
            ConfigCommand::Set { key, value } => {
                println!("Set key = {key}, value = {value}");
            }
        },
        Command::List(args) => match args.command {
            ListCommand::User { email } => {
                println!("List user with email = {email}");
            }
            ListCommand::Secret { label, all: _ } => {
                if let Some(label) = label {
                    let s =
                        reqwest::get(format!("http://localhost:3000/v1/secret?label={}", label))
                            .await?
                            .json::<Value>()
                            .await?;
                    println!("{}", serde_json::to_string_pretty(&s)?);
                } else {
                    println!("List all secrets");
                }
            }
            ListCommand::Wallet { label } => {
                println!("List wallet with label = {label}");
            }
        },
    }

    Ok(())
}
