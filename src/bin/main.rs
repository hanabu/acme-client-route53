// Debug build connects Let's Encrypt staging endpoint
#[cfg(debug_assertions)]
const DEFAULT_ACME_ENDPOINT: &str = instant_acme::LetsEncrypt::Staging.url();

// Release build connects production endpoint
#[cfg(not(debug_assertions))]
const DEFAULT_ACME_ENDPOINT: &str = instant_acme::LetsEncrypt::Production.url();

#[derive(clap::Parser)]
#[command(version, about)]
struct Cli {
    /// Read configuration from file
    #[arg(
        short = 'c',
        long,
        value_name = "CONFIG FILE",
        default_value = "acme.toml"
    )]
    config_file: std::path::PathBuf,

    #[command(subcommand)]
    command: CliCommands,
}

#[derive(clap::Subcommand)]
enum CliCommands {
    /// Create new Let's encrypt account
    Register {
        /// If you agree the terms of service,
        /// then --agree-terms-of-service YES
        #[arg(long, value_name = "YES")]
        agree_terms_of_service: String,

        /// ACME server endpoint
        #[arg(long, default_value=DEFAULT_ACME_ENDPOINT)]
        endpoint: String,

        /// Your contact email addresses
        #[arg(required(true))]
        contacts: Vec<String>,
    },
    /// Update certificates
    Update {},
}

/// main() for generic environment
#[tokio::main]
async fn main() {
    use acme_client_route53::*;
    use clap::Parser;

    let cli = Cli::parse();

    match cli.command {
        CliCommands::Register {
            agree_terms_of_service,
            endpoint,
            contacts,
        } => {
            if &agree_terms_of_service != "YES" {
                panic!("You must agree terms of service first.");
            }
            if contacts.is_empty() {
                panic!("You need at least one contact email address.");
            }
            new_account(
                &cli.config_file,
                &endpoint,
                contacts.iter().map(|c| c.as_str()),
            )
            .await
            .unwrap();
        }
        CliCommands::Update {} => {
            let config = Config::from_file(&cli.config_file).await.unwrap();
            issue_certificates(&config).await.unwrap();
        }
    }
}
