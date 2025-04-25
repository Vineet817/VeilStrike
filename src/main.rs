use clap::Parser;
use std::path::PathBuf;

mod target;
mod recon;
mod utils;

use target::Target;

#[derive(Parser, Debug)]
#[command(name = "VeilStrike", about = "Autonomous Security Recon AI")]
struct Cli {
    #[arg(long)]
    url: Option<String>,
    #[arg(long)]
    ip: Option<String>,
    #[arg(long)]
    repo: Option<PathBuf>,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let count = vec![cli.url.is_some(), cli.ip.is_some(), cli.repo.is_some()]
        .iter()
        .filter(|x| **x)
        .count();

    if count != 1 {
        eprintln!("❌ Please provide exactly one of --url, --ip, or --repo.");
        std::process::exit(1);
    }

    match Target::new_from_args(cli.url, cli.ip, cli.repo) {
        Ok(target) => {
            println!("🔍 Target identified: {:?}", target);
            recon::run_recon(&target).await;
        }
        Err(e) => {
            eprintln!("❌ {}", e);
            std::process::exit(1);
        }
    }
}
