mod cli;
mod config;
mod scan;
mod output;
mod evasion;
mod fingerprint;
mod scripts;
mod utils;

use clap::Parser;
use tracing::{info, error};

use cli::Args;
use config::ScanConfig;
use scan::perform_scan;
use output::format_results;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    
    let args = Args::parse();
    info!("Starting Apollo Scan Ultimate Network Scanner");
    info!("Professional Network Security Tool");
    
    // Verify we have root privileges for raw socket operations
    if unsafe { libc::geteuid() } != 0 {
        error!("Warning: Raw socket operations require root privileges");
        error!("Some stealth features may be limited without root access");
    }
    
    let config = ScanConfig::from_args(&args);
    let mut results = perform_scan(&config).await?;
    results.finalize();
    
    format_results(&results, &args.output).await?;
    
    Ok(())
}
