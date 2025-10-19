mod cli;
mod config;
mod scan;
mod techniques;
mod evasion;
mod detection;
mod utils;
mod output;

use tracing_subscriber;
use cli::Args;
use config::ScanConfig;
use scan::perform_scan;
use output::format_results;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    
    let args = cli::parse_args();
    utils::check_privileges();
    
    let config = ScanConfig::from_args(&args);
    let mut results = perform_scan(&config).await?;
    results.finalize();
    
    format_results(&results, &args.output).await?;
    
    Ok(())
}
