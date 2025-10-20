use serde_json;
use tokio::fs;

use crate::scan::types::ScanResults;

pub async fn format_results(results: &ScanResults, output_file: &Option<String>) -> Result<(), Box<dyn std::error::Error>> {
    let json_output = serde_json::to_string_pretty(results)?;
    
    match output_file {
        Some(file) => {
            fs::write(file, json_output).await?;
            println!("Results saved to {}", file);
        },
        None => {
            println!("{}", json_output);
        }
    }
    
    Ok(())
}
