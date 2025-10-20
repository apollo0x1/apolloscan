pub mod types;
pub mod tcp;
pub mod udp;
pub mod advanced;

use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use futures::stream::{FuturesUnordered, StreamExt};
use tokio::sync::Semaphore;
use std::sync::Arc;
use tracing::{debug};
use trust_dns_resolver::Resolver;
use cidr::Ipv4Cidr;

use crate::config::ScanConfig;
use crate::scan::types::*;
use crate::utils::LoadingIndicator;
use crate::evasion::apply_stealth_modifications;

pub async fn resolve_targets(target: &str) -> Result<Vec<IpAddr>, Box<dyn std::error::Error>> {
    let mut spinner = LoadingIndicator::new("Resolving targets...");
    let resolver = Resolver::default()?;
    
    let result = if target.contains("/") {
        // CIDR notation
        Ok(Ipv4Cidr::from_str(target)?
            .iter()
            .map(|ip| IpAddr::V4(ip))
            .collect())
    } else if let Ok(ip) = target.parse::<IpAddr>() {
        // Single IP
        Ok(vec![ip])
    } else {
        // Hostname
        let response = resolver.lookup_ip(target)?;
        Ok(response.iter().collect())
    };
    
    spinner.finish();
    result
}

pub async fn perform_scan(config: &ScanConfig) -> Result<ScanResults, Box<dyn std::error::Error>> {
    let semaphore = config.rate_limit.map(|limit| 
        Arc::new(Semaphore::new(limit as usize))
    );
    
    let targets = resolve_targets(&config.target).await?;
    let mut scan_tasks = FuturesUnordered::new();
    
    // Initialize evasion report
    let mut results = ScanResults::new();
    
    // Apply stealth modifications if requested
    if config.apollo_stealth {
        apply_stealth_modifications(&mut results, config);
    }
    
    println!("Starting scan on {} targets...", targets.len());
    let mut spinner = LoadingIndicator::new("Scanning network...");
    
    for target in targets {
        for &port in &config.ports {
            let task = perform_port_scan(
                target,
                port,
                config,
                semaphore.clone(),
            );
            scan_tasks.push(task);
        }
    }
    
    let mut completed = 0;
    let total = scan_tasks.len();
    
    while let Some(result) = scan_tasks.next().await {
        if let Ok((target, scan_result)) = result {
            results.add_result(target.to_string(), scan_result);
        }
        
        completed += 1;
        if completed % 10 == 0 || completed == total {
            spinner.update();
        }
    }
    
    spinner.finish();
    
    // Run custom scripts on open ports
    if !config.scripts.is_empty() {
        let mut script_spinner = LoadingIndicator::new("Running custom scripts...");
        crate::scripts::run_custom_scripts(&mut results, &config.scripts).await?;
        script_spinner.finish();
    }
    
    Ok(results)
}

async fn perform_port_scan(
    target: IpAddr,
    port: u16,
    config: &ScanConfig,
    semaphore: Option<Arc<Semaphore>>,
) -> Result<(IpAddr, PortResult), Box<dyn std::error::Error>> {
    if let Some(semaphore) = &semaphore {
        let _permit = semaphore.acquire().await?;
        tokio::time::sleep(get_timing_delay(&config.timing)).await;
    }
    
    let socket_addr = SocketAddr::new(target, port);
    let result = match config.scan_type {
        ScanType::Apollo => advanced::apollo_scan(socket_addr, config).await,
        ScanType::Syn => tcp::syn_scan(socket_addr, config).await,
        ScanType::Fin => tcp::fin_scan(socket_addr, config).await,
        ScanType::Null => tcp::null_scan(socket_addr, config).await,
        ScanType::Xmas => tcp::xmas_scan(socket_addr, config).await,
        ScanType::Ack => tcp::ack_scan(socket_addr, config).await,
        ScanType::Udp => udp::udp_scan(socket_addr, config).await,
        ScanType::Idle => advanced::idle_scan(socket_addr, config).await,
        ScanType::Fragment => advanced::fragment_scan(socket_addr, config).await,
        ScanType::Decoy => advanced::decoy_scan(socket_addr, config).await,
        _ => tcp::tcp_connect_scan(socket_addr, config).await,
    };
    
    Ok((target, result))
}

fn get_timing_delay(timing: &Timing) -> tokio::time::Duration {
    match timing {
        Timing::Paranoid => tokio::time::Duration::from_secs(60),
        Timing::Sneaky => tokio::time::Duration::from_secs(10),
        Timing::Polite => tokio::time::Duration::from_millis(2000),
        Timing::Normal => tokio::time::Duration::from_millis(200),
        Timing::Aggressive => tokio::time::Duration::from_millis(20),
        Timing::Insane => tokio::time::Duration::from_millis(2),
        Timing::Apocalyptic => tokio::time::Duration::from_millis(0), // No delay - fastest possible
    }
}

fn detect_service(port: u16) -> Option<String> {
    match port {
        21 => Some("ftp".to_string()),
        22 => Some("ssh".to_string()),
        23 => Some("telnet".to_string()),
        25 => Some("smtp".to_string()),
        53 => Some("dns".to_string()),
        80 => Some("http".to_string()),
        110 => Some("pop3".to_string()),
        143 => Some("imap".to_string()),
        443 => Some("https".to_string()),
        993 => Some("imaps".to_string()),
        995 => Some("pop3s".to_string()),
        1433 => Some("mssql".to_string()),
        3306 => Some("mysql".to_string()),
        3389 => Some("ms-wbt-server".to_string()),
        5432 => Some("postgresql".to_string()),
        6379 => Some("redis".to_string()),
        27017 => Some("mongodb".to_string()),
        _ => None,
    }
}
