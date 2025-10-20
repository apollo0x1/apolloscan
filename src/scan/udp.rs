use std::net::SocketAddr;
use tokio::net::UdpSocket;
use tokio::time::{timeout, Duration};
use std::time::Instant;
use tracing::{debug};

use crate::config::ScanConfig;
use crate::scan::types::{PortResult, PortState};

pub async fn udp_scan(socket_addr: SocketAddr, config: &ScanConfig) -> PortResult {
    debug!("Performing UDP scan on {}", socket_addr);
    
    // UDP scanning is challenging because:
    // 1. Open ports typically don't respond to empty UDP packets
    // 2. Closed ports send ICMP "port unreachable"
    // 3. Filtered ports don't respond or send ICMP errors
    
    let timeout_duration = match config.timing {
        crate::scan::types::Timing::Paranoid => Duration::from_secs(20),
        crate::scan::types::Timing::Sneaky => Duration::from_secs(10),
        crate::scan::types::Timing::Polite => Duration::from_secs(5),
        crate::scan::types::Timing::Normal => Duration::from_secs(2),
        crate::scan::types::Timing::Aggressive => Duration::from_millis(1000),
        crate::scan::types::Timing::Insane => Duration::from_millis(200),
        crate::scan::types::Timing::Apocalyptic => Duration::from_millis(50),
    };
    
    let start_time = Instant::now();
    
    // Create a UDP socket
    let socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(_) => {
            return PortResult {
                port: socket_addr.port(),
                protocol: "udp".to_string(),
                state: PortState::Filtered,
                service: None,
                version: None,
                confidence: 0.3,
                reason: "socket-bind-failed".to_string(),
                ttl: None,
                response_time: Some(start_time.elapsed().as_secs_f64()),
                packet_analysis: None,
            };
        }
    };
    
    // Send an empty UDP packet
    let send_result = socket.send_to(&[], socket_addr).await;
    if send_result.is_err() {
        return PortResult {
            port: socket_addr.port(),
            protocol: "udp".to_string(),
            state: PortState::Filtered,
            service: None,
            version: None,
            confidence: 0.5,
            reason: "send-failed".to_string(),
            ttl: None,
            response_time: Some(start_time.elapsed().as_secs_f64()),
            packet_analysis: None,
        };
    }
    
    // Wait for response
    let mut buffer = [0; 1024];
    match timeout(timeout_duration, socket.recv_from(&mut buffer)).await {
        Ok(Ok((_, _))) => {
            // Received a response, port is likely open
            PortResult {
                port: socket_addr.port(),
                protocol: "udp".to_string(),
                state: PortState::Open,
                service: super::detect_service(socket_addr.port()),
                version: None,
                confidence: 0.9,
                reason: "udp-response".to_string(),
                ttl: None,
                response_time: Some(start_time.elapsed().as_secs_f64()),
                packet_analysis: None,
            }
        }
        Ok(Err(_)) => {
            // Error receiving, port is likely filtered
            PortResult {
                port: socket_addr.port(),
                protocol: "udp".to_string(),
                state: PortState::Filtered,
                service: None,
                version: None,
                confidence: 0.7,
                reason: "recv-error".to_string(),
                ttl: None,
                response_time: Some(start_time.elapsed().as_secs_f64()),
                packet_analysis: None,
            }
        }
        Err(_) => {
            // Timeout, port is likely open|filtered (no response)
            PortResult {
                port: socket_addr.port(),
                protocol: "udp".to_string(),
                state: PortState::OpenFiltered,
                service: None,
                version: None,
                confidence: 0.6,
                reason: "no-response".to_string(),
                ttl: None,
                response_time: Some(timeout_duration.as_secs_f64()),
                packet_analysis: None,
            }
        }
    }
}
