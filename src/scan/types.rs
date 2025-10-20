use std::str::FromStr;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub enum ScanType {
    Apollo,        // Custom advanced technique
    Syn,
    Fin,
    Null,
    Xmas,
    Ack,
    Udp,
    Idle,
    Fragment,
    Decoy,
    Connect,
    Custom(String),
}

#[derive(Debug, Clone)]
pub enum Timing {
    Paranoid,
    Sneaky,
    Polite,
    Normal,
    Aggressive,
    Insane,
    Apocalyptic,   // Custom extreme timing
}

impl FromStr for ScanType {
    type Err = ();
    
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "apollo" => Ok(ScanType::Apollo),
            "syn" => Ok(ScanType::Syn),
            "fin" => Ok(ScanType::Fin),
            "null" => Ok(ScanType::Null),
            "xmas" => Ok(ScanType::Xmas),
            "ack" => Ok(ScanType::Ack),
            "udp" => Ok(ScanType::Udp),
            "idle" => Ok(ScanType::Idle),
            "fragment" => Ok(ScanType::Fragment),
            "decoy" => Ok(ScanType::Decoy),
            "connect" => Ok(ScanType::Connect),
            _ => Ok(ScanType::Custom(s.to_string())),
        }
    }
}

impl FromStr for Timing {
    type Err = ();
    
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "paranoid" => Ok(Timing::Paranoid),
            "sneaky" => Ok(Timing::Sneaky),
            "polite" => Ok(Timing::Polite),
            "normal" => Ok(Timing::Normal),
            "aggressive" => Ok(Timing::Aggressive),
            "insane" => Ok(Timing::Insane),
            "apocalyptic" => Ok(Timing::Apocalyptic),
            _ => Ok(Timing::Normal),
        }
    }
}

// Core data structures

#[derive(Serialize, Deserialize)]
pub struct ScanResults {
    pub timestamp: DateTime<Utc>,
    pub targets: Vec<TargetResult>,
    pub summary: ScanSummary,
    pub scan_stats: ScanStats,
    pub evasion_report: Option<EvasionReport>,
}

#[derive(Serialize, Deserialize)]
pub struct TargetResult {
    pub ip: String,
    pub hostname: Option<String>,
    pub ports: Vec<PortResult>,
    pub os_detection: Option<OSDetection>,
    pub scripts: Vec<ScriptResult>,
    pub fingerprint: Option<HostFingerprint>,
    pub evasion_success: Option<bool>,
}

#[derive(Serialize, Deserialize)]
pub struct PortResult {
    pub port: u16,
    pub protocol: String,
    pub state: PortState,
    pub service: Option<String>,
    pub version: Option<String>,
    pub confidence: f32,
    pub reason: String,
    pub ttl: Option<u8>,
    pub response_time: Option<f64>,
    pub packet_analysis: Option<PacketAnalysis>,
}

#[derive(Serialize, Deserialize)]
pub struct PacketAnalysis {
    pub ip_id: Option<u16>,
    pub tcp_sequence: Option<u32>,
    pub tcp_ack: Option<u32>,
    pub window_size: Option<u16>,
    pub tcp_options: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
    Unfiltered,
    OpenFiltered,
    ClosedFiltered,
}

#[derive(Serialize, Deserialize)]
pub struct ScanSummary {
    pub total_hosts: u32,
    pub total_ports: u32,
    pub open_ports: u32,
}

#[derive(Serialize, Deserialize)]
pub struct ScanStats {
    pub start_time: DateTime<Utc>,
    pub end_time: Option<DateTime<Utc>>,
    pub duration: Option<f64>,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub packets_dropped: u64,
    pub evasion_techniques_used: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub struct EvasionReport {
    pub techniques_successful: Vec<String>,
    pub ids_avoided: Vec<String>,
    pub firewall_bypassed: Option<bool>,
    pub packet_modifications: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub struct OSDetection {
    pub name: String,
    pub confidence: f32,
    pub fingerprints: Vec<String>,
    pub icmp_response: Option<String>,
    pub tcp_isn_analysis: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct ScriptResult {
    pub name: String,
    pub output: String,
    pub risk_level: String,
    pub stealth_score: f32,
}

#[derive(Serialize, Deserialize)]
pub struct HostFingerprint {
    pub tcp_sequence: String,
    pub ip_id_sequence: String,
    pub tcp_ts_sequence: Option<String>,
    pub service_scan_results: HashMap<u16, ServiceProbe>,
    pub raw_packet_data: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct ServiceProbe {
    pub probe_name: String,
    pub response: String,
    pub service: String,
    pub version: Option<String>,
    pub encrypted: bool,
}

impl ScanResults {
    pub fn new() -> Self {
        Self {
            timestamp: Utc::now(),
            targets: Vec::new(),
            summary: ScanSummary {
                total_hosts: 0,
                total_ports: 0,
                open_ports: 0,
            },
            scan_stats: ScanStats {
                start_time: Utc::now(),
                end_time: None,
                duration: None,
                packets_sent: 0,
                packets_received: 0,
                packets_dropped: 0,
                evasion_techniques_used: vec![],
            },
            evasion_report: None,
        }
    }
    
    pub fn add_result(&mut self, target: String, port_result: PortResult) {
        self.summary.total_ports += 1;
        if matches!(port_result.state, PortState::Open) {
            self.summary.open_ports += 1;
        }
    }
    
    pub fn finalize(&mut self) {
        self.scan_stats.end_time = Some(Utc::now());
        // In a real implementation, we would calculate actual duration and packet stats
    }
    
    pub fn add_evasion_technique(&mut self, technique: String) {
        self.scan_stats.evasion_techniques_used.push(technique);
    }
}
