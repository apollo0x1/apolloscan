use crate::cli::Args;
use std::net::IpAddr;
use std::str::FromStr;

pub struct ScanConfig {
    pub target: String,
    pub scan_type: ScanType,
    pub ports: Vec<u16>,
    pub rate_limit: Option<u32>,
    pub timing: Timing,
    pub scripts: Vec<String>,
    pub apollo_stealth: bool,
    pub zombie: Option<String>,
    pub decoys: Option<Vec<IpAddr>>,
    pub fragment: bool,
    pub data_length: Option<u16>,
    pub ttl: Option<u8>,
    pub source_port: Option<u16>,
    pub max_retries: u8,
    pub spoof_ip: Option<IpAddr>,
    pub random_mac: bool,
    pub ids_bypass: bool,
    pub custom_signature: Option<String>,
}

#[derive(Debug, Clone)]
pub enum ScanType {
    Apollo,
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
    Apocalyptic,
}

impl ScanConfig {
    pub fn from_args(args: &Args) -> Self {
        Self {
            target: args.target.clone(),
            scan_type: args.scan_type.parse().unwrap_or(ScanType::Apollo),
            ports: parse_ports(&args.ports),
            rate_limit: args.rate,
            timing: parse_timing(&args.timing),
            scripts: args.scripts.clone().unwrap_or_default().split(',').map(|s| s.to_string()).collect(),
            apollo_stealth: args.apollo_stealth,
            zombie: args.zombie.clone(),
            decoys: args.decoys.as_ref().map(|d| 
                d.split(',').filter_map(|s| s.parse().ok()).collect()
            ),
            fragment: args.fragment,
            data_length: args.data_length,
            ttl: args.ttl,
            source_port: args.source_port,
            max_retries: args.max_retries.unwrap_or(1),
            spoof_ip: args.spoof_ip.as_ref().and_then(|s| s.parse().ok()),
            random_mac: args.random_mac,
            ids_bypass: args.ids_bypass,
            custom_signature: args.custom_signature.clone(),
        }
    }
}

fn parse_ports(ports: &Option<String>) -> Vec<u16> {
    match ports {
        Some(p) => {
            if p == "-" {
                (1..=65535).collect()
            } else if p.contains("-") {
                let parts: Vec<&str> = p.split("-").collect();
                if parts.len() == 2 {
                    if let (Ok(start), Ok(end)) = (parts[0].parse::<u16>(), parts[1].parse::<u16>()) {
                        return (start..=end).collect();
                    }
                }
                vec![]
            } else {
                p.split(',')
                    .filter_map(|s| s.parse().ok())
                    .collect()
            }
        },
        None => vec![21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995, 1433, 3306, 3389, 5432, 6379, 27017],
    }
}

fn parse_timing(timing: &str) -> Timing {
    match timing.to_lowercase().as_str() {
        "paranoid" => Timing::Paranoid,
        "sneaky" => Timing::Sneaky,
        "polite" => Timing::Polite,
        "aggressive" => Timing::Aggressive,
        "insane" => Timing::Insane,
        "apocalyptic" => Timing::Apocalyptic,
        _ => Timing::Normal,
    }
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
