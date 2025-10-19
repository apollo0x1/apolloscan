use clap::Parser;

#[derive(Parser)]
#[command(author = "Apollo", version = "3.0", about = "Ultimate Network Scanner")]
pub struct Args {
    #[arg(short, long, help = "Target IP, hostname, or CIDR range")]
    pub target: String,
    
    #[arg(short, long, default_value = "apollo", help = "Scan type: apollo, syn, fin, null, xmas, ack, udp, idle, fragment, decoy")]
    pub scan_type: String,
    
    #[arg(long, help = "Port range (e.g., 1-1000 or 22,80,443)")]
    pub ports: Option<String>,
    
    #[arg(long, help = "Custom scripts to run")]
    pub scripts: Option<String>,
    
    #[arg(long, help = "Rate limit (packets per second)")]
    pub rate: Option<u32>,
    
    #[arg(long, default_value = "normal", help = "Timing template")]
    pub timing: String,
    
    #[arg(long, help = "Output file path")]
    pub output: Option<String>,
    
    #[arg(long, help = "Apollo stealth mode (advanced evasion techniques)")]
    pub apollo_stealth: bool,
    
    #[arg(long, help = "Zombie host for idle scanning")]
    pub zombie: Option<String>,
    
    #[arg(long, help = "Decoy hosts to obfuscate scan origin")]
    pub decoys: Option<String>,
    
    #[arg(long, help = "Enable fragmentation to bypass firewalls")]
    pub fragment: bool,
    
    #[arg(long, help = "Data length for packets")]
    pub data_length: Option<u16>,
    
    #[arg(long, help = "TTL value for packets")]
    pub ttl: Option<u8>,
    
    #[arg(long, help = "Source port to use")]
    pub source_port: Option<u16>,
    
    #[arg(long, help = "Number of retries for filtered ports")]
    pub max_retries: Option<u8>,
    
    #[arg(long, help = "Source IP address to spoof")]
    pub spoof_ip: Option<String>,
    
    #[arg(long, help = "Use random MAC address")]
    pub random_mac: bool,
    
    #[arg(long, help = "Bypass IDS by randomizing packet order")]
    pub ids_bypass: bool,
    
    #[arg(long, help = "Use custom packet signatures")]
    pub custom_signature: Option<String>,
}

pub fn parse_args() -> Args {
    Args::parse()
}
