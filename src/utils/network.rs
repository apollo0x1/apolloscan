pub fn check_privileges() {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("Warning: Raw socket operations require root privileges");
        eprintln!("Some stealth features may be limited without root access");
    }
}
