use std::io::{self, Write};

pub struct LoadingIndicator {
    spinner: Vec<&'static str>,
    current: usize,
    message: String,
}

impl LoadingIndicator {
    pub fn new(message: &str) -> Self {
        Self {
            spinner: vec!["|", "/", "-", "\\"],
            current: 0,
            message: message.to_string(),
        }
    }
    
    pub fn update(&mut self) {
        print!("\r{} {} ", self.spinner[self.current], self.message);
        io::stdout().flush().unwrap();
        self.current = (self.current + 1) % self.spinner.len();
    }
    
    pub fn finish(&self) {
        print!("\r[+] {} completed\n", self.message);
        io::stdout().flush().unwrap();
    }
}
