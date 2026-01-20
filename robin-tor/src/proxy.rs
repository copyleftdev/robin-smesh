//! Tor SOCKS5h proxy client
//!
//! Creates HTTP clients that route through Tor for .onion access.

use reqwest::{Client, Proxy};
use std::time::Duration;
use thiserror::Error;

/// Tor proxy configuration
#[derive(Debug, Clone)]
pub struct TorConfig {
    /// SOCKS5 proxy address (default: 127.0.0.1:9050)
    pub socks_addr: String,
    /// Request timeout in seconds
    pub timeout_secs: u64,
    /// Maximum retries per request
    pub max_retries: u32,
}

impl Default for TorConfig {
    fn default() -> Self {
        Self {
            socks_addr: "socks5h://127.0.0.1:9050".to_string(),
            timeout_secs: 45,
            max_retries: 3,
        }
    }
}

/// Errors from Tor networking
#[derive(Debug, Error)]
pub enum TorError {
    #[error("Failed to build Tor client: {0}")]
    ClientBuild(String),

    #[error("Request failed: {0}")]
    Request(#[from] reqwest::Error),

    #[error("Timeout after {0} seconds")]
    Timeout(u64),

    #[error("Max retries ({0}) exceeded")]
    MaxRetries(u32),

    #[error("Invalid URL: {0}")]
    InvalidUrl(String),
}

/// User agents for rotation
const USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:137.0) Gecko/20100101 Firefox/137.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.7; rv:137.0) Gecko/20100101 Firefox/137.0",
];

/// Get a random user agent
pub fn random_user_agent() -> &'static str {
    use rand::Rng;
    let idx = rand::thread_rng().gen_range(0..USER_AGENTS.len());
    USER_AGENTS[idx]
}

/// Create a Tor-enabled HTTP client
pub fn create_tor_client(config: &TorConfig) -> Result<Client, TorError> {
    let proxy = Proxy::all(&config.socks_addr)
        .map_err(|e| TorError::ClientBuild(e.to_string()))?;

    Client::builder()
        .proxy(proxy)
        .timeout(Duration::from_secs(config.timeout_secs))
        .user_agent(random_user_agent())
        .danger_accept_invalid_certs(true) // Many .onion sites have self-signed certs
        .build()
        .map_err(|e| TorError::ClientBuild(e.to_string()))
}

/// Check if Tor proxy is reachable
pub async fn check_tor_connection(config: &TorConfig) -> Result<bool, TorError> {
    let client = create_tor_client(config)?;
    
    // Try to reach a known .onion address (Tor Project's)
    let result = client
        .get("http://2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3ber7fzs2xqxczfebsid.onion/")
        .send()
        .await;

    match result {
        Ok(resp) => Ok(resp.status().is_success() || resp.status().is_redirection()),
        Err(_) => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = TorConfig::default();
        assert!(config.socks_addr.contains("9050"));
        assert_eq!(config.timeout_secs, 45);
    }

    #[test]
    fn test_random_user_agent() {
        let ua = random_user_agent();
        assert!(ua.contains("Mozilla"));
    }
}
