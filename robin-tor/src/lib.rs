//! Robin×SMESH Tor Layer
//!
//! Provides Tor-based networking for dark web crawling:
//! - SOCKS5h proxy client (DNS resolution via Tor)
//! - Search engine querying
//! - Content scraping with retry logic

pub mod proxy;
pub mod crawler;
pub mod scraper;

pub use proxy::*;
pub use crawler::*;
pub use scraper::*;
