//! Scraper Agent
//!
//! Extracts content from filtered dark web URLs.
//! - Senses: FilteredResult signals
//! - Emits: ScrapedContent signals

use async_trait::async_trait;
use std::collections::HashSet;
use tracing::{debug, info, warn};

use robin_core::{AgentType, Field, OsintPayload, Signal};
use robin_tor::{scrape_url, TorConfig};

use crate::{AgentConfig, AgentError, OsintAgent};

/// Scraper agent - extracts content from dark web sites
pub struct ScraperAgent {
    config: AgentConfig,
    tor_config: TorConfig,
    scraped_urls: HashSet<String>,
}

impl ScraperAgent {
    pub fn new(config: AgentConfig, tor_config: TorConfig) -> Self {
        Self {
            config,
            tor_config,
            scraped_urls: HashSet::new(),
        }
    }

    pub fn with_default_tor(config: AgentConfig) -> Self {
        Self::new(config, TorConfig::default())
    }
}

#[async_trait]
impl OsintAgent for ScraperAgent {
    fn id(&self) -> &str {
        &self.config.id
    }

    fn agent_type(&self) -> &str {
        "scraper"
    }

    fn sense<'a>(&self, field: &'a Field) -> Vec<&'a Signal> {
        field.sense_where(|signal| {
            if signal.effective_intensity(field.now()) < self.config.sensing_threshold {
                return false;
            }

            match &signal.payload {
                OsintPayload::FilteredResult { url, .. } => {
                    !self.scraped_urls.contains(url)
                }
                _ => false,
            }
        })
    }

    async fn process(&mut self, field: &mut Field) -> Result<Vec<String>, AgentError> {
        let signals: Vec<_> = self.sense(field).iter().map(|s| (*s).clone()).collect();

        if signals.is_empty() {
            return Err(AgentError::NoWork);
        }

        let mut emitted = Vec::new();

        // Process URLs with limited concurrency
        let urls_to_scrape: Vec<(String, String)> = signals
            .iter()
            .filter_map(|signal| {
                if let OsintPayload::FilteredResult { url, title, .. } = &signal.payload {
                    Some((url.clone(), title.clone()))
                } else {
                    None
                }
            })
            .take(self.config.max_concurrent)
            .collect();

        info!("Scraper processing {} URLs", urls_to_scrape.len());

        for (url, title) in urls_to_scrape {
            // Mark as scraped (even if it fails, to avoid retrying)
            self.scraped_urls.insert(url.clone());

            match scrape_url(&url, &self.tor_config).await {
                Ok(page) => {
                    if page.text.is_empty() {
                        debug!("Empty content from {}", url);
                        continue;
                    }

                    let scraped_signal = Signal::builder(OsintPayload::ScrapedContent {
                        url: url.clone(),
                        title: page.title.unwrap_or(title),
                        text: page.text,
                        char_count: page.char_count,
                    })
                    .origin(&self.config.id)
                    .confidence(0.9)
                    .ttl(180.0) // Scraped content persists longer
                    .build();

                    let hash = field.emit(scraped_signal);
                    emitted.push(hash);

                    debug!("Scraped {} chars from {}", page.char_count, url);
                }
                Err(e) => {
                    warn!("Failed to scrape {}: {}", url, e);
                }
            }
        }

        info!("Scraper emitted {} content signals", emitted.len());
        Ok(emitted)
    }

    fn heartbeat(&self, field: &mut Field) {
        let capacity = if self.scraped_urls.len() < 10 {
            1.0
        } else {
            0.5
        };

        let signal = Signal::builder(OsintPayload::Heartbeat {
            agent_id: self.config.id.clone(),
            agent_type: AgentType::Scraper,
            capacity,
        })
        .origin(&self.config.id)
        .ttl(10.0)
        .build();

        field.emit(signal);
    }
}
