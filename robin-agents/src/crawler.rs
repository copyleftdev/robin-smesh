//! Crawler Agent
//!
//! Searches dark web search engines for results.
//! - Senses: RefinedQuery signals
//! - Emits: RawResult signals

use async_trait::async_trait;
use tracing::{debug, info};

use robin_core::{active_engines, AgentType, Field, OsintPayload, Signal};
use robin_tor::{crawl_engines, TorConfig};

use crate::{AgentConfig, AgentError, OsintAgent};

/// Crawler agent - searches dark web search engines
pub struct CrawlerAgent {
    config: AgentConfig,
    tor_config: TorConfig,
    processed_queries: Vec<String>,
}

impl CrawlerAgent {
    pub fn new(config: AgentConfig, tor_config: TorConfig) -> Self {
        Self {
            config,
            tor_config,
            processed_queries: Vec::new(),
        }
    }

    pub fn with_default_tor(config: AgentConfig) -> Self {
        Self::new(config, TorConfig::default())
    }
}

#[async_trait]
impl OsintAgent for CrawlerAgent {
    fn id(&self) -> &str {
        &self.config.id
    }

    fn agent_type(&self) -> &str {
        "crawler"
    }

    fn sense<'a>(&self, field: &'a Field) -> Vec<&'a Signal> {
        field.sense_where(|signal| {
            if signal.effective_intensity(field.now()) < self.config.sensing_threshold {
                return false;
            }

            matches!(&signal.payload, OsintPayload::RefinedQuery { refined, .. }
                if !self.processed_queries.contains(refined))
        })
    }

    async fn process(&mut self, field: &mut Field) -> Result<Vec<String>, AgentError> {
        let signals: Vec<_> = self.sense(field).iter().map(|s| (*s).clone()).collect();

        if signals.is_empty() {
            return Err(AgentError::NoWork);
        }

        let mut emitted = Vec::new();

        for signal in signals {
            if let OsintPayload::RefinedQuery { refined, .. } = &signal.payload {
                info!("Crawler searching for: {}", refined);

                // Mark as processed
                self.processed_queries.push(refined.clone());

                // Get active search engines
                let engines: Vec<_> = active_engines().collect();
                debug!("Crawling {} search engines", engines.len());

                // Crawl all engines concurrently
                let results = crawl_engines(
                    &engines,
                    refined,
                    &self.tor_config,
                    self.config.max_concurrent,
                )
                .await;

                info!("Found {} raw results", results.len());

                // Emit a signal for each result
                for result in results {
                    let result_signal = Signal::builder(OsintPayload::RawResult {
                        url: result.url.clone(),
                        title: result.title.clone(),
                        engine: result.engine.clone(),
                    })
                    .origin(&self.config.id)
                    .confidence(0.7) // Lower confidence until filtered
                    .ttl(90.0)
                    .build();

                    let hash = field.emit(result_signal);
                    emitted.push(hash);
                }

                debug!("Emitted {} raw result signals", emitted.len());
            }
        }

        Ok(emitted)
    }

    fn heartbeat(&self, field: &mut Field) {
        let signal = Signal::builder(OsintPayload::Heartbeat {
            agent_id: self.config.id.clone(),
            agent_type: AgentType::Crawler,
            capacity: if self.processed_queries.len() < 3 {
                1.0
            } else {
                0.5
            },
        })
        .origin(&self.config.id)
        .ttl(10.0)
        .build();

        field.emit(signal);
    }
}
