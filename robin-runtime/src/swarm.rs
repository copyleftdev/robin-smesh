//! Swarm Coordinator
//!
//! Manages the OSINT agent swarm using SMESH signal diffusion:
//! - No central orchestration
//! - Agents sense and emit signals independently
//! - Coordination emerges from signal reinforcement
//! - Field ticks advance time and decay signals

use std::time::Duration;
use tokio::time::interval;
use tracing::{debug, error, info, warn};

use robin_agents::{
    AgentConfig, AgentError, AnalystAgent, CrawlerAgent, EnrichmentAgent, EnrichmentConfig,
    ExtractorAgent, FilterAgent, OsintAgent, RefinerAgent, ScraperAgent, SharedBackend,
};
use robin_core::{Field, OsintPayload, Signal};
use robin_tor::TorConfig;

/// Swarm configuration
pub struct SwarmConfig {
    /// LLM backend (pre-constructed)
    pub backend: SharedBackend,
    /// Tor proxy configuration
    pub tor_config: TorConfig,
    /// Field tick interval in milliseconds
    pub tick_interval_ms: u64,
    /// Maximum runtime in seconds (0 = unlimited)
    pub max_runtime_secs: u64,
    /// Number of crawler agents
    pub num_crawlers: usize,
    /// Number of scraper agents
    pub num_scrapers: usize,
    /// Use multi-specialist analyst mode
    pub use_specialists: bool,
    /// Enable external OSINT enrichment (GitHub, Brave search)
    pub enable_enrichment: bool,
}

/// The OSINT swarm coordinator
pub struct Swarm {
    backend: SharedBackend,
    tor_config: TorConfig,
    tick_interval_ms: u64,
    max_runtime_secs: u64,
    use_specialists: bool,
    enable_enrichment: bool,
    field: Field,
    agents: Vec<Box<dyn OsintAgent>>,
}

impl Swarm {
    /// Create a new swarm with configuration
    pub fn new(config: SwarmConfig) -> Result<Self, anyhow::Error> {
        let use_specialists = config.use_specialists;
        let enable_enrichment = config.enable_enrichment;
        let mut swarm = Self {
            backend: config.backend,
            tor_config: config.tor_config,
            tick_interval_ms: config.tick_interval_ms,
            max_runtime_secs: config.max_runtime_secs,
            use_specialists,
            enable_enrichment,
            field: Field::new(),
            agents: Vec::new(),
        };

        // Initialize agents
        swarm.init_agents(config.num_crawlers, config.num_scrapers);

        Ok(swarm)
    }

    fn init_agents(&mut self, num_crawlers: usize, num_scrapers: usize) {
        // Refiner agent (1)
        let refiner = RefinerAgent::new(
            AgentConfig::default().with_id("refiner-1"),
            self.backend.clone(),
        );
        self.agents.push(Box::new(refiner));

        // Crawler agents
        for i in 0..num_crawlers {
            let crawler = CrawlerAgent::new(
                AgentConfig::default().with_id(&format!("crawler-{}", i + 1)),
                self.tor_config.clone(),
            );
            self.agents.push(Box::new(crawler));
        }

        // Filter agent (1)
        let filter = FilterAgent::new(
            AgentConfig::default().with_id("filter-1"),
            self.backend.clone(),
        );
        self.agents.push(Box::new(filter));

        // Scraper agents
        for i in 0..num_scrapers {
            let scraper = ScraperAgent::new(
                AgentConfig::default().with_id(&format!("scraper-{}", i + 1)),
                self.tor_config.clone(),
            );
            self.agents.push(Box::new(scraper));
        }

        // Extractor agent (1)
        let extractor = ExtractorAgent::new(AgentConfig::default().with_id("extractor-1"));
        self.agents.push(Box::new(extractor));

        // Enrichment agent (optional) - queries external OSINT sources
        if self.enable_enrichment {
            info!("Enabling external OSINT enrichment (GitHub, Brave)");
            let enricher = EnrichmentAgent::new(
                AgentConfig::default().with_id("enricher-1"),
                EnrichmentConfig::default(),
            );
            self.agents.push(Box::new(enricher));
        }

        // Analyst agent (1) - with or without specialists
        let analyst = if self.use_specialists {
            info!("Using multi-specialist analyst mode");
            AnalystAgent::new_with_specialists(
                AgentConfig::default().with_id("analyst-1"),
                self.backend.clone(),
            )
        } else {
            AnalystAgent::new(
                AgentConfig::default().with_id("analyst-1"),
                self.backend.clone(),
            )
        };
        self.agents.push(Box::new(analyst));

        info!("Initialized {} agents", self.agents.len());
    }

    /// Submit a query to the swarm
    pub fn submit_query(&mut self, query: &str, priority: f64) -> String {
        let signal = Signal::builder(OsintPayload::UserQuery {
            query: query.to_string(),
            priority,
        })
        .origin("user")
        .confidence(1.0)
        .ttl(300.0) // Query lives for 5 minutes
        .build();

        let hash = self.field.emit(signal);
        info!("Submitted query: {} (hash: {})", query, hash);
        hash
    }

    /// Run the swarm until completion or timeout
    pub async fn run(&mut self) -> Result<Option<String>, anyhow::Error> {
        let tick_duration = Duration::from_millis(self.tick_interval_ms);
        let mut ticker = interval(tick_duration);

        let start = std::time::Instant::now();
        let max_runtime = if self.max_runtime_secs > 0 {
            Duration::from_secs(self.max_runtime_secs)
        } else {
            Duration::from_secs(u64::MAX)
        };

        info!("Swarm starting with {} agents", self.agents.len());

        loop {
            ticker.tick().await;

            // Check timeout
            if start.elapsed() >= max_runtime {
                warn!("Swarm reached maximum runtime");
                break;
            }

            // Tick the field (decay signals)
            let tick_result = self.field.tick(self.tick_interval_ms as f64 / 1000.0);
            debug!(
                "Field tick: {} active, {} expired",
                tick_result.active_count, tick_result.expired_count
            );

            // Process each agent
            for agent in &mut self.agents {
                // Emit heartbeat
                agent.heartbeat(&mut self.field);

                // Process signals
                match agent.process(&mut self.field).await {
                    Ok(hashes) => {
                        if !hashes.is_empty() {
                            debug!(
                                "Agent {} emitted {} signals",
                                agent.id(),
                                hashes.len()
                            );
                        }
                    }
                    Err(AgentError::NoWork) => {
                        // Normal - agent has nothing to do this tick
                    }
                    Err(AgentError::NotReady(msg)) => {
                        debug!("Agent {} not ready: {}", agent.id(), msg);
                    }
                    Err(e) => {
                        error!("Agent {} error: {}", agent.id(), e);
                    }
                }
            }

            // Check for summary signal (completion)
            let summaries: Vec<_> = self
                .field
                .sense_where(|s| matches!(&s.payload, OsintPayload::Summary { .. }))
                .into_iter()
                .cloned()
                .collect();

            if let Some(summary_signal) = summaries.first() {
                if let OsintPayload::Summary { markdown, .. } = &summary_signal.payload {
                    info!("Swarm completed - summary generated");
                    return Ok(Some(markdown.clone()));
                }
            }

            // Print field stats periodically
            let stats = self.field.stats();
            if stats.active_signals > 0 {
                debug!(
                    "Field: {} active signals, {} reinforcements",
                    stats.active_signals, stats.total_reinforcements
                );
            }
        }

        Ok(None)
    }

    /// Get field statistics
    pub fn stats(&self) -> robin_core::FieldStats {
        self.field.stats()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use robin_agents::{create_backend, OpenAIBackendConfig};

    fn mock_backend() -> SharedBackend {
        create_backend(OpenAIBackendConfig {
            api_key: "test-key".to_string(),
            model: "gpt-4o-mini".to_string(),
            ..Default::default()
        })
        .unwrap()
    }

    #[test]
    fn test_swarm_creation() {
        let config = SwarmConfig {
            backend: mock_backend(),
            tor_config: TorConfig::default(),
            tick_interval_ms: 500,
            max_runtime_secs: 300,
            num_crawlers: 2,
            num_scrapers: 3,
            use_specialists: false,
            enable_enrichment: false,
        };

        let swarm = Swarm::new(config);
        assert!(swarm.is_ok());

        let swarm = swarm.unwrap();
        assert!(swarm.agents.len() >= 5);
    }

    #[test]
    fn test_submit_query() {
        let config = SwarmConfig {
            backend: mock_backend(),
            tor_config: TorConfig::default(),
            tick_interval_ms: 500,
            max_runtime_secs: 300,
            num_crawlers: 2,
            num_scrapers: 3,
            use_specialists: false,
            enable_enrichment: false,
        };

        let mut swarm = Swarm::new(config).unwrap();
        let hash = swarm.submit_query("ransomware payments", 0.8);
        assert!(!hash.is_empty());
        assert_eq!(swarm.field.active_count(), 1);
    }
}
