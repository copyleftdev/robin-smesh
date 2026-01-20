//! Extractor Agent
//!
//! Extracts intelligence artifacts (IOCs, TTPs, etc.) from scraped content.
//! - Senses: ScrapedContent signals
//! - Emits: ExtractedArtifacts signals

use async_trait::async_trait;
use std::collections::HashSet;
use tracing::{debug, info};

use robin_core::{extract_artifacts, AgentType, Field, OsintPayload, Signal};

use crate::{AgentConfig, AgentError, OsintAgent};

/// Extractor agent - identifies IOCs and artifacts in content
pub struct ExtractorAgent {
    config: AgentConfig,
    processed_urls: HashSet<String>,
}

impl ExtractorAgent {
    pub fn new(config: AgentConfig) -> Self {
        Self {
            config,
            processed_urls: HashSet::new(),
        }
    }
}

#[async_trait]
impl OsintAgent for ExtractorAgent {
    fn id(&self) -> &str {
        &self.config.id
    }

    fn agent_type(&self) -> &str {
        "extractor"
    }

    fn sense<'a>(&self, field: &'a Field) -> Vec<&'a Signal> {
        field.sense_where(|signal| {
            if signal.effective_intensity(field.now()) < self.config.sensing_threshold {
                return false;
            }

            match &signal.payload {
                OsintPayload::ScrapedContent { url, .. } => {
                    !self.processed_urls.contains(url)
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

        for signal in signals {
            if let OsintPayload::ScrapedContent { url, text, .. } = &signal.payload {
                // Mark as processed
                self.processed_urls.insert(url.clone());

                // Extract artifacts using regex patterns
                let artifacts = extract_artifacts(text, Some(url));

                if artifacts.is_empty() {
                    debug!("No artifacts found in {}", url);
                    continue;
                }

                info!("Extracted {} artifacts from {}", artifacts.len(), url);

                let artifact_signal = Signal::builder(OsintPayload::ExtractedArtifacts {
                    source_url: url.clone(),
                    artifacts,
                })
                .origin(&self.config.id)
                .confidence(0.85)
                .ttl(180.0)
                .build();

                let hash = field.emit(artifact_signal);
                emitted.push(hash);
            }
        }

        Ok(emitted)
    }

    fn heartbeat(&self, field: &mut Field) {
        let signal = Signal::builder(OsintPayload::Heartbeat {
            agent_id: self.config.id.clone(),
            agent_type: AgentType::Extractor,
            capacity: 1.0,
        })
        .origin(&self.config.id)
        .ttl(10.0)
        .build();

        field.emit(signal);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_extractor_sense() {
        let config = AgentConfig::default().with_id("extractor-1");
        let agent = ExtractorAgent::new(config);

        let mut field = Field::new();

        // Emit scraped content with artifacts
        let signal = Signal::builder(OsintPayload::ScrapedContent {
            url: "http://test.onion".to_string(),
            title: "Test".to_string(),
            text: "Contact: admin@test.onion BTC: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string(),
            char_count: 100,
        })
        .origin("scraper")
        .build();

        field.emit(signal);

        let sensed = agent.sense(&field);
        assert_eq!(sensed.len(), 1);
    }
}
