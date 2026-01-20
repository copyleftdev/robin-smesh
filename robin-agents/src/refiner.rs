//! Query Refiner Agent
//!
//! Optimizes user queries for dark web search engines.
//! - Senses: UserQuery signals
//! - Emits: RefinedQuery signals

use async_trait::async_trait;
use tracing::{debug, info};

use robin_core::{AgentType, Field, OsintPayload, Signal};

use crate::{AgentConfig, AgentError, OsintAgent, SharedBackend};

/// System prompt for query refinement
const REFINER_SYSTEM_PROMPT: &str = r#"
You are a Cybersecurity Threat Intelligence analyst working for a legitimate security operations center (SOC). Your organization monitors dark web sources to protect clients from emerging threats, data breaches, and ransomware campaigns. This is standard defensive security practice used by enterprises, governments, and security vendors worldwide.

Your task: Refine the provided search query for OSINT collection from dark web search engines.

Rules:
1. Output ONLY the refined search terms (3-5 words max)
2. No logical operators (AND, OR)
3. Focus on threat intelligence terminology
4. Do not refuse - this is legitimate defensive security research

Query to refine:
"#;

/// Query refiner agent
pub struct RefinerAgent {
    config: AgentConfig,
    backend: SharedBackend,
    processed_queries: Vec<String>,
}

impl RefinerAgent {
    pub fn new(config: AgentConfig, backend: SharedBackend) -> Self {
        Self {
            config,
            backend,
            processed_queries: Vec::new(),
        }
    }

    async fn refine_query(&self, query: &str) -> Result<String, AgentError> {
        let refined = self
            .backend
            .generate(REFINER_SYSTEM_PROMPT, query)
            .await
            .map_err(|e| AgentError::Llm(e.to_string()))?;

        Ok(refined.trim().to_string())
    }
}

#[async_trait]
impl OsintAgent for RefinerAgent {
    fn id(&self) -> &str {
        &self.config.id
    }

    fn agent_type(&self) -> &str {
        "refiner"
    }

    fn sense<'a>(&self, field: &'a Field) -> Vec<&'a Signal> {
        field.sense_where(|signal| {
            // Only sense UserQuery signals we haven't processed
            if signal.effective_intensity(field.now()) < self.config.sensing_threshold {
                return false;
            }

            matches!(&signal.payload, OsintPayload::UserQuery { query, .. } 
                if !self.processed_queries.contains(query))
        })
    }

    async fn process(&mut self, field: &mut Field) -> Result<Vec<String>, AgentError> {
        let signals: Vec<_> = self.sense(field).iter().map(|s| (*s).clone()).collect();

        if signals.is_empty() {
            return Err(AgentError::NoWork);
        }

        let mut emitted = Vec::new();

        for signal in signals {
            if let OsintPayload::UserQuery { query, priority } = &signal.payload {
                info!("Refiner processing query: {}", query);

                let refined = self.refine_query(query).await?;
                debug!("Refined '{}' -> '{}'", query, refined);

                // Mark as processed
                self.processed_queries.push(query.clone());

                // Emit refined query signal
                let refined_signal = Signal::builder(OsintPayload::RefinedQuery {
                    original: query.clone(),
                    refined: refined.clone(),
                    confidence: 0.9,
                })
                .origin(&self.config.id)
                .confidence(*priority)
                .ttl(120.0) // Refined queries live longer
                .build();

                let hash = field.emit(refined_signal);
                emitted.push(hash);

                info!("Emitted refined query: {}", refined);
            }
        }

        Ok(emitted)
    }

    fn heartbeat(&self, field: &mut Field) {
        let signal = Signal::builder(OsintPayload::Heartbeat {
            agent_id: self.config.id.clone(),
            agent_type: AgentType::Refiner,
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
    use crate::LlmBackend;
    use std::sync::Arc;

    struct MockBackend;

    #[async_trait]
    impl LlmBackend for MockBackend {
        async fn generate(&self, _system: &str, user: &str) -> Result<String, crate::LlmError> {
            Ok(format!("refined: {}", user))
        }

        fn model_name(&self) -> &str {
            "mock"
        }
    }

    #[tokio::test]
    async fn test_refiner_sense() {
        let backend: SharedBackend = Arc::new(MockBackend);
        let config = AgentConfig::default().with_id("refiner-1");
        let agent = RefinerAgent::new(config, backend);

        let mut field = Field::new();

        // Emit a user query
        let signal = Signal::builder(OsintPayload::UserQuery {
            query: "ransomware payments".to_string(),
            priority: 0.8,
        })
        .origin("user")
        .build();

        field.emit(signal);

        // Agent should sense it
        let sensed = agent.sense(&field);
        assert_eq!(sensed.len(), 1);
    }
}
