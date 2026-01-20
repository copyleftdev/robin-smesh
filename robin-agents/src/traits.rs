//! Common traits for OSINT agents

use async_trait::async_trait;
use robin_core::{Field, Signal};
use thiserror::Error;

/// Errors from agent operations
#[derive(Debug, Error)]
pub enum AgentError {
    #[error("LLM error: {0}")]
    Llm(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("No work available")]
    NoWork,

    #[error("Agent not ready: {0}")]
    NotReady(String),
}

/// Common interface for all OSINT agents
#[async_trait]
pub trait OsintAgent: Send + Sync {
    /// Unique agent identifier
    fn id(&self) -> &str;

    /// Agent type name
    fn agent_type(&self) -> &str;

    /// Sense relevant signals from the field
    fn sense<'a>(&self, field: &'a Field) -> Vec<&'a Signal>;

    /// Process sensed signals and emit new ones
    async fn process(&mut self, field: &mut Field) -> Result<Vec<String>, AgentError>;

    /// Emit a heartbeat signal
    fn heartbeat(&self, field: &mut Field);
}

/// Agent configuration
#[derive(Debug, Clone)]
pub struct AgentConfig {
    /// Unique agent ID
    pub id: String,
    /// Minimum signal intensity to sense
    pub sensing_threshold: f64,
    /// Maximum concurrent tasks
    pub max_concurrent: usize,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string()[..8].to_string(),
            sensing_threshold: 0.1,
            max_concurrent: 3,
        }
    }
}

impl AgentConfig {
    pub fn with_id(mut self, id: &str) -> Self {
        self.id = id.to_string();
        self
    }

    pub fn with_threshold(mut self, threshold: f64) -> Self {
        self.sensing_threshold = threshold;
        self
    }
}
