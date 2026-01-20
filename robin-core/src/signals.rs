//! SMESH-inspired signals for dark web OSINT coordination
//!
//! Signals are environmental messages that:
//! - Have intensity that decays over time
//! - Can be reinforced by multiple observers
//! - Carry confidence scores
//! - Enable emergent consensus without central orchestration

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{Artifact, DEFAULT_DECAY_RATE, DEFAULT_TTL};

/// Decay functions for signal intensity over time
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum DecayFunction {
    /// Exponential decay: I(t) = I₀ * e^(-λt)
    #[default]
    Exponential,
    /// Linear decay: I(t) = I₀ * (1 - t/TTL)
    Linear,
    /// Step function: full intensity until TTL, then zero
    Step,
}

/// OSINT-specific signal payload types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum OsintPayload {
    /// User submitted a search query
    UserQuery {
        query: String,
        priority: f64,
    },

    /// Query refined for dark web search engines
    RefinedQuery {
        original: String,
        refined: String,
        confidence: f64,
    },

    /// Raw result from a search engine
    RawResult {
        url: String,
        title: String,
        engine: String,
    },

    /// Result filtered as relevant by an agent
    FilteredResult {
        url: String,
        title: String,
        relevance: f64,
        reason: String,
    },

    /// Content scraped from a dark web site
    ScrapedContent {
        url: String,
        title: String,
        text: String,
        char_count: usize,
    },

    /// Artifacts extracted from scraped content
    ExtractedArtifacts {
        source_url: String,
        artifacts: Vec<Artifact>,
    },

    /// Intelligence insight from analysis
    Insight {
        category: InsightCategory,
        content: String,
        sources: Vec<String>,
        confidence: f64,
    },

    /// Final investigation summary
    Summary {
        markdown: String,
        artifact_count: usize,
        source_count: usize,
    },

    /// Enriched artifacts from external OSINT sources
    EnrichedArtifacts {
        /// Original artifact that was enriched
        artifact: Artifact,
        /// External source (github, brave, shodan, etc.)
        source: String,
        /// Enrichment findings
        findings: Vec<EnrichmentFinding>,
    },

    /// Blockchain temporal analysis results
    BlockchainAnalysis {
        /// The cryptocurrency address analyzed
        address: String,
        /// Blockchain network (bitcoin, ethereum, etc.)
        chain: String,
        /// Analysis results
        analysis: WalletAnalysis,
    },

    /// Paste site content discovered
    PasteContent {
        /// URL of the paste
        url: String,
        /// Paste site name (pastebin, rentry, ghostbin, etc.)
        site: String,
        /// Title if available
        title: Option<String>,
        /// Raw content of the paste
        content: String,
        /// When the paste was created (if known)
        created_at: Option<String>,
        /// Paste author if available
        author: Option<String>,
    },

    /// Heartbeat signal for agent liveness
    Heartbeat {
        agent_id: String,
        agent_type: AgentType,
        capacity: f64,
    },

    /// Task claim signal (prevents duplicate work)
    TaskClaim {
        task_id: String,
        claimer_id: String,
        affinity: f64,
    },
}

/// Categories of intelligence insights
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InsightCategory {
    ThreatActor,
    Malware,
    Vulnerability,
    DataLeak,
    Infrastructure,
    Financial,
    Operational,
    Attribution,
}

/// Blockchain wallet temporal analysis results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletAnalysis {
    /// First transaction timestamp (Unix epoch)
    pub first_seen: Option<i64>,
    /// Last transaction timestamp (Unix epoch)
    pub last_seen: Option<i64>,
    /// Total number of transactions
    pub tx_count: u32,
    /// Total received (in smallest unit, e.g., satoshis)
    pub total_received: u64,
    /// Total sent (in smallest unit)
    pub total_sent: u64,
    /// Current balance (in smallest unit)
    pub balance: u64,
    /// Detected temporal patterns
    pub patterns: Vec<TemporalPattern>,
    /// Risk indicators
    pub risk_indicators: Vec<String>,
}

/// Temporal patterns detected in blockchain activity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporalPattern {
    /// Pattern type (e.g., "regular_interval", "burst_activity", "dormant_then_active")
    pub pattern_type: String,
    /// Human-readable description
    pub description: String,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f64,
    /// Supporting data points
    pub evidence: Vec<String>,
}

/// A finding from external OSINT enrichment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichmentFinding {
    /// Type of finding (github_repo, github_user, web_mention, etc.)
    pub finding_type: String,
    /// Title or summary of the finding
    pub title: String,
    /// URL where this was found
    pub url: Option<String>,
    /// Snippet/context of the finding
    pub snippet: String,
    /// Relevance score (0.0 - 1.0)
    pub relevance: f64,
}

/// Types of agents in the OSINT swarm
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentType {
    Refiner,
    Crawler,
    Filter,
    Scraper,
    Extractor,
    Enricher,
    BlockchainAnalyst,
    PasteMonitor,
    Analyst,
}

/// A signal in the OSINT field
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signal {
    /// Unique signal instance ID
    pub id: Uuid,

    /// Content-based hash for deduplication/reinforcement
    pub origin_hash: String,

    /// The payload (OSINT-specific data)
    pub payload: OsintPayload,

    /// Initial intensity (0.0 - 1.0)
    pub intensity: f64,

    /// Current intensity after decay
    pub current_intensity: f64,

    /// Time to live in seconds
    pub ttl: f64,

    /// Decay rate parameter
    pub decay_rate: f64,

    /// Decay function
    pub decay_function: DecayFunction,

    /// Sender's confidence (0.0 - 1.0)
    pub confidence: f64,

    /// ID of originating agent
    pub origin_agent_id: String,

    /// Creation timestamp
    pub created_at: DateTime<Utc>,

    /// Reinforcement count
    pub reinforcement_count: u32,

    /// IDs of agents that reinforced this signal
    pub reinforced_by: Vec<String>,
}

impl Signal {
    /// Create a new signal builder
    pub fn builder(payload: OsintPayload) -> SignalBuilder {
        SignalBuilder::new(payload)
    }

    /// Compute current intensity based on decay and elapsed time
    pub fn compute_intensity(&self, current_time: DateTime<Utc>) -> f64 {
        let age = (current_time - self.created_at).num_milliseconds() as f64 / 1000.0;

        if age < 0.0 {
            return self.intensity;
        }

        if age >= self.ttl {
            return 0.0;
        }

        match self.decay_function {
            DecayFunction::Exponential => self.intensity * (-self.decay_rate * age).exp(),
            DecayFunction::Linear => (self.intensity * (1.0 - age / self.ttl)).max(0.0),
            DecayFunction::Step => {
                if age < self.ttl {
                    self.intensity
                } else {
                    0.0
                }
            }
        }
    }

    /// Effective intensity = base * confidence * reinforcement boost
    pub fn effective_intensity(&self, current_time: DateTime<Utc>) -> f64 {
        let base = self.compute_intensity(current_time);
        let reinforcement_boost = 1.0 + (self.reinforcement_count as f64 * 0.1).min(0.5);
        (base * self.confidence * reinforcement_boost).min(1.0)
    }

    /// Check if signal has expired
    pub fn is_expired(&self, current_time: DateTime<Utc>) -> bool {
        let age = (current_time - self.created_at).num_milliseconds() as f64 / 1000.0;
        age >= self.ttl || self.compute_intensity(current_time) < 0.01
    }

    /// Reinforce this signal (agreement from another agent)
    pub fn reinforce(&mut self, reinforcer_id: &str) {
        if !self.reinforced_by.contains(&reinforcer_id.to_string()) {
            self.reinforced_by.push(reinforcer_id.to_string());
            self.reinforcement_count += 1;

            // Boost confidence with diminishing returns
            let boost = 0.1 / (1.0 + self.reinforcement_count as f64 * 0.5);
            self.confidence = (self.confidence + boost).min(1.0);
        }
    }

    fn compute_origin_hash(payload: &OsintPayload, origin_agent_id: &str) -> String {
        let mut hasher = Sha256::new();
        let payload_json = serde_json::to_string(payload).unwrap_or_default();
        hasher.update(payload_json.as_bytes());
        hasher.update(origin_agent_id.as_bytes());
        format!("{:x}", hasher.finalize())[..16].to_string()
    }
}

/// Builder for signals
pub struct SignalBuilder {
    payload: OsintPayload,
    intensity: f64,
    ttl: f64,
    decay_rate: f64,
    decay_function: DecayFunction,
    confidence: f64,
    origin_agent_id: String,
}

impl SignalBuilder {
    pub fn new(payload: OsintPayload) -> Self {
        Self {
            payload,
            intensity: 1.0,
            ttl: DEFAULT_TTL,
            decay_rate: DEFAULT_DECAY_RATE,
            decay_function: DecayFunction::default(),
            confidence: 1.0,
            origin_agent_id: String::new(),
        }
    }

    pub fn intensity(mut self, intensity: f64) -> Self {
        self.intensity = intensity.clamp(0.0, 1.0);
        self
    }

    pub fn ttl(mut self, ttl: f64) -> Self {
        self.ttl = ttl.max(0.0);
        self
    }

    pub fn decay_rate(mut self, rate: f64) -> Self {
        self.decay_rate = rate.max(0.0);
        self
    }

    pub fn decay_function(mut self, func: DecayFunction) -> Self {
        self.decay_function = func;
        self
    }

    pub fn confidence(mut self, confidence: f64) -> Self {
        self.confidence = confidence.clamp(0.0, 1.0);
        self
    }

    pub fn origin(mut self, agent_id: &str) -> Self {
        self.origin_agent_id = agent_id.to_string();
        self
    }

    pub fn build(self) -> Signal {
        let now = Utc::now();
        let origin_hash = Signal::compute_origin_hash(&self.payload, &self.origin_agent_id);

        Signal {
            id: Uuid::new_v4(),
            origin_hash,
            payload: self.payload,
            intensity: self.intensity,
            current_intensity: self.intensity,
            ttl: self.ttl,
            decay_rate: self.decay_rate,
            decay_function: self.decay_function,
            confidence: self.confidence,
            origin_agent_id: self.origin_agent_id,
            created_at: now,
            reinforcement_count: 0,
            reinforced_by: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signal_creation() {
        let signal = Signal::builder(OsintPayload::UserQuery {
            query: "ransomware payments".to_string(),
            priority: 0.8,
        })
        .intensity(0.9)
        .confidence(0.95)
        .origin("refiner-01")
        .build();

        assert_eq!(signal.intensity, 0.9);
        assert_eq!(signal.confidence, 0.95);
        assert!(!signal.origin_hash.is_empty());
    }

    #[test]
    fn test_exponential_decay() {
        let signal = Signal::builder(OsintPayload::UserQuery {
            query: "test".to_string(),
            priority: 1.0,
        })
        .intensity(1.0)
        .decay_rate(0.1)
        .build();

        let later = signal.created_at + chrono::Duration::seconds(10);
        let intensity = signal.compute_intensity(later);
        // e^(-0.1 * 10) ≈ 0.368
        assert!((intensity - 0.368).abs() < 0.01);
    }

    #[test]
    fn test_reinforcement() {
        let mut signal = Signal::builder(OsintPayload::UserQuery {
            query: "test".to_string(),
            priority: 1.0,
        })
        .confidence(0.5)
        .build();

        let initial_confidence = signal.confidence;
        signal.reinforce("agent-1");
        signal.reinforce("agent-2");
        signal.reinforce("agent-1"); // duplicate, should be ignored

        assert_eq!(signal.reinforcement_count, 2);
        assert!(signal.confidence > initial_confidence);
    }
}
