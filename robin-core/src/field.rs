//! Signal Field - shared space where signals propagate and decay
//!
//! The field is the central coordination mechanism in SMESH:
//! - Agents emit signals into the field
//! - Signals decay over time
//! - Agents sense signals matching their interests
//! - Reinforcement from multiple agents builds consensus

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::{OsintPayload, Signal};

/// The shared field where signals exist and propagate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Field {
    /// Active signals (origin_hash -> Signal)
    signals: HashMap<String, Signal>,

    /// Signal history for analysis
    history: Vec<Signal>,

    /// Current simulation time
    current_time: DateTime<Utc>,

    /// Maximum signals to store in history
    max_history: usize,
}

impl Field {
    /// Create a new field
    pub fn new() -> Self {
        Self {
            signals: HashMap::new(),
            history: Vec::new(),
            current_time: Utc::now(),
            max_history: 10000,
        }
    }

    /// Get current time
    pub fn now(&self) -> DateTime<Utc> {
        self.current_time
    }

    /// Emit a signal into the field
    /// Returns the signal hash (for tracking)
    pub fn emit(&mut self, signal: Signal) -> String {
        let hash = signal.origin_hash.clone();

        // Check for existing signal to reinforce
        if let Some(existing) = self.signals.get_mut(&hash) {
            existing.reinforce(&signal.origin_agent_id);
            return hash;
        }

        self.signals.insert(hash.clone(), signal);
        hash
    }

    /// Advance time and process decay/expiration
    pub fn tick(&mut self, dt_seconds: f64) -> FieldTickResult {
        self.current_time += chrono::Duration::milliseconds((dt_seconds * 1000.0) as i64);

        let mut expired = Vec::new();

        for (hash, signal) in &mut self.signals {
            signal.current_intensity = signal.compute_intensity(self.current_time);
            if signal.is_expired(self.current_time) {
                expired.push(hash.clone());
            }
        }

        // Move expired signals to history
        for hash in &expired {
            if let Some(signal) = self.signals.remove(hash) {
                if self.history.len() < self.max_history {
                    self.history.push(signal);
                }
            }
        }

        FieldTickResult {
            expired_count: expired.len(),
            active_count: self.signals.len(),
        }
    }

    /// Sense all signals above a threshold intensity
    pub fn sense(&self, min_intensity: f64) -> Vec<&Signal> {
        self.signals
            .values()
            .filter(|s| s.effective_intensity(self.current_time) >= min_intensity)
            .collect()
    }

    /// Sense signals matching a predicate
    pub fn sense_where<F>(&self, predicate: F) -> Vec<&Signal>
    where
        F: Fn(&Signal) -> bool,
    {
        self.signals.values().filter(|s| predicate(s)).collect()
    }

    /// Sense signals by payload type
    pub fn sense_by_type(&self, min_intensity: f64) -> SignalsByType<'_> {
        let mut result = SignalsByType::default();

        for signal in self.sense(min_intensity) {
            match &signal.payload {
                OsintPayload::UserQuery { .. } => result.user_queries.push(signal),
                OsintPayload::RefinedQuery { .. } => result.refined_queries.push(signal),
                OsintPayload::RawResult { .. } => result.raw_results.push(signal),
                OsintPayload::FilteredResult { .. } => result.filtered_results.push(signal),
                OsintPayload::ScrapedContent { .. } => result.scraped_content.push(signal),
                OsintPayload::ExtractedArtifacts { .. } => result.extracted_artifacts.push(signal),
                OsintPayload::EnrichedArtifacts { .. } => result.enriched_artifacts.push(signal),
                OsintPayload::Insight { .. } => result.insights.push(signal),
                OsintPayload::Summary { .. } => result.summaries.push(signal),
                OsintPayload::Heartbeat { .. } => result.heartbeats.push(signal),
                OsintPayload::TaskClaim { .. } => result.task_claims.push(signal),
            }
        }

        result
    }

    /// Get a specific signal by hash
    pub fn get(&self, hash: &str) -> Option<&Signal> {
        self.signals.get(hash)
    }

    /// Get mutable reference to a signal
    pub fn get_mut(&mut self, hash: &str) -> Option<&mut Signal> {
        self.signals.get_mut(hash)
    }

    /// Reinforce a signal from an external agent
    pub fn reinforce(&mut self, hash: &str, agent_id: &str) -> bool {
        if let Some(signal) = self.signals.get_mut(hash) {
            signal.reinforce(agent_id);
            true
        } else {
            false
        }
    }

    /// Count of active signals
    pub fn active_count(&self) -> usize {
        self.signals.len()
    }

    /// Get field statistics
    pub fn stats(&self) -> FieldStats {
        let total_intensity: f64 = self.signals.values().map(|s| s.current_intensity).sum();
        let avg_intensity = if self.signals.is_empty() {
            0.0
        } else {
            total_intensity / self.signals.len() as f64
        };

        let total_reinforcements: u32 =
            self.signals.values().map(|s| s.reinforcement_count).sum();

        FieldStats {
            active_signals: self.signals.len(),
            total_intensity,
            avg_intensity,
            total_reinforcements,
            history_size: self.history.len(),
        }
    }

    /// Clear all signals (for testing)
    pub fn clear(&mut self) {
        self.signals.clear();
    }
}

impl Default for Field {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of a field tick operation
#[derive(Debug, Clone)]
pub struct FieldTickResult {
    pub expired_count: usize,
    pub active_count: usize,
}

/// Field statistics
#[derive(Debug, Clone)]
pub struct FieldStats {
    pub active_signals: usize,
    pub total_intensity: f64,
    pub avg_intensity: f64,
    pub total_reinforcements: u32,
    pub history_size: usize,
}

/// Signals grouped by payload type
#[derive(Debug, Default)]
pub struct SignalsByType<'a> {
    pub user_queries: Vec<&'a Signal>,
    pub refined_queries: Vec<&'a Signal>,
    pub raw_results: Vec<&'a Signal>,
    pub filtered_results: Vec<&'a Signal>,
    pub scraped_content: Vec<&'a Signal>,
    pub extracted_artifacts: Vec<&'a Signal>,
    pub enriched_artifacts: Vec<&'a Signal>,
    pub insights: Vec<&'a Signal>,
    pub summaries: Vec<&'a Signal>,
    pub heartbeats: Vec<&'a Signal>,
    pub task_claims: Vec<&'a Signal>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_field_emit_and_sense() {
        let mut field = Field::new();

        let signal = Signal::builder(OsintPayload::UserQuery {
            query: "test".to_string(),
            priority: 1.0,
        })
        .origin("agent-1")
        .build();

        let hash = field.emit(signal);
        assert!(!hash.is_empty());
        assert_eq!(field.active_count(), 1);

        let sensed = field.sense(0.1);
        assert_eq!(sensed.len(), 1);
    }

    #[test]
    fn test_field_reinforcement() {
        let mut field = Field::new();

        let signal1 = Signal::builder(OsintPayload::UserQuery {
            query: "test".to_string(),
            priority: 1.0,
        })
        .origin("agent-1")
        .build();

        let signal2 = Signal::builder(OsintPayload::UserQuery {
            query: "test".to_string(),
            priority: 1.0,
        })
        .origin("agent-1") // same origin_hash
        .build();

        field.emit(signal1);
        field.emit(signal2); // should reinforce

        assert_eq!(field.active_count(), 1);
        let signal = field.signals.values().next().unwrap();
        assert_eq!(signal.reinforcement_count, 1);
    }

    #[test]
    fn test_field_expiration() {
        let mut field = Field::new();

        let signal = Signal::builder(OsintPayload::UserQuery {
            query: "test".to_string(),
            priority: 1.0,
        })
        .ttl(1.0)
        .build();

        field.emit(signal);
        assert_eq!(field.active_count(), 1);

        // Advance past TTL
        let result = field.tick(2.0);
        assert_eq!(result.expired_count, 1);
        assert_eq!(field.active_count(), 0);
    }
}
