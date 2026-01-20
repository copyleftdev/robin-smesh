//! Filter Agent
//!
//! Ranks search results by relevance using LLM analysis.
//! - Senses: RawResult signals (batched)
//! - Emits: FilteredResult signals (top N)

use async_trait::async_trait;
use tracing::{debug, info};

use robin_core::{AgentType, Field, OsintPayload, Signal};

use crate::{AgentConfig, AgentError, OsintAgent, SharedBackend};

/// System prompt for relevance filtering
const FILTER_SYSTEM_PROMPT: &str = r#"
You are a Cybercrime Threat Intelligence Expert. You are given a dark web search query and a list of search results (index, link, title).

Your task is to select the Top 20 most relevant results for investigation.

Rules:
1. Output ONLY the indices of the top 20 most relevant results (comma-separated)
2. Order by relevance (most relevant first)
3. Skip results that appear to be spam, unrelated, or low-quality
4. If fewer than 20 are relevant, output only the relevant ones

Search Query: {query}

Search Results:
"#;

/// Filter agent - ranks results by relevance
pub struct FilterAgent {
    config: AgentConfig,
    backend: SharedBackend,
    batch_size: usize,
}

impl FilterAgent {
    pub fn new(config: AgentConfig, backend: SharedBackend) -> Self {
        Self {
            config,
            backend,
            batch_size: 50, // Process up to 50 results at a time
        }
    }

    async fn filter_results(
        &self,
        query: &str,
        results: &[(usize, String, String)], // (index, url, title)
    ) -> Result<Vec<usize>, AgentError> {
        // Format results for LLM
        let results_str: String = results
            .iter()
            .map(|(idx, url, title)| {
                // Truncate URL at .onion for display
                let short_url = url
                    .find(".onion")
                    .map(|i| &url[..i + 6])
                    .unwrap_or(url);
                format!("{}. {} - {}", idx, short_url, title)
            })
            .collect::<Vec<_>>()
            .join("\n");

        let system = FILTER_SYSTEM_PROMPT.replace("{query}", query);

        let response = self
            .backend
            .generate(&system, &results_str)
            .await
            .map_err(|e| AgentError::Llm(e.to_string()))?;

        // Parse indices from response
        let indices: Vec<usize> = response
            .split(|c: char| !c.is_ascii_digit())
            .filter_map(|s| s.parse().ok())
            .filter(|&idx| idx > 0 && idx <= results.len())
            .take(20)
            .collect();

        Ok(indices)
    }
}

#[async_trait]
impl OsintAgent for FilterAgent {
    fn id(&self) -> &str {
        &self.config.id
    }

    fn agent_type(&self) -> &str {
        "filter"
    }

    fn sense<'a>(&self, field: &'a Field) -> Vec<&'a Signal> {
        // First, check for refined queries to get the current query
        let _refined_signals = field.sense_where(|signal| {
            signal.effective_intensity(field.now()) >= self.config.sensing_threshold
                && matches!(&signal.payload, OsintPayload::RefinedQuery { .. })
        });

        // Then sense raw results
        field.sense_where(|signal| {
            signal.effective_intensity(field.now()) >= self.config.sensing_threshold
                && matches!(&signal.payload, OsintPayload::RawResult { .. })
        })
    }

    async fn process(&mut self, field: &mut Field) -> Result<Vec<String>, AgentError> {
        // Get current refined query
        let refined_signals: Vec<_> = field
            .sense_where(|s| matches!(&s.payload, OsintPayload::RefinedQuery { .. }))
            .into_iter()
            .cloned()
            .collect();

        let query = if let Some(signal) = refined_signals.first() {
            if let OsintPayload::RefinedQuery { refined, .. } = &signal.payload {
                refined.clone()
            } else {
                return Err(AgentError::NoWork);
            }
        } else {
            return Err(AgentError::NoWork);
        };

        // Collect raw results
        let raw_signals: Vec<_> = field
            .sense_where(|s| matches!(&s.payload, OsintPayload::RawResult { .. }))
            .into_iter()
            .cloned()
            .collect();

        if raw_signals.is_empty() {
            return Err(AgentError::NoWork);
        }

        info!("Filter processing {} raw results for query: {}", raw_signals.len(), query);

        // Build indexed list
        let indexed: Vec<(usize, String, String)> = raw_signals
            .iter()
            .enumerate()
            .filter_map(|(idx, signal)| {
                if let OsintPayload::RawResult { url, title, .. } = &signal.payload {
                    Some((idx + 1, url.clone(), title.clone()))
                } else {
                    None
                }
            })
            .take(self.batch_size)
            .collect();

        // Get filtered indices from LLM
        let selected_indices = self.filter_results(&query, &indexed).await?;
        info!("Filter selected {} relevant results", selected_indices.len());

        let mut emitted = Vec::new();

        // Emit filtered result signals
        for (rank, &idx) in selected_indices.iter().enumerate() {
            if let Some((_, url, title)) = indexed.iter().find(|(i, _, _)| *i == idx) {
                let relevance = 1.0 - (rank as f64 * 0.03); // Higher rank = higher relevance

                let filtered_signal = Signal::builder(OsintPayload::FilteredResult {
                    url: url.clone(),
                    title: title.clone(),
                    relevance,
                    reason: format!("Ranked #{} by relevance filter", rank + 1),
                })
                .origin(&self.config.id)
                .confidence(0.85)
                .ttl(120.0)
                .build();

                let hash = field.emit(filtered_signal);
                emitted.push(hash);
            }
        }

        debug!("Emitted {} filtered result signals", emitted.len());
        Ok(emitted)
    }

    fn heartbeat(&self, field: &mut Field) {
        let signal = Signal::builder(OsintPayload::Heartbeat {
            agent_id: self.config.id.clone(),
            agent_type: AgentType::Filter,
            capacity: 1.0,
        })
        .origin(&self.config.id)
        .ttl(10.0)
        .build();

        field.emit(signal);
    }
}
