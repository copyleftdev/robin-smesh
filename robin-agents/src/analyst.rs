//! Analyst Agent
//!
//! Synthesizes intelligence summaries from scraped content and artifacts.
//! - Senses: ScrapedContent + ExtractedArtifacts signals
//! - Emits: Summary signal

use async_trait::async_trait;
use tracing::info;

use robin_core::{AgentType, Artifact, Field, OsintPayload, Signal};

use crate::{AgentConfig, AgentError, OsintAgent, SharedBackend};

/// System prompt for intelligence analysis
const ANALYST_SYSTEM_PROMPT: &str = r#"
You are a Cybercrime Threat Intelligence Expert tasked with generating investigative insights from dark web OSINT data.

Rules:
1. Analyze the provided dark web data (URLs, content, artifacts)
2. Output source links referenced for analysis
3. Provide detailed, evidence-based technical analysis
4. List intelligence artifacts with context (emails, crypto addresses, domains, threat actors, malware, TTPs)
5. Generate 3-5 key insights that are specific, actionable, and data-driven
6. Include suggested next steps for further investigation
7. Be objective and analytical
8. Ignore NSFW content

Output Format:
# Investigation Summary

## Input Query
{query}

## Source Links Referenced
- [list sources]

## Intelligence Artifacts
- [categorized artifacts with context]

## Key Insights
1. [insight with evidence]
2. [insight with evidence]
...

## Next Steps
- [recommended actions]
- [follow-up queries]

INPUT DATA:
"#;

/// Analyst agent - synthesizes intelligence summaries
pub struct AnalystAgent {
    config: AgentConfig,
    backend: SharedBackend,
    summary_generated: bool,
}

impl AnalystAgent {
    pub fn new(config: AgentConfig, backend: SharedBackend) -> Self {
        Self {
            config,
            backend,
            summary_generated: false,
        }
    }

    async fn generate_summary(
        &self,
        query: &str,
        content: &[(String, String)], // (url, text)
        artifacts: &[Artifact],
    ) -> Result<String, AgentError> {
        // Build input data string
        let mut input = String::new();

        // Add content summaries
        input.push_str("## Scraped Content\n\n");
        for (url, text) in content.iter().take(10) {
            // Truncate text for LLM context limits
            let truncated = if text.len() > 1500 {
                format!("{}...", &text[..1500])
            } else {
                text.clone()
            };
            input.push_str(&format!("### {}\n{}\n\n", url, truncated));
        }

        // Add artifacts
        input.push_str("## Extracted Artifacts\n\n");
        for artifact in artifacts.iter().take(50) {
            input.push_str(&format!(
                "- {:?}: {} (confidence: {:.2})\n",
                artifact.artifact_type, artifact.value, artifact.confidence
            ));
        }

        let system = ANALYST_SYSTEM_PROMPT.replace("{query}", query);

        let summary = self
            .backend
            .generate(&system, &input)
            .await
            .map_err(|e| AgentError::Llm(e.to_string()))?;

        Ok(summary)
    }
}

#[async_trait]
impl OsintAgent for AnalystAgent {
    fn id(&self) -> &str {
        &self.config.id
    }

    fn agent_type(&self) -> &str {
        "analyst"
    }

    fn sense<'a>(&self, field: &'a Field) -> Vec<&'a Signal> {
        if self.summary_generated {
            return Vec::new();
        }

        // Sense scraped content and artifacts
        field.sense_where(|signal| {
            signal.effective_intensity(field.now()) >= self.config.sensing_threshold
                && matches!(
                    &signal.payload,
                    OsintPayload::ScrapedContent { .. } | OsintPayload::ExtractedArtifacts { .. }
                )
        })
    }

    async fn process(&mut self, field: &mut Field) -> Result<Vec<String>, AgentError> {
        if self.summary_generated {
            return Err(AgentError::NoWork);
        }

        // Get the original query
        let refined_signals: Vec<_> = field
            .sense_where(|s| matches!(&s.payload, OsintPayload::RefinedQuery { .. }))
            .into_iter()
            .cloned()
            .collect();

        let query = if let Some(signal) = refined_signals.first() {
            if let OsintPayload::RefinedQuery { original, .. } = &signal.payload {
                original.clone()
            } else {
                "Unknown query".to_string()
            }
        } else {
            "Unknown query".to_string()
        };

        // Collect scraped content
        let content_signals: Vec<_> = field
            .sense_where(|s| matches!(&s.payload, OsintPayload::ScrapedContent { .. }))
            .into_iter()
            .cloned()
            .collect();

        if content_signals.len() < 3 {
            // Wait for more content before generating summary
            return Err(AgentError::NotReady(format!(
                "Only {} content signals, waiting for more",
                content_signals.len()
            )));
        }

        // Collect artifacts
        let artifact_signals: Vec<_> = field
            .sense_where(|s| matches!(&s.payload, OsintPayload::ExtractedArtifacts { .. }))
            .into_iter()
            .cloned()
            .collect();

        info!(
            "Analyst processing {} content signals, {} artifact signals",
            content_signals.len(),
            artifact_signals.len()
        );

        // Extract content tuples
        let content: Vec<(String, String)> = content_signals
            .iter()
            .filter_map(|signal| {
                if let OsintPayload::ScrapedContent { url, text, .. } = &signal.payload {
                    Some((url.clone(), text.clone()))
                } else {
                    None
                }
            })
            .collect();

        // Flatten artifacts
        let artifacts: Vec<Artifact> = artifact_signals
            .iter()
            .filter_map(|signal| {
                if let OsintPayload::ExtractedArtifacts { artifacts, .. } = &signal.payload {
                    Some(artifacts.clone())
                } else {
                    None
                }
            })
            .flatten()
            .collect();

        // Generate summary
        let summary = self.generate_summary(&query, &content, &artifacts).await?;

        self.summary_generated = true;

        // Emit summary signal
        let summary_signal = Signal::builder(OsintPayload::Summary {
            markdown: summary.clone(),
            artifact_count: artifacts.len(),
            source_count: content.len(),
        })
        .origin(&self.config.id)
        .confidence(0.95)
        .ttl(300.0) // Summary persists for 5 minutes
        .build();

        let hash = field.emit(summary_signal);

        info!("Analyst emitted summary with {} artifacts from {} sources", 
            artifacts.len(), content.len());

        Ok(vec![hash])
    }

    fn heartbeat(&self, field: &mut Field) {
        let signal = Signal::builder(OsintPayload::Heartbeat {
            agent_id: self.config.id.clone(),
            agent_type: AgentType::Analyst,
            capacity: if self.summary_generated { 0.0 } else { 1.0 },
        })
        .origin(&self.config.id)
        .ttl(10.0)
        .build();

        field.emit(signal);
    }
}
