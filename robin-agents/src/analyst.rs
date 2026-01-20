//! Analyst Agent
//!
//! Synthesizes intelligence summaries from scraped content and artifacts.
//! - Senses: ScrapedContent + ExtractedArtifacts signals
//! - Emits: Summary signal
//!
//! ## Multi-Specialist Mode
//!
//! When enabled, runs multiple specialist analysts (crypto, forensic, malware,
//! threat actor, network, OSINT) in parallel, then synthesizes via lead analyst.
//! Enable with `AnalystAgent::new_with_specialists()`.

use async_trait::async_trait;
use tracing::info;

use robin_core::{AgentType, Artifact, Field, OsintPayload, Signal};

use crate::{AgentConfig, AgentError, OsintAgent, SharedBackend, SpecialistSystem};

/// Analyst agent - synthesizes intelligence summaries
pub struct AnalystAgent {
    config: AgentConfig,
    backend: SharedBackend,
    specialist_system: Option<SpecialistSystem>,
    summary_generated: bool,
}

impl AnalystAgent {
    /// Create a new analyst with single-pass analysis (legacy mode)
    pub fn new(config: AgentConfig, backend: SharedBackend) -> Self {
        Self {
            config,
            backend,
            specialist_system: None,
            summary_generated: false,
        }
    }

    /// Create a new analyst with multi-specialist analysis
    pub fn new_with_specialists(config: AgentConfig, backend: SharedBackend) -> Self {
        let specialist_system = SpecialistSystem::new(backend.clone());
        Self {
            config,
            backend,
            specialist_system: Some(specialist_system),
            summary_generated: false,
        }
    }

    /// Check if multi-specialist mode is enabled
    pub fn has_specialists(&self) -> bool {
        self.specialist_system.is_some()
    }

    /// List available specialist analysts (if enabled)
    pub fn list_specialists(&self) -> Vec<&str> {
        self.specialist_system
            .as_ref()
            .map(|s| s.list_specialists())
            .unwrap_or_default()
    }

    async fn generate_summary(
        &self,
        query: &str,
        content: &[(String, String)], // (url, text)
        artifacts: &[Artifact],
    ) -> Result<String, AgentError> {
        // Build content string
        let content_str = content
            .iter()
            .take(10)
            .map(|(url, text)| {
                let truncated = if text.len() > 1500 {
                    format!("{}...", &text[..1500])
                } else {
                    text.clone()
                };
                format!("### {}\n{}\n", url, truncated)
            })
            .collect::<Vec<_>>()
            .join("\n");

        // Build artifacts string
        let artifacts_str = artifacts
            .iter()
            .take(50)
            .map(|a| format!("- {:?}: {} (confidence: {:.2})", a.artifact_type, a.value, a.confidence))
            .collect::<Vec<_>>()
            .join("\n");

        // Use specialist system if available, otherwise fall back to lead-only
        if let Some(ref specialist_system) = self.specialist_system {
            info!("Running multi-specialist analysis with {} specialists", 
                specialist_system.list_specialists().len());
            
            specialist_system
                .full_analysis(query, &content_str, &artifacts_str)
                .await
                .map_err(|e| AgentError::Llm(e.to_string()))
        } else {
            // Fallback: use lead analyst prompt directly
            let lead = crate::PersonaRegistry::load_embedded()
                .lead_analyst()
                .map(|p| p.system_prompt().to_string())
                .unwrap_or_else(|| "Analyze the following OSINT data and provide a summary.".to_string());

            let input = format!(
                "# Investigation Context\n\n## Original Query\n{}\n\n## Scraped Content\n{}\n\n## Extracted Artifacts\n{}",
                query, content_str, artifacts_str
            );

            self.backend
                .generate(&lead, &input)
                .await
                .map_err(|e| AgentError::Llm(e.to_string()))
        }
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
