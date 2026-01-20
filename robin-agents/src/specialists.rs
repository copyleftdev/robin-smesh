//! Specialist Analyst System
//!
//! Runs multiple specialist analysts in parallel, each with their own
//! persona and expertise, then synthesizes results via the lead analyst.

use futures::future::join_all;
use tracing::{debug, info, warn};

use crate::{Persona, PersonaRegistry, SharedBackend, LlmError};

/// Result from a specialist analyst
#[derive(Debug, Clone)]
pub struct SpecialistReport {
    pub analyst_id: String,
    pub analyst_name: String,
    pub analysis: String,
}

/// The specialist analysis system
pub struct SpecialistSystem {
    backend: SharedBackend,
    registry: PersonaRegistry,
}

impl SpecialistSystem {
    /// Create a new specialist system with embedded personas
    pub fn new(backend: SharedBackend) -> Self {
        Self {
            backend,
            registry: PersonaRegistry::load_embedded(),
        }
    }

    /// Create with a custom persona registry
    pub fn with_registry(backend: SharedBackend, registry: PersonaRegistry) -> Self {
        Self { backend, registry }
    }

    /// Run all specialist analysts on the provided content
    pub async fn analyze_with_specialists(
        &self,
        query: &str,
        content: &str,
        artifacts: &str,
    ) -> Vec<SpecialistReport> {
        let specialists = self.registry.specialist_analysts();
        
        info!("Running {} specialist analysts", specialists.len());

        // Build the analysis context
        let context = format!(
            "Original Query: {}\n\n## Scraped Content\n{}\n\n## Extracted Artifacts\n{}",
            query, content, artifacts
        );

        // Run specialists in parallel
        let futures: Vec<_> = specialists
            .iter()
            .map(|persona| self.run_specialist(persona, &context))
            .collect();

        let results = join_all(futures).await;

        // Collect successful results
        results.into_iter().filter_map(|r| r.ok()).collect()
    }

    /// Run a single specialist analyst
    async fn run_specialist(
        &self,
        persona: &Persona,
        context: &str,
    ) -> Result<SpecialistReport, LlmError> {
        debug!("Running specialist: {}", persona.persona.name);

        let analysis = self
            .backend
            .generate(persona.system_prompt(), context)
            .await?;

        Ok(SpecialistReport {
            analyst_id: persona.persona.id.clone(),
            analyst_name: persona.persona.name.clone(),
            analysis,
        })
    }

    /// Synthesize specialist reports into a final summary using the lead analyst
    pub async fn synthesize(
        &self,
        query: &str,
        content: &str,
        artifacts: &str,
        specialist_reports: &[SpecialistReport],
    ) -> Result<String, LlmError> {
        let lead = self.registry.lead_analyst().ok_or_else(|| {
            LlmError::Api("No lead analyst persona found".to_string())
        })?;

        info!("Lead analyst synthesizing {} specialist reports", specialist_reports.len());

        // Build the synthesis context
        let reports_section: String = specialist_reports
            .iter()
            .map(|r| format!("### {} Report\n{}\n", r.analyst_name, r.analysis))
            .collect::<Vec<_>>()
            .join("\n---\n\n");

        let context = format!(
            "# Investigation Context\n\n\
             ## Original Query\n{}\n\n\
             ## Raw Content Summary\n{}\n\n\
             ## Extracted Artifacts\n{}\n\n\
             # Specialist Analyst Reports\n\n{}",
            query,
            truncate_content(content, 4000),
            artifacts,
            reports_section
        );

        self.backend.generate(lead.system_prompt(), &context).await
    }

    /// Full analysis pipeline: specialists → lead synthesis
    pub async fn full_analysis(
        &self,
        query: &str,
        content: &str,
        artifacts: &str,
    ) -> Result<String, LlmError> {
        // Run all specialists
        let reports = self.analyze_with_specialists(query, content, artifacts).await;

        if reports.is_empty() {
            warn!("No specialist reports generated, falling back to lead-only analysis");
        }

        // Synthesize with lead analyst
        self.synthesize(query, content, artifacts, &reports).await
    }

    /// Get the persona registry
    pub fn registry(&self) -> &PersonaRegistry {
        &self.registry
    }

    /// List available specialist names
    pub fn list_specialists(&self) -> Vec<&str> {
        self.registry
            .specialist_analysts()
            .iter()
            .map(|p| p.persona.name.as_str())
            .collect()
    }
}

/// Truncate content to a maximum length, preserving word boundaries
fn truncate_content(content: &str, max_chars: usize) -> &str {
    if content.len() <= max_chars {
        return content;
    }
    
    // Find a good break point
    let truncated = &content[..max_chars];
    truncated
        .rfind(|c: char| c.is_whitespace())
        .map(|pos| &content[..pos])
        .unwrap_or(truncated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use crate::LlmBackend;
    use std::sync::Arc;

    struct MockBackend;

    #[async_trait]
    impl LlmBackend for MockBackend {
        async fn generate(&self, _system: &str, _user: &str) -> Result<String, LlmError> {
            Ok("Mock analysis result".to_string())
        }

        fn model_name(&self) -> &str {
            "mock"
        }
    }

    #[tokio::test]
    async fn test_specialist_system_creation() {
        let backend: SharedBackend = Arc::new(MockBackend);
        let system = SpecialistSystem::new(backend);
        
        let specialists = system.list_specialists();
        assert!(specialists.len() >= 6, "Should have multiple specialists");
    }

    #[tokio::test]
    async fn test_full_analysis() {
        let backend: SharedBackend = Arc::new(MockBackend);
        let system = SpecialistSystem::new(backend);
        
        let result = system
            .full_analysis("test query", "test content", "test artifacts")
            .await;
        
        assert!(result.is_ok());
    }
}
