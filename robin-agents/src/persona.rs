//! Persona management for OSINT agents
//!
//! Loads modular persona definitions from TOML files, enabling easy
//! customization and extension of agent behaviors.

use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

/// A persona definition loaded from TOML
#[derive(Debug, Clone, Deserialize)]
pub struct Persona {
    pub persona: PersonaMetadata,
    pub expertise: ExpertiseConfig,
    pub prompt: PromptConfig,
    pub output: OutputConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PersonaMetadata {
    pub id: String,
    pub name: String,
    pub category: String,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub role: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ExpertiseConfig {
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub artifact_types: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PromptConfig {
    pub system: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OutputConfig {
    #[serde(default = "default_format")]
    pub format: String,
    #[serde(default = "default_max_tokens")]
    pub max_tokens: u32,
}

fn default_format() -> String {
    "markdown".to_string()
}

fn default_max_tokens() -> u32 {
    2048
}

/// Registry of all loaded personas
#[derive(Debug, Default)]
pub struct PersonaRegistry {
    personas: HashMap<String, Persona>,
}

impl PersonaRegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self::default()
    }

    /// Load all personas from the embedded prompts
    pub fn load_embedded() -> Self {
        let mut registry = Self::new();
        
        // Embedded persona definitions
        let embedded = [
            include_str!("../prompts/refiner.toml"),
            include_str!("../prompts/filter.toml"),
            include_str!("../prompts/analyst_lead.toml"),
            include_str!("../prompts/analyst_crypto.toml"),
            include_str!("../prompts/analyst_forensic.toml"),
            include_str!("../prompts/analyst_malware.toml"),
            include_str!("../prompts/analyst_threat.toml"),
            include_str!("../prompts/analyst_network.toml"),
            include_str!("../prompts/analyst_osint.toml"),
        ];

        for toml_str in embedded {
            if let Ok(persona) = toml::from_str::<Persona>(toml_str) {
                if persona.persona.enabled {
                    registry.register(persona);
                }
            }
        }

        registry
    }

    /// Load personas from a directory
    pub fn load_from_dir<P: AsRef<Path>>(dir: P) -> std::io::Result<Self> {
        let mut registry = Self::new();
        
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            
            if path.extension().is_some_and(|ext| ext == "toml") {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    if let Ok(persona) = toml::from_str::<Persona>(&content) {
                        if persona.persona.enabled {
                            registry.register(persona);
                        }
                    }
                }
            }
        }

        Ok(registry)
    }

    /// Register a persona
    pub fn register(&mut self, persona: Persona) {
        self.personas.insert(persona.persona.id.clone(), persona);
    }

    /// Get a persona by ID
    pub fn get(&self, id: &str) -> Option<&Persona> {
        self.personas.get(id)
    }

    /// Get all personas in a category
    pub fn by_category(&self, category: &str) -> Vec<&Persona> {
        self.personas
            .values()
            .filter(|p| p.persona.category == category)
            .collect()
    }

    /// Get all analyst personas (specialists only, not lead)
    pub fn specialist_analysts(&self) -> Vec<&Persona> {
        self.personas
            .values()
            .filter(|p| {
                p.persona.category == "analyst"
                    && p.persona.role.as_deref() == Some("specialist")
            })
            .collect()
    }

    /// Get the lead analyst persona
    pub fn lead_analyst(&self) -> Option<&Persona> {
        self.personas
            .values()
            .find(|p| {
                p.persona.category == "analyst"
                    && p.persona.role.as_deref() == Some("orchestrator")
            })
    }

    /// List all persona IDs
    pub fn list_ids(&self) -> Vec<&str> {
        self.personas.keys().map(|s| s.as_str()).collect()
    }

    /// Count of loaded personas
    pub fn len(&self) -> usize {
        self.personas.len()
    }

    /// Check if registry is empty
    pub fn is_empty(&self) -> bool {
        self.personas.is_empty()
    }
}

impl Persona {
    /// Get the system prompt
    pub fn system_prompt(&self) -> &str {
        &self.prompt.system
    }

    /// Check if this persona handles a specific artifact type
    pub fn handles_artifact(&self, artifact_type: &str) -> bool {
        self.expertise.artifact_types.iter().any(|t| t == artifact_type || t == "all")
    }

    /// Check if this persona covers a domain
    pub fn covers_domain(&self, domain: &str) -> bool {
        self.expertise.domains.iter().any(|d| d == domain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_embedded_personas() {
        let registry = PersonaRegistry::load_embedded();
        assert!(registry.len() >= 9, "Should load at least 9 personas");
        
        // Check specific personas exist
        assert!(registry.get("refiner").is_some());
        assert!(registry.get("filter").is_some());
        assert!(registry.get("analyst_lead").is_some());
        assert!(registry.get("analyst_crypto").is_some());
    }

    #[test]
    fn test_specialist_analysts() {
        let registry = PersonaRegistry::load_embedded();
        let specialists = registry.specialist_analysts();
        
        // Should have crypto, forensic, malware, threat, network, osint
        assert!(specialists.len() >= 6, "Should have at least 6 specialist analysts");
    }

    #[test]
    fn test_lead_analyst() {
        let registry = PersonaRegistry::load_embedded();
        let lead = registry.lead_analyst();
        
        assert!(lead.is_some());
        assert_eq!(lead.unwrap().persona.id, "analyst_lead");
    }
}
