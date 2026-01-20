//! Enrichment Agent - External OSINT source integration
//!
//! Enriches extracted artifacts by querying:
//! - GitHub Search (emails, usernames, code snippets)
//! - Brave Search (IPs, domains, hashes, general web)
//!
//! Artifacts are prioritized for enrichment based on type:
//! - High: Email, Username, Domain, IP
//! - Medium: Hash, Bitcoin address
//! - Low: URL, OnionAddress (less useful for surface web)

use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;
use tracing::{debug, info};

use robin_core::{
    AgentType, Artifact, ArtifactType, EnrichmentFinding, Field, OsintPayload, Signal,
};

use crate::{AgentConfig, AgentError, OsintAgent};

/// Configuration for external OSINT sources
#[derive(Debug, Clone)]
pub struct EnrichmentConfig {
    /// GitHub personal access token (optional, increases rate limit)
    pub github_token: Option<String>,
    /// Brave Search API key (optional)
    pub brave_api_key: Option<String>,
    /// Maximum enrichments per artifact type
    pub max_results_per_artifact: usize,
    /// Enable GitHub search
    pub enable_github: bool,
    /// Enable Brave search
    pub enable_brave: bool,
}

impl Default for EnrichmentConfig {
    fn default() -> Self {
        Self {
            github_token: std::env::var("GITHUB_TOKEN").ok(),
            brave_api_key: std::env::var("BRAVE_API_KEY").ok(),
            max_results_per_artifact: 5,
            enable_github: true,
            enable_brave: true,
        }
    }
}

/// Agent that enriches artifacts via external OSINT sources
pub struct EnrichmentAgent {
    config: AgentConfig,
    enrichment_config: EnrichmentConfig,
    http_client: Client,
    processed_artifacts: std::collections::HashSet<String>,
}

impl EnrichmentAgent {
    pub fn new(config: AgentConfig, enrichment_config: EnrichmentConfig) -> Self {
        Self {
            config,
            enrichment_config,
            http_client: Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap_or_default(),
            processed_artifacts: std::collections::HashSet::new(),
        }
    }

    /// Determine if an artifact is worth enriching
    fn should_enrich(&self, artifact: &Artifact) -> bool {
        matches!(
            artifact.artifact_type,
            ArtifactType::Email
                | ArtifactType::Username
                | ArtifactType::Domain
                | ArtifactType::Ipv4
                | ArtifactType::Ipv6
                | ArtifactType::Sha256
                | ArtifactType::Sha1
                | ArtifactType::Md5
                | ArtifactType::Bitcoin
                | ArtifactType::Ethereum
        )
    }

    /// Build search query for GitHub based on artifact type
    fn github_query(&self, artifact: &Artifact) -> Option<String> {
        match &artifact.artifact_type {
            ArtifactType::Email => Some(format!("\"{}\"", artifact.value)),
            ArtifactType::Username => Some(format!("\"{}\" OR author:{}", artifact.value, artifact.value)),
            ArtifactType::Domain => Some(format!("\"{}\"", artifact.value)),
            ArtifactType::Ipv4 | ArtifactType::Ipv6 => Some(format!("\"{}\"", artifact.value)),
            ArtifactType::Sha256 | ArtifactType::Sha1 | ArtifactType::Md5 => {
                Some(format!("\"{}\"", artifact.value))
            }
            ArtifactType::Bitcoin | ArtifactType::Ethereum => {
                Some(format!("\"{}\"", artifact.value))
            }
            _ => None,
        }
    }

    /// Build search query for Brave based on artifact type
    fn brave_query(&self, artifact: &Artifact) -> String {
        match &artifact.artifact_type {
            ArtifactType::Email => format!("\"{}\" data breach leak", artifact.value),
            ArtifactType::Username => format!("\"{}\" hacker forum profile", artifact.value),
            ArtifactType::Domain => format!("\"{}\" malware infrastructure", artifact.value),
            ArtifactType::Ipv4 | ArtifactType::Ipv6 => {
                format!("\"{}\" threat intelligence", artifact.value)
            }
            ArtifactType::Sha256 | ArtifactType::Sha1 | ArtifactType::Md5 => {
                format!("\"{}\" malware analysis", artifact.value)
            }
            ArtifactType::Bitcoin => format!("\"{}\" ransomware bitcoin", artifact.value),
            ArtifactType::Ethereum => format!("\"{}\" cryptocurrency scam", artifact.value),
            _ => format!("\"{}\"", artifact.value),
        }
    }

    /// Search GitHub for artifact mentions
    async fn search_github(&self, artifact: &Artifact) -> Vec<EnrichmentFinding> {
        let query = match self.github_query(artifact) {
            Some(q) => q,
            None => return vec![],
        };

        let url = format!(
            "https://api.github.com/search/code?q={}&per_page={}",
            urlencoding::encode(&query),
            self.enrichment_config.max_results_per_artifact
        );

        let mut request = self.http_client
            .get(&url)
            .header("Accept", "application/vnd.github.v3+json")
            .header("User-Agent", "robin-smesh-osint/0.1");

        if let Some(token) = &self.enrichment_config.github_token {
            request = request.header("Authorization", format!("token {}", token));
        }

        match request.send().await {
            Ok(response) => {
                if !response.status().is_success() {
                    debug!("GitHub search failed: {}", response.status());
                    return vec![];
                }

                match response.json::<GitHubSearchResponse>().await {
                    Ok(data) => {
                        data.items
                            .into_iter()
                            .take(self.enrichment_config.max_results_per_artifact)
                            .map(|item| EnrichmentFinding {
                                finding_type: "github_code".to_string(),
                                title: format!("{}/{}", item.repository.full_name, item.name),
                                url: Some(item.html_url),
                                snippet: format!(
                                    "Found in {} ({})",
                                    item.path,
                                    item.repository.description.unwrap_or_default()
                                ),
                                relevance: 0.8,
                            })
                            .collect()
                    }
                    Err(e) => {
                        debug!("Failed to parse GitHub response: {}", e);
                        vec![]
                    }
                }
            }
            Err(e) => {
                debug!("GitHub search request failed: {}", e);
                vec![]
            }
        }
    }

    /// Search Brave for artifact context
    async fn search_brave(&self, artifact: &Artifact) -> Vec<EnrichmentFinding> {
        let api_key = match &self.enrichment_config.brave_api_key {
            Some(key) => key,
            None => {
                debug!("No Brave API key configured");
                return vec![];
            }
        };

        let query = self.brave_query(artifact);
        let url = format!(
            "https://api.search.brave.com/res/v1/web/search?q={}&count={}",
            urlencoding::encode(&query),
            self.enrichment_config.max_results_per_artifact
        );

        match self.http_client
            .get(&url)
            .header("Accept", "application/json")
            .header("X-Subscription-Token", api_key)
            .send()
            .await
        {
            Ok(response) => {
                if !response.status().is_success() {
                    debug!("Brave search failed: {}", response.status());
                    return vec![];
                }

                match response.json::<BraveSearchResponse>().await {
                    Ok(data) => {
                        data.web
                            .results
                            .into_iter()
                            .take(self.enrichment_config.max_results_per_artifact)
                            .map(|result| EnrichmentFinding {
                                finding_type: "web_search".to_string(),
                                title: result.title,
                                url: Some(result.url),
                                snippet: result.description,
                                relevance: 0.7,
                            })
                            .collect()
                    }
                    Err(e) => {
                        debug!("Failed to parse Brave response: {}", e);
                        vec![]
                    }
                }
            }
            Err(e) => {
                debug!("Brave search request failed: {}", e);
                vec![]
            }
        }
    }

    /// Enrich a single artifact from all configured sources
    async fn enrich_artifact(&self, artifact: &Artifact) -> Vec<(String, Vec<EnrichmentFinding>)> {
        let mut results = Vec::new();

        if self.enrichment_config.enable_github {
            let findings = self.search_github(artifact).await;
            if !findings.is_empty() {
                results.push(("github".to_string(), findings));
            }
        }

        if self.enrichment_config.enable_brave && self.enrichment_config.brave_api_key.is_some() {
            let findings = self.search_brave(artifact).await;
            if !findings.is_empty() {
                results.push(("brave".to_string(), findings));
            }
        }

        results
    }
}

#[async_trait]
impl OsintAgent for EnrichmentAgent {
    fn id(&self) -> &str {
        &self.config.id
    }

    fn agent_type(&self) -> &str {
        "enricher"
    }

    fn sense<'a>(&self, field: &'a Field) -> Vec<&'a Signal> {
        field.sense_by_type(self.config.sensing_threshold).extracted_artifacts
    }

    async fn process(&mut self, field: &mut Field) -> Result<Vec<String>, AgentError> {
        // Collect artifacts to process (to avoid borrow issues)
        let artifacts_to_process: Vec<Artifact> = {
            let signals = field.sense_by_type(0.3);
            signals
                .extracted_artifacts
                .iter()
                .filter_map(|signal| {
                    if let OsintPayload::ExtractedArtifacts { artifacts, .. } = &signal.payload {
                        Some(artifacts.clone())
                    } else {
                        None
                    }
                })
                .flatten()
                .filter(|artifact| {
                    let artifact_key = format!("{:?}:{}", artifact.artifact_type, artifact.value);
                    !self.processed_artifacts.contains(&artifact_key) && self.should_enrich(artifact)
                })
                .collect()
        };

        let mut emitted_hashes = Vec::new();

        for artifact in artifacts_to_process {
            let artifact_key = format!("{:?}:{}", artifact.artifact_type, artifact.value);
            self.processed_artifacts.insert(artifact_key);

            info!(
                "Enriching {:?} artifact: {}",
                artifact.artifact_type,
                &artifact.value[..artifact.value.len().min(50)]
            );

            let enrichments = self.enrich_artifact(&artifact).await;

            for (source, findings) in enrichments {
                if !findings.is_empty() {
                    info!(
                        "Found {} {} findings for {:?}",
                        findings.len(),
                        source,
                        artifact.artifact_type
                    );

                    let signal = Signal::builder(OsintPayload::EnrichedArtifacts {
                        artifact: artifact.clone(),
                        source: source.clone(),
                        findings,
                    })
                    .origin(&self.config.id)
                    .confidence(0.7)
                    .ttl(120.0)
                    .build();

                    let hash = field.emit(signal);
                    emitted_hashes.push(hash);
                }
            }
        }

        Ok(emitted_hashes)
    }

    fn heartbeat(&self, field: &mut Field) {
        let signal = Signal::builder(OsintPayload::Heartbeat {
            agent_id: self.config.id.clone(),
            agent_type: AgentType::Enricher,
            capacity: 1.0,
        })
        .origin(&self.config.id)
        .ttl(10.0)
        .build();
        field.emit(signal);
    }
}

// GitHub API response types
#[derive(Debug, Deserialize)]
struct GitHubSearchResponse {
    items: Vec<GitHubCodeItem>,
}

#[derive(Debug, Deserialize)]
struct GitHubCodeItem {
    name: String,
    path: String,
    html_url: String,
    repository: GitHubRepository,
}

#[derive(Debug, Deserialize)]
struct GitHubRepository {
    full_name: String,
    description: Option<String>,
}

// Brave Search API response types
#[derive(Debug, Deserialize)]
struct BraveSearchResponse {
    web: BraveWebResults,
}

#[derive(Debug, Deserialize)]
struct BraveWebResults {
    results: Vec<BraveWebResult>,
}

#[derive(Debug, Deserialize)]
struct BraveWebResult {
    title: String,
    url: String,
    description: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_should_enrich() {
        let agent = EnrichmentAgent::new(
            AgentConfig::default().with_id("test"),
            EnrichmentConfig::default(),
        );

        let email = Artifact::new(ArtifactType::Email, "test@example.com".to_string());
        assert!(agent.should_enrich(&email));

        let onion = Artifact::new(
            ArtifactType::OnionAddress,
            "abc123.onion".to_string(),
        );
        assert!(!agent.should_enrich(&onion));
    }

    #[test]
    fn test_github_query() {
        let agent = EnrichmentAgent::new(
            AgentConfig::default().with_id("test"),
            EnrichmentConfig::default(),
        );

        let email = Artifact::new(ArtifactType::Email, "hacker@dark.net".to_string());
        let query = agent.github_query(&email);
        assert!(query.is_some());
        assert!(query.unwrap().contains("hacker@dark.net"));
    }

    #[test]
    fn test_brave_query() {
        let agent = EnrichmentAgent::new(
            AgentConfig::default().with_id("test"),
            EnrichmentConfig::default(),
        );

        let btc = Artifact::new(
            ArtifactType::Bitcoin,
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string(),
        );
        let query = agent.brave_query(&btc);
        assert!(query.contains("ransomware"));
        assert!(query.contains("bitcoin"));
    }
}
