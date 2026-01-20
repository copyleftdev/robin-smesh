//! Paste Site Monitor Agent
//!
//! Monitors public paste sites for leaked credentials, cryptocurrency addresses,
//! and other intelligence artifacts. Searches multiple paste platforms based on
//! refined query terms.

use async_trait::async_trait;
use reqwest::Client;
use scraper::{Html, Selector};
use serde::Deserialize;
use std::collections::HashSet;
use std::time::Duration;
use tracing::{info, warn};

use robin_core::{AgentType, Field, OsintPayload, Signal};

use crate::traits::{AgentConfig, AgentError, OsintAgent};

/// Configuration for the paste monitor agent
#[derive(Debug, Clone)]
pub struct PasteMonitorConfig {
    /// Maximum pastes to fetch per site
    pub max_pastes_per_site: usize,
    /// Request timeout
    pub request_timeout: Duration,
    /// Minimum paste length to consider (filter out tiny pastes)
    pub min_paste_length: usize,
}

impl Default for PasteMonitorConfig {
    fn default() -> Self {
        Self {
            max_pastes_per_site: 10,
            request_timeout: Duration::from_secs(30),
            min_paste_length: 50,
        }
    }
}

/// Paste site monitor agent
pub struct PasteMonitorAgent {
    config: AgentConfig,
    paste_config: PasteMonitorConfig,
    client: Client,
    processed_urls: HashSet<String>,
}

impl PasteMonitorAgent {
    pub fn new(config: AgentConfig, paste_config: PasteMonitorConfig) -> Self {
        let client = Client::builder()
            .timeout(paste_config.request_timeout)
            .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
            .build()
            .expect("Failed to create HTTP client");

        Self {
            config,
            paste_config,
            client,
            processed_urls: HashSet::new(),
        }
    }

    /// Search Pastebin via Google dork (public pastes)
    async fn search_pastebin(&self, query: &str) -> Vec<PasteResult> {
        let mut results = Vec::new();
        
        // Use Pastebin's scraping API if available, otherwise search recent
        let search_url = format!(
            "https://psbdmp.ws/api/v3/search/{}",
            urlencoding::encode(query)
        );

        match self.client.get(&search_url).send().await {
            Ok(response) => {
                if let Ok(data) = response.json::<PsbdmpResponse>().await {
                    for paste in data.data.into_iter().take(self.paste_config.max_pastes_per_site) {
                        results.push(PasteResult {
                            url: format!("https://pastebin.com/{}", paste.id),
                            site: "pastebin".to_string(),
                            title: paste.title,
                            content: paste.content,
                            created_at: paste.time,
                            author: paste.author,
                        });
                    }
                }
            }
            Err(e) => {
                warn!("Pastebin search failed: {}", e);
            }
        }

        results
    }

    /// Search Rentry.co pastes
    async fn search_rentry(&self, query: &str) -> Vec<PasteResult> {
        let mut results = Vec::new();

        // Rentry doesn't have a search API, but we can try common patterns
        // and check if pastes exist with query-related slugs
        let slugs = self.generate_search_slugs(query);
        
        for slug in slugs.iter().take(5) {
            let url = format!("https://rentry.co/{}", slug);
            if let Ok(response) = self.client.get(&url).send().await {
                if response.status().is_success() {
                    if let Ok(html) = response.text().await {
                        if let Some(content) = self.extract_rentry_content(&html) {
                            if content.len() >= self.paste_config.min_paste_length {
                                results.push(PasteResult {
                                    url,
                                    site: "rentry".to_string(),
                                    title: None,
                                    content,
                                    created_at: None,
                                    author: None,
                                });
                            }
                        }
                    }
                }
            }
        }

        results
    }

    /// Search dpaste.org
    async fn search_dpaste(&self, _query: &str) -> Vec<PasteResult> {
        let mut results = Vec::new();

        // dpaste has an API for recent pastes
        let url = "https://dpaste.org/api/?format=json";
        
        match self.client.get(url).send().await {
            Ok(response) => {
                if let Ok(pastes) = response.json::<Vec<DpasteEntry>>().await {
                    for paste in pastes.into_iter().take(self.paste_config.max_pastes_per_site) {
                        // Fetch full content
                        let paste_url = format!("https://dpaste.org/{}/raw", paste.id);
                        if let Ok(content_resp) = self.client.get(&paste_url).send().await {
                            if let Ok(content) = content_resp.text().await {
                                if content.len() >= self.paste_config.min_paste_length {
                                    results.push(PasteResult {
                                        url: format!("https://dpaste.org/{}", paste.id),
                                        site: "dpaste".to_string(),
                                        title: None,
                                        content,
                                        created_at: Some(paste.created),
                                        author: None,
                                    });
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => {
                warn!("dpaste search failed: {}", e);
            }
        }

        results
    }

    /// Search ControlC paste site
    async fn search_controlc(&self, query: &str) -> Vec<PasteResult> {
        let mut results = Vec::new();

        let search_url = format!(
            "https://controlc.com/search?q={}",
            urlencoding::encode(query)
        );

        match self.client.get(&search_url).send().await {
            Ok(response) => {
                if let Ok(html) = response.text().await {
                    results.extend(self.parse_controlc_results(&html));
                }
            }
            Err(e) => {
                warn!("ControlC search failed: {}", e);
            }
        }

        results
    }

    /// Search JustPaste.it
    async fn search_justpaste(&self, query: &str) -> Vec<PasteResult> {
        let mut results = Vec::new();

        let search_url = format!(
            "https://justpaste.it/search?q={}",
            urlencoding::encode(query)
        );

        match self.client.get(&search_url).send().await {
            Ok(response) => {
                if let Ok(html) = response.text().await {
                    results.extend(self.parse_justpaste_results(&html));
                }
            }
            Err(e) => {
                warn!("JustPaste.it search failed: {}", e);
            }
        }

        results
    }

    /// Generate search slugs from query terms
    fn generate_search_slugs(&self, query: &str) -> Vec<String> {
        let words: Vec<&str> = query.split_whitespace().collect();
        let mut slugs = Vec::new();

        // Single words
        for word in &words {
            slugs.push(word.to_lowercase());
        }

        // Combinations
        if words.len() >= 2 {
            slugs.push(words[0..2].join("-").to_lowercase());
            slugs.push(words[0..2].join("_").to_lowercase());
        }

        slugs
    }

    /// Extract content from Rentry HTML
    fn extract_rentry_content(&self, html: &str) -> Option<String> {
        let document = Html::parse_document(html);
        let selector = Selector::parse(".markdown-body").ok()?;
        
        document.select(&selector)
            .next()
            .map(|el| el.text().collect::<Vec<_>>().join(" "))
    }

    /// Parse ControlC search results
    fn parse_controlc_results(&self, html: &str) -> Vec<PasteResult> {
        let mut results = Vec::new();
        let document = Html::parse_document(html);
        
        let selector = Selector::parse(".paste-link").unwrap();
        for element in document.select(&selector).take(self.paste_config.max_pastes_per_site) {
                if let Some(href) = element.value().attr("href") {
                    let url = if href.starts_with("http") {
                        href.to_string()
                    } else {
                        format!("https://controlc.com{}", href)
                    };
                    
                    let title = element.text().collect::<Vec<_>>().join(" ");
                    
                results.push(PasteResult {
                    url,
                    site: "controlc".to_string(),
                    title: if title.is_empty() { None } else { Some(title) },
                    content: String::new(), // Will fetch later
                    created_at: None,
                    author: None,
                });
            }
        }

        results
    }

    /// Parse JustPaste.it search results
    fn parse_justpaste_results(&self, html: &str) -> Vec<PasteResult> {
        let mut results = Vec::new();
        let document = Html::parse_document(html);
        
        let selector = Selector::parse(".result-item a").unwrap();
        for element in document.select(&selector).take(self.paste_config.max_pastes_per_site) {
                if let Some(href) = element.value().attr("href") {
                    let url = if href.starts_with("http") {
                        href.to_string()
                    } else {
                        format!("https://justpaste.it{}", href)
                    };
                    
                    let title = element.text().collect::<Vec<_>>().join(" ");
                    
                results.push(PasteResult {
                    url,
                    site: "justpaste".to_string(),
                    title: if title.is_empty() { None } else { Some(title) },
                    content: String::new(),
                    created_at: None,
                    author: None,
                });
            }
        }

        results
    }

    /// Fetch full paste content
    async fn fetch_paste_content(&self, result: &mut PasteResult) -> bool {
        if !result.content.is_empty() {
            return true;
        }

        let raw_url = match result.site.as_str() {
            "pastebin" => format!("{}/raw", result.url),
            "controlc" => format!("{}/raw", result.url),
            "justpaste" => result.url.clone(),
            _ => result.url.clone(),
        };

        match self.client.get(&raw_url).send().await {
            Ok(response) => {
                if let Ok(content) = response.text().await {
                    if content.len() >= self.paste_config.min_paste_length {
                        result.content = content;
                        return true;
                    }
                }
            }
            Err(e) => {
                warn!("Failed to fetch paste content from {}: {}", result.url, e);
            }
        }

        false
    }
}

#[async_trait]
impl OsintAgent for PasteMonitorAgent {
    fn id(&self) -> &str {
        &self.config.id
    }

    fn agent_type(&self) -> &str {
        "paste_monitor"
    }

    fn sense<'a>(&self, field: &'a Field) -> Vec<&'a Signal> {
        let by_type = field.sense_by_type(self.config.sensing_threshold);
        
        // Sense refined queries to search paste sites
        by_type.refined_queries
            .into_iter()
            .filter(|s| !self.processed_urls.contains(&s.origin_hash))
            .collect()
    }

    async fn process(&mut self, field: &mut Field) -> Result<Vec<String>, AgentError> {
        // Collect query data first to release the immutable borrow
        let queries: Vec<(String, String)> = {
            let signals = self.sense(field);
            if signals.is_empty() {
                return Err(AgentError::NoWork);
            }
            signals.iter()
                .filter_map(|s| {
                    if let OsintPayload::RefinedQuery { refined, .. } = &s.payload {
                        Some((s.origin_hash.clone(), refined.clone()))
                    } else {
                        None
                    }
                })
                .collect()
        };

        if queries.is_empty() {
            return Err(AgentError::NoWork);
        }

        let mut emitted = Vec::new();

        for (origin_hash, query) in queries {
            self.processed_urls.insert(origin_hash);

            info!("Paste monitor searching for: {}", query);

            // Search all paste sites in parallel
            let (pastebin, rentry, dpaste, controlc, justpaste) = tokio::join!(
                self.search_pastebin(&query),
                self.search_rentry(&query),
                self.search_dpaste(&query),
                self.search_controlc(&query),
                self.search_justpaste(&query),
            );

            let mut all_results: Vec<PasteResult> = Vec::new();
            all_results.extend(pastebin);
            all_results.extend(rentry);
            all_results.extend(dpaste);
            all_results.extend(controlc);
            all_results.extend(justpaste);

            info!("Found {} paste results across all sites", all_results.len());

            // Fetch content for results that don't have it
            for result in &mut all_results {
                if result.content.is_empty() {
                    self.fetch_paste_content(result).await;
                }
            }

            // Emit signals for pastes with content
            for result in all_results {
                if result.content.is_empty() {
                    continue;
                }

                let paste_signal = Signal::builder(OsintPayload::PasteContent {
                    url: result.url.clone(),
                    site: result.site.clone(),
                    title: result.title,
                    content: result.content,
                    created_at: result.created_at,
                    author: result.author,
                })
                .origin(&self.config.id)
                .confidence(0.7)
                .ttl(300.0)
                .build();

                let hash = field.emit(paste_signal);
                emitted.push(hash);
                info!("Emitted paste from {} ({})", result.site, result.url);
            }
        }

        if emitted.is_empty() {
            Err(AgentError::NoWork)
        } else {
            Ok(emitted)
        }
    }

    fn heartbeat(&self, field: &mut Field) {
        let hb = Signal::builder(OsintPayload::Heartbeat {
            agent_id: self.config.id.clone(),
            agent_type: AgentType::PasteMonitor,
            capacity: 1.0,
        })
        .origin(&self.config.id)
        .ttl(30.0)
        .build();
        field.emit(hb);
    }
}

/// Internal paste result structure
#[derive(Debug)]
struct PasteResult {
    url: String,
    site: String,
    title: Option<String>,
    content: String,
    created_at: Option<String>,
    author: Option<String>,
}

/// Psbdmp API response (Pastebin dump search)
#[derive(Debug, Deserialize)]
struct PsbdmpResponse {
    #[serde(default)]
    data: Vec<PsbdmpPaste>,
}

#[derive(Debug, Deserialize)]
struct PsbdmpPaste {
    id: String,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    content: String,
    #[serde(default)]
    time: Option<String>,
    #[serde(default)]
    author: Option<String>,
}

/// dpaste API entry
#[derive(Debug, Deserialize)]
struct DpasteEntry {
    id: String,
    created: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_paste_config_default() {
        let config = PasteMonitorConfig::default();
        assert_eq!(config.max_pastes_per_site, 10);
        assert_eq!(config.min_paste_length, 50);
    }

    #[test]
    fn test_generate_search_slugs() {
        let agent = PasteMonitorAgent::new(
            AgentConfig::default().with_id("test"),
            PasteMonitorConfig::default(),
        );
        
        let slugs = agent.generate_search_slugs("bitcoin wallet");
        assert!(slugs.contains(&"bitcoin".to_string()));
        assert!(slugs.contains(&"wallet".to_string()));
        assert!(slugs.contains(&"bitcoin-wallet".to_string()));
    }
}
