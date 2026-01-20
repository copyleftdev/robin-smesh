//! Dark web search engine crawler
//!
//! Queries .onion search engines and extracts result links.

use scraper::{Html, Selector};
use std::collections::HashSet;
use tracing::{debug, warn};

use crate::{create_tor_client, TorConfig, TorError};
use robin_core::SearchEngine;

/// A search result from a dark web search engine
#[derive(Debug, Clone)]
pub struct SearchResult {
    /// Result title
    pub title: String,
    /// Result URL (typically .onion)
    pub url: String,
    /// Source search engine
    pub engine: String,
}

/// Crawl a search engine for results
pub async fn crawl_engine(
    engine: &SearchEngine,
    query: &str,
    config: &TorConfig,
) -> Result<Vec<SearchResult>, TorError> {
    let client = create_tor_client(config)?;
    let url = engine.build_url(query);

    debug!("Crawling {} with query: {}", engine.name, query);

    let response = client.get(&url).send().await?;

    if !response.status().is_success() {
        warn!("Engine {} returned status: {}", engine.name, response.status());
        return Ok(Vec::new());
    }

    let html = response.text().await?;
    let results = parse_search_results(&html, engine.name);

    debug!("Engine {} returned {} results", engine.name, results.len());
    Ok(results)
}

/// Crawl a URL directly (for use in async contexts)
async fn crawl_url(
    url: &str,
    engine_name: &str,
    config: &TorConfig,
) -> Result<Vec<SearchResult>, TorError> {
    let client = create_tor_client(config)?;

    debug!("Crawling URL: {}", url);

    let response = client.get(url).send().await?;

    if !response.status().is_success() {
        warn!("URL {} returned status: {}", url, response.status());
        return Ok(Vec::new());
    }

    let html = response.text().await?;
    let results = parse_search_results(&html, engine_name);

    debug!("URL returned {} results", results.len());
    Ok(results)
}

/// Crawl multiple search engines concurrently
pub async fn crawl_engines(
    engines: &[&SearchEngine],
    query: &str,
    config: &TorConfig,
    max_concurrent: usize,
) -> Vec<SearchResult> {
    use futures::stream::{self, StreamExt};

    // Clone engine data to avoid lifetime issues with async closures
    let engine_data: Vec<(String, String)> = engines
        .iter()
        .map(|e| (e.name.to_string(), e.build_url(query)))
        .collect();

    let results: Vec<_> = stream::iter(engine_data)
        .map(|(name, url)| {
            let config = config.clone();
            async move {
                match crawl_url(&url, &name, &config).await {
                    Ok(results) => results,
                    Err(e) => {
                        warn!("Engine {} failed: {}", name, e);
                        Vec::new()
                    }
                }
            }
        })
        .buffer_unordered(max_concurrent)
        .collect()
        .await;

    // Flatten and deduplicate
    let mut seen: HashSet<String> = HashSet::new();
    let mut deduped = Vec::new();

    for result in results.into_iter().flatten() {
        let normalized = result.url.trim_end_matches('/').to_lowercase();
        if !seen.contains(&normalized) {
            seen.insert(normalized);
            deduped.push(result);
        }
    }

    deduped
}

/// Parse search results from HTML
fn parse_search_results(html: &str, engine_name: &str) -> Vec<SearchResult> {
    let document = Html::parse_document(html);
    let link_selector = Selector::parse("a").unwrap();

    let mut results = Vec::new();
    let onion_regex = regex::Regex::new(r#"https?://[a-z0-9\.]+\.onion[^\s"'<>]*"#).unwrap();

    for element in document.select(&link_selector) {
        let href = match element.value().attr("href") {
            Some(h) => h,
            None => continue,
        };

        // Extract .onion URLs
        if let Some(m) = onion_regex.find(href) {
            let url = m.as_str().to_string();

            // Skip search engine self-links
            if url.contains("search") || url.contains("query") {
                continue;
            }

            let title = element
                .text()
                .collect::<String>()
                .trim()
                .to_string();

            // Skip empty or very short titles
            if title.len() < 3 {
                continue;
            }

            results.push(SearchResult {
                title,
                url,
                engine: engine_name.to_string(),
            });
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_search_results() {
        let html = r#"
            <html>
            <body>
                <a href="http://example1234567890abcdef.onion/page">Test Site</a>
                <a href="http://search.onion/search?q=test">Search Link</a>
                <a href="http://another1234567890abcdef.onion/">Another Site</a>
            </body>
            </html>
        "#;

        let results = parse_search_results(html, "TestEngine");
        
        // Should include the first and third, skip the search link
        assert!(results.len() >= 1);
        assert!(results.iter().all(|r| !r.url.contains("search")));
    }
}
