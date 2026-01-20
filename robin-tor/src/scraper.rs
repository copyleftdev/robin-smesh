//! Content scraper for dark web sites
//!
//! Fetches and extracts text content from .onion URLs.

use scraper::{Html, Selector};
use tracing::{debug, warn};

use crate::{create_tor_client, TorConfig, TorError};

/// Scraped content from a dark web page
#[derive(Debug, Clone)]
pub struct ScrapedPage {
    /// Original URL
    pub url: String,
    /// Page title (if found)
    pub title: Option<String>,
    /// Extracted text content
    pub text: String,
    /// Character count
    pub char_count: usize,
    /// Whether content was truncated
    pub truncated: bool,
}

/// Maximum characters to extract per page
const MAX_CONTENT_LENGTH: usize = 4000;

/// Scrape content from a URL
pub async fn scrape_url(url: &str, config: &TorConfig) -> Result<ScrapedPage, TorError> {
    let client = create_tor_client(config)?;

    debug!("Scraping: {}", url);

    let response = client.get(url).send().await?;

    if !response.status().is_success() {
        warn!("Scrape of {} returned status: {}", url, response.status());
        return Ok(ScrapedPage {
            url: url.to_string(),
            title: None,
            text: String::new(),
            char_count: 0,
            truncated: false,
        });
    }

    let html = response.text().await?;
    let (title, text) = extract_content(&html);

    let truncated = text.len() > MAX_CONTENT_LENGTH;
    let final_text = if truncated {
        format!("{}...(truncated)", &text[..MAX_CONTENT_LENGTH])
    } else {
        text
    };

    Ok(ScrapedPage {
        url: url.to_string(),
        title,
        text: final_text.clone(),
        char_count: final_text.len(),
        truncated,
    })
}

/// Scrape multiple URLs concurrently
pub async fn scrape_urls(
    urls: &[&str],
    config: &TorConfig,
    max_concurrent: usize,
) -> Vec<ScrapedPage> {
    use futures::stream::{self, StreamExt};

    stream::iter(urls)
        .map(|url| {
            let config = config.clone();
            let url = url.to_string();
            async move {
                match scrape_url(&url, &config).await {
                    Ok(page) => Some(page),
                    Err(e) => {
                        warn!("Failed to scrape {}: {}", url, e);
                        None
                    }
                }
            }
        })
        .buffer_unordered(max_concurrent)
        .filter_map(|x| async { x })
        .collect()
        .await
}

/// Extract title and text content from HTML
fn extract_content(html: &str) -> (Option<String>, String) {
    use scraper::node::Node;

    let document = Html::parse_document(html);

    // Extract title
    let title_selector = Selector::parse("title").unwrap();
    let title = document
        .select(&title_selector)
        .next()
        .map(|el| el.text().collect::<String>().trim().to_string());

    let body_selector = Selector::parse("body").unwrap();
    let body = document.select(&body_selector).next();

    let text = if let Some(body) = body {
        let mut text_parts = Vec::new();

        // Walk all descendants, skip script/style/noscript subtrees
        for node_ref in body.descendants() {
            // Skip text nodes inside script/style/noscript
            if let Node::Text(text_node) = node_ref.value() {
                // Check if any ancestor is a script/style/noscript
                let in_excluded = node_ref.ancestors().any(|ancestor| {
                    ancestor
                        .value()
                        .as_element()
                        .map(|el| matches!(el.name(), "script" | "style" | "noscript"))
                        .unwrap_or(false)
                });

                if !in_excluded {
                    let trimmed = text_node.trim();
                    if !trimmed.is_empty() {
                        text_parts.push(trimmed.to_string());
                    }
                }
            }
        }

        normalize_whitespace(&text_parts.join(" "))
    } else {
        String::new()
    };

    (title, text)
}

/// Normalize whitespace in text
fn normalize_whitespace(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_content() {
        let html = r#"
            <html>
            <head><title>Test Page</title></head>
            <body>
                <script>var x = 1;</script>
                <h1>Hello World</h1>
                <p>This is test content.</p>
                <style>.x { color: red; }</style>
            </body>
            </html>
        "#;

        let (title, text) = extract_content(html);

        assert_eq!(title, Some("Test Page".to_string()));
        assert!(text.contains("Hello World"));
        assert!(text.contains("test content"));
        assert!(!text.contains("var x"));
        assert!(!text.contains("color: red"));
    }

    #[test]
    fn test_normalize_whitespace() {
        let input = "  hello   world  \n\t  test  ";
        let output = normalize_whitespace(input);
        assert_eq!(output, "hello world test");
    }
}
