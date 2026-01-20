//! Intelligence artifacts extracted from dark web content
//!
//! Supports extraction of:
//! - Indicators of Compromise (IOCs): IPs, domains, hashes, emails
//! - Threat actor information
//! - Cryptocurrency addresses
//! - Malware names and TTPs

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::LazyLock;

/// Categories of intelligence artifacts
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactType {
    /// IPv4 address
    Ipv4,
    /// IPv6 address
    Ipv6,
    /// Domain name
    Domain,
    /// Onion address
    OnionAddress,
    /// Email address
    Email,
    /// MD5 hash
    Md5,
    /// SHA1 hash
    Sha1,
    /// SHA256 hash
    Sha256,
    /// Bitcoin address
    Bitcoin,
    /// Ethereum address
    Ethereum,
    /// Monero address
    Monero,
    /// CVE identifier
    Cve,
    /// MITRE ATT&CK TTP
    MitreAttack,
    /// Threat actor name/alias
    ThreatActor,
    /// Malware name
    Malware,
    /// URL
    Url,
    /// Username/handle
    Username,
    /// Phone number
    Phone,
    /// Credit card number (redacted)
    CreditCard,
    /// Custom/unknown
    Custom(String),
}

/// An extracted artifact with context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Artifact {
    /// Type of artifact
    pub artifact_type: ArtifactType,
    /// The extracted value
    pub value: String,
    /// Surrounding context (snippet)
    pub context: Option<String>,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f64,
    /// Source URL where found
    pub source: Option<String>,
}

impl Artifact {
    pub fn new(artifact_type: ArtifactType, value: String) -> Self {
        Self {
            artifact_type,
            value,
            context: None,
            confidence: 1.0,
            source: None,
        }
    }

    pub fn with_context(mut self, context: &str) -> Self {
        self.context = Some(context.to_string());
        self
    }

    pub fn with_confidence(mut self, confidence: f64) -> Self {
        self.confidence = confidence.clamp(0.0, 1.0);
        self
    }

    pub fn with_source(mut self, source: &str) -> Self {
        self.source = Some(source.to_string());
        self
    }
}

// Regex patterns for artifact extraction
static IPV4_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b").unwrap()
});

static DOMAIN_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b").unwrap()
});

static ONION_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b[a-z2-7]{16,56}\.onion\b").unwrap()
});

static EMAIL_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b").unwrap()
});

static MD5_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b[a-fA-F0-9]{32}\b").unwrap()
});

static SHA1_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b[a-fA-F0-9]{40}\b").unwrap()
});

static SHA256_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b[a-fA-F0-9]{64}\b").unwrap()
});

static BITCOIN_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b").unwrap()
});

static ETHEREUM_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b0x[a-fA-F0-9]{40}\b").unwrap()
});

static MONERO_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b").unwrap()
});

static CVE_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\bCVE-\d{4}-\d{4,}\b").unwrap()
});

static MITRE_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b[TS]\d{4}(?:\.\d{3})?\b").unwrap()
});

static URL_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"https?://[^\s<>"']+"#).unwrap()
});

/// Helper to add artifact if not already seen
fn try_add_artifact(
    artifacts: &mut Vec<Artifact>,
    seen: &mut HashSet<String>,
    artifact_type: ArtifactType,
    value: &str,
    confidence: f64,
    source: Option<&str>,
) {
    let key = format!("{:?}:{}", artifact_type, value.to_lowercase());
    if seen.insert(key) {
        let mut artifact = Artifact::new(artifact_type, value.to_string())
            .with_confidence(confidence);
        if let Some(src) = source {
            artifact = artifact.with_source(src);
        }
        artifacts.push(artifact);
    }
}

/// Extract all artifacts from text content
pub fn extract_artifacts(text: &str, source: Option<&str>) -> Vec<Artifact> {
    let mut artifacts = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    // Extract onion addresses (high priority for dark web)
    for cap in ONION_REGEX.find_iter(text) {
        try_add_artifact(&mut artifacts, &mut seen, ArtifactType::OnionAddress, cap.as_str(), 1.0, source);
    }

    // Extract URLs
    for cap in URL_REGEX.find_iter(text) {
        try_add_artifact(&mut artifacts, &mut seen, ArtifactType::Url, cap.as_str(), 0.9, source);
    }

    // Extract cryptocurrency addresses
    for cap in BITCOIN_REGEX.find_iter(text) {
        try_add_artifact(&mut artifacts, &mut seen, ArtifactType::Bitcoin, cap.as_str(), 0.95, source);
    }
    for cap in ETHEREUM_REGEX.find_iter(text) {
        try_add_artifact(&mut artifacts, &mut seen, ArtifactType::Ethereum, cap.as_str(), 0.95, source);
    }
    for cap in MONERO_REGEX.find_iter(text) {
        try_add_artifact(&mut artifacts, &mut seen, ArtifactType::Monero, cap.as_str(), 0.95, source);
    }

    // Extract hashes (order matters: SHA256 > SHA1 > MD5)
    for cap in SHA256_REGEX.find_iter(text) {
        try_add_artifact(&mut artifacts, &mut seen, ArtifactType::Sha256, cap.as_str(), 0.9, source);
    }
    for cap in SHA1_REGEX.find_iter(text) {
        // Skip if already matched as SHA256
        let sha256_key = format!("{:?}:{}", ArtifactType::Sha256, cap.as_str().to_lowercase());
        if !seen.contains(&sha256_key) {
            try_add_artifact(&mut artifacts, &mut seen, ArtifactType::Sha1, cap.as_str(), 0.85, source);
        }
    }
    for cap in MD5_REGEX.find_iter(text) {
        try_add_artifact(&mut artifacts, &mut seen, ArtifactType::Md5, cap.as_str(), 0.8, source);
    }

    // Extract CVEs
    for cap in CVE_REGEX.find_iter(text) {
        try_add_artifact(&mut artifacts, &mut seen, ArtifactType::Cve, cap.as_str(), 1.0, source);
    }

    // Extract MITRE ATT&CK TTPs
    for cap in MITRE_REGEX.find_iter(text) {
        try_add_artifact(&mut artifacts, &mut seen, ArtifactType::MitreAttack, cap.as_str(), 0.9, source);
    }

    // Extract email addresses
    for cap in EMAIL_REGEX.find_iter(text) {
        try_add_artifact(&mut artifacts, &mut seen, ArtifactType::Email, cap.as_str(), 0.95, source);
    }

    // Extract IPv4 addresses
    for cap in IPV4_REGEX.find_iter(text) {
        let ip = cap.as_str();
        if !ip.starts_with("0.") && !ip.starts_with("127.0.0.1") {
            try_add_artifact(&mut artifacts, &mut seen, ArtifactType::Ipv4, ip, 0.85, source);
        }
    }

    // Extract domains (filter out common ones)
    for cap in DOMAIN_REGEX.find_iter(text) {
        let domain = cap.as_str().to_lowercase();
        if !is_common_domain(&domain) && !domain.ends_with(".onion") {
            try_add_artifact(&mut artifacts, &mut seen, ArtifactType::Domain, cap.as_str(), 0.7, source);
        }
    }

    artifacts
}

/// Filter out common/benign domains
fn is_common_domain(domain: &str) -> bool {
    const COMMON: &[&str] = &[
        "google.com", "facebook.com", "twitter.com", "github.com",
        "microsoft.com", "apple.com", "amazon.com", "youtube.com",
        "linkedin.com", "instagram.com", "wikipedia.org", "reddit.com",
    ];
    COMMON.iter().any(|&c| domain.ends_with(c))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_bitcoin() {
        let text = "Send payment to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
        let artifacts = extract_artifacts(text, None);
        assert!(artifacts.iter().any(|a| a.artifact_type == ArtifactType::Bitcoin));
    }

    #[test]
    fn test_extract_onion() {
        let text = "Visit our forum at dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad.onion";
        let artifacts = extract_artifacts(text, None);
        assert!(artifacts.iter().any(|a| a.artifact_type == ArtifactType::OnionAddress));
    }

    #[test]
    fn test_extract_cve() {
        let text = "Exploiting CVE-2023-12345 for initial access";
        let artifacts = extract_artifacts(text, None);
        assert!(artifacts.iter().any(|a| a.artifact_type == ArtifactType::Cve));
    }

    #[test]
    fn test_extract_email() {
        let text = "Contact admin@darkmarket.onion for support";
        let artifacts = extract_artifacts(text, None);
        assert!(artifacts.iter().any(|a| a.artifact_type == ArtifactType::Email));
    }
}
