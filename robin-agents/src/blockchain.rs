//! Blockchain Analysis Agent
//!
//! Performs temporal analysis on cryptocurrency wallet addresses extracted
//! from dark web content. Queries public blockchain APIs to derive patterns.

use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashSet;
use std::env;
use std::time::Duration;
use tracing::{info, warn};

use robin_core::{
    AgentType, Artifact, ArtifactType, Field, OsintPayload, Signal, TemporalPattern, WalletAnalysis,
};

use crate::traits::{AgentConfig, AgentError, OsintAgent};

/// Configuration for the blockchain analysis agent
#[derive(Debug, Clone)]
pub struct BlockchainConfig {
    /// Etherscan API key (optional, increases rate limits)
    pub etherscan_api_key: Option<String>,
    /// Timeout for API requests
    pub request_timeout: Duration,
    /// Minimum transaction count to analyze patterns
    pub min_tx_for_patterns: u32,
}

impl Default for BlockchainConfig {
    fn default() -> Self {
        Self {
            etherscan_api_key: env::var("ETHERSCAN_API_KEY").ok(),
            request_timeout: Duration::from_secs(30),
            min_tx_for_patterns: 3,
        }
    }
}

/// Agent that analyzes cryptocurrency wallet addresses
pub struct BlockchainAgent {
    config: AgentConfig,
    blockchain_config: BlockchainConfig,
    client: Client,
    processed_addresses: HashSet<String>,
}

impl BlockchainAgent {
    pub fn new(config: AgentConfig, blockchain_config: BlockchainConfig) -> Self {
        let client = Client::builder()
            .timeout(blockchain_config.request_timeout)
            .user_agent("Robin-SMESH/1.0")
            .build()
            .expect("Failed to create HTTP client");

        Self {
            config,
            blockchain_config,
            client,
            processed_addresses: HashSet::new(),
        }
    }

    /// Determine which blockchain a crypto address belongs to
    fn detect_chain(artifact: &Artifact) -> Option<&'static str> {
        match artifact.artifact_type {
            ArtifactType::Bitcoin => Some("bitcoin"),
            ArtifactType::Ethereum => Some("ethereum"),
            ArtifactType::Monero => None, // Monero is privacy-focused, no public explorer
            _ => None,
        }
    }

    /// Analyze a Bitcoin address using Blockstream API
    async fn analyze_bitcoin(&self, address: &str) -> Result<WalletAnalysis, AgentError> {
        let url = format!("https://blockstream.info/api/address/{}", address);
        
        let response = self.client.get(&url).send().await.map_err(|e| {
            AgentError::Network(format!("Blockstream API error: {}", e))
        })?;

        if !response.status().is_success() {
            return Err(AgentError::Network(format!(
                "Blockstream returned status: {}",
                response.status()
            )));
        }

        let data: BlockstreamAddress = response.json().await.map_err(|e| {
            AgentError::Parse(format!("Failed to parse Blockstream response: {}", e))
        })?;

        // Get transaction history for temporal analysis
        let tx_url = format!("https://blockstream.info/api/address/{}/txs", address);
        let txs: Vec<BlockstreamTx> = match self.client.get(&tx_url).send().await {
            Ok(resp) => resp.json().await.unwrap_or_default(),
            Err(_) => vec![],
        };

        let (first_seen, last_seen, patterns) = self.analyze_tx_patterns(&txs);
        let risk_indicators = self.detect_risk_indicators(&data, &txs);

        Ok(WalletAnalysis {
            first_seen,
            last_seen,
            tx_count: data.chain_stats.tx_count + data.mempool_stats.tx_count,
            total_received: data.chain_stats.funded_txo_sum + data.mempool_stats.funded_txo_sum,
            total_sent: data.chain_stats.spent_txo_sum + data.mempool_stats.spent_txo_sum,
            balance: (data.chain_stats.funded_txo_sum + data.mempool_stats.funded_txo_sum)
                .saturating_sub(data.chain_stats.spent_txo_sum + data.mempool_stats.spent_txo_sum),
            patterns,
            risk_indicators,
        })
    }

    /// Analyze an Ethereum address using Etherscan API
    async fn analyze_ethereum(&self, address: &str) -> Result<WalletAnalysis, AgentError> {
        let api_key = self.blockchain_config.etherscan_api_key.as_deref().unwrap_or("");
        
        // Get balance
        let balance_url = format!(
            "https://api.etherscan.io/api?module=account&action=balance&address={}&tag=latest&apikey={}",
            address, api_key
        );
        
        let balance_resp: EtherscanResponse<String> = self.client.get(&balance_url)
            .send()
            .await
            .map_err(|e| AgentError::Network(format!("Etherscan balance error: {}", e)))?
            .json()
            .await
            .map_err(|e| AgentError::Parse(format!("Failed to parse Etherscan balance: {}", e)))?;

        let balance: u64 = balance_resp.result.parse().unwrap_or(0);

        // Get transaction list
        let tx_url = format!(
            "https://api.etherscan.io/api?module=account&action=txlist&address={}&startblock=0&endblock=99999999&sort=asc&apikey={}",
            address, api_key
        );

        let tx_resp: EtherscanResponse<Vec<EtherscanTx>> = match self.client.get(&tx_url).send().await {
            Ok(resp) => resp.json().await.unwrap_or(EtherscanResponse { status: "0".to_string(), result: vec![] }),
            Err(_) => EtherscanResponse { status: "0".to_string(), result: vec![] },
        };

        let txs = tx_resp.result;
        let tx_count = txs.len() as u32;

        let (first_seen, last_seen) = if txs.is_empty() {
            (None, None)
        } else {
            let first = txs.first().and_then(|t| t.time_stamp.parse::<i64>().ok());
            let last = txs.last().and_then(|t| t.time_stamp.parse::<i64>().ok());
            (first, last)
        };

        let patterns = self.analyze_eth_tx_patterns(&txs);
        let risk_indicators = self.detect_eth_risk_indicators(&txs);

        // Calculate totals
        let (total_received, total_sent) = txs.iter().fold((0u64, 0u64), |(recv, sent), tx| {
            let value: u64 = tx.value.parse().unwrap_or(0);
            if tx.to.as_ref().map(|t| t.eq_ignore_ascii_case(address)).unwrap_or(false) {
                (recv.saturating_add(value), sent)
            } else {
                (recv, sent.saturating_add(value))
            }
        });

        Ok(WalletAnalysis {
            first_seen,
            last_seen,
            tx_count,
            total_received,
            total_sent,
            balance,
            patterns,
            risk_indicators,
        })
    }

    /// Analyze transaction patterns for temporal intelligence
    fn analyze_tx_patterns(&self, txs: &[BlockstreamTx]) -> (Option<i64>, Option<i64>, Vec<TemporalPattern>) {
        if txs.is_empty() {
            return (None, None, vec![]);
        }

        let timestamps: Vec<i64> = txs.iter()
            .filter_map(|tx| tx.status.block_time)
            .collect();

        if timestamps.is_empty() {
            return (None, None, vec![]);
        }

        let first_seen = timestamps.iter().min().copied();
        let last_seen = timestamps.iter().max().copied();

        let mut patterns = vec![];

        // Check for regular intervals
        if timestamps.len() >= self.blockchain_config.min_tx_for_patterns as usize {
            let intervals: Vec<i64> = timestamps.windows(2)
                .map(|w| w[1] - w[0])
                .collect();

            if !intervals.is_empty() {
                let avg_interval = intervals.iter().sum::<i64>() / intervals.len() as i64;
                let variance: f64 = intervals.iter()
                    .map(|&i| (i - avg_interval).pow(2) as f64)
                    .sum::<f64>() / intervals.len() as f64;
                let std_dev = variance.sqrt();

                // Low variance = regular pattern
                if std_dev < (avg_interval as f64 * 0.3) && avg_interval > 0 {
                    let interval_desc = if avg_interval < 3600 {
                        format!("~{} minutes", avg_interval / 60)
                    } else if avg_interval < 86400 {
                        format!("~{} hours", avg_interval / 3600)
                    } else {
                        format!("~{} days", avg_interval / 86400)
                    };

                    patterns.push(TemporalPattern {
                        pattern_type: "regular_interval".to_string(),
                        description: format!("Transactions occur at regular intervals of {}", interval_desc),
                        confidence: 1.0 - (std_dev / avg_interval as f64).min(1.0),
                        evidence: vec![
                            format!("Average interval: {} seconds", avg_interval),
                            format!("Standard deviation: {:.0} seconds", std_dev),
                        ],
                    });
                }

                // Check for burst activity
                let short_intervals: Vec<_> = intervals.iter().filter(|&&i| i < 3600).collect();
                if short_intervals.len() > intervals.len() / 2 {
                    patterns.push(TemporalPattern {
                        pattern_type: "burst_activity".to_string(),
                        description: "Multiple transactions within short time periods".to_string(),
                        confidence: short_intervals.len() as f64 / intervals.len() as f64,
                        evidence: vec![
                            format!("{} of {} transactions within 1 hour of each other", 
                                    short_intervals.len(), intervals.len()),
                        ],
                    });
                }
            }
        }

        // Check for dormancy followed by activity
        if let (Some(first), Some(last)) = (first_seen, last_seen) {
            let lifespan = last - first;
            if lifespan > 86400 * 30 && timestamps.len() >= 2 {
                // Find longest gap
                let max_gap = timestamps.windows(2)
                    .map(|w| w[1] - w[0])
                    .max()
                    .unwrap_or(0);

                if max_gap > lifespan / 2 {
                    patterns.push(TemporalPattern {
                        pattern_type: "dormant_then_active".to_string(),
                        description: format!("Long dormancy period of {} days followed by resumed activity",
                                            max_gap / 86400),
                        confidence: max_gap as f64 / lifespan as f64,
                        evidence: vec![
                            format!("Maximum gap: {} days", max_gap / 86400),
                            format!("Total wallet age: {} days", lifespan / 86400),
                        ],
                    });
                }
            }
        }

        (first_seen, last_seen, patterns)
    }

    fn analyze_eth_tx_patterns(&self, txs: &[EtherscanTx]) -> Vec<TemporalPattern> {
        let timestamps: Vec<i64> = txs.iter()
            .filter_map(|tx| tx.time_stamp.parse::<i64>().ok())
            .collect();

        if timestamps.len() < self.blockchain_config.min_tx_for_patterns as usize {
            return vec![];
        }

        let mut patterns = vec![];

        // Analyze time-of-day patterns for timezone inference
        let hours: Vec<u32> = timestamps.iter()
            .map(|&ts| ((ts % 86400) / 3600) as u32)
            .collect();

        let mut hour_counts = [0u32; 24];
        for h in &hours {
            hour_counts[*h as usize] += 1;
        }

        let peak_hour = hour_counts.iter().enumerate()
            .max_by_key(|(_, &count)| count)
            .map(|(h, _)| h)
            .unwrap_or(0);

        let activity_in_peak_range: usize = hours.iter()
            .filter(|&&h| (h as i32 - peak_hour as i32).abs() <= 4 || 
                         (h as i32 - peak_hour as i32 + 24).abs() <= 4)
            .count();

        if activity_in_peak_range > hours.len() * 2 / 3 {
            patterns.push(TemporalPattern {
                pattern_type: "timezone_indicator".to_string(),
                description: format!("Activity concentrated around {}:00 UTC (possible operator timezone)", peak_hour),
                confidence: activity_in_peak_range as f64 / hours.len() as f64,
                evidence: vec![
                    format!("Peak activity hour: {}:00 UTC", peak_hour),
                    format!("{}% of transactions within ±4 hours of peak", 
                            activity_in_peak_range * 100 / hours.len()),
                ],
            });
        }

        patterns
    }

    fn detect_risk_indicators(&self, data: &BlockstreamAddress, txs: &[BlockstreamTx]) -> Vec<String> {
        let mut indicators = vec![];

        // High volume
        let total_btc = (data.chain_stats.funded_txo_sum as f64) / 100_000_000.0;
        if total_btc > 10.0 {
            indicators.push(format!("High volume: {:.2} BTC total received", total_btc));
        }

        // Many transactions
        if data.chain_stats.tx_count > 100 {
            indicators.push(format!("High transaction count: {}", data.chain_stats.tx_count));
        }

        // Recent activity
        if let Some(latest) = txs.first() {
            if let Some(block_time) = latest.status.block_time {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64;
                if now - block_time < 86400 * 7 {
                    indicators.push("Active within last 7 days".to_string());
                }
            }
        }

        indicators
    }

    fn detect_eth_risk_indicators(&self, txs: &[EtherscanTx]) -> Vec<String> {
        let mut indicators = vec![];

        // Contract interactions
        let contract_txs: usize = txs.iter()
            .filter(|tx| !tx.input.is_empty() && tx.input != "0x")
            .count();
        
        if contract_txs > txs.len() / 2 {
            indicators.push(format!("Heavy smart contract usage: {}% of transactions", 
                                   contract_txs * 100 / txs.len().max(1)));
        }

        // Check for failed transactions (possible attack patterns)
        let failed: usize = txs.iter()
            .filter(|tx| tx.is_error.as_deref() == Some("1"))
            .count();
        
        if failed > 5 {
            indicators.push(format!("{} failed transactions (possible probing/attack)", failed));
        }

        indicators
    }
}

#[async_trait]
impl OsintAgent for BlockchainAgent {
    fn id(&self) -> &str {
        &self.config.id
    }

    fn agent_type(&self) -> &str {
        "blockchain_analyst"
    }

    fn sense<'a>(&self, field: &'a Field) -> Vec<&'a Signal> {
        field.sense_by_type(self.config.sensing_threshold).extracted_artifacts
    }

    async fn process(&mut self, field: &mut Field) -> Result<Vec<String>, AgentError> {
        // Collect crypto artifacts to analyze
        let artifacts_to_analyze: Vec<Artifact> = {
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
                    let key = format!("{:?}:{}", artifact.artifact_type, artifact.value);
                    !self.processed_addresses.contains(&key) && 
                    Self::detect_chain(artifact).is_some()
                })
                .collect()
        };

        let mut emitted_hashes = Vec::new();

        for artifact in artifacts_to_analyze {
            let key = format!("{:?}:{}", artifact.artifact_type, artifact.value);
            self.processed_addresses.insert(key);

            let chain = match Self::detect_chain(&artifact) {
                Some(c) => c,
                None => continue,
            };

            info!(
                "Analyzing {} address: {}...",
                chain,
                &artifact.value[..artifact.value.len().min(16)]
            );

            let analysis_result = match chain {
                "bitcoin" => self.analyze_bitcoin(&artifact.value).await,
                "ethereum" => self.analyze_ethereum(&artifact.value).await,
                _ => continue,
            };

            match analysis_result {
                Ok(analysis) => {
                    info!(
                        "Found {} transactions, {} patterns for {} address",
                        analysis.tx_count,
                        analysis.patterns.len(),
                        chain
                    );

                    let signal = Signal::builder(OsintPayload::BlockchainAnalysis {
                        address: artifact.value.clone(),
                        chain: chain.to_string(),
                        analysis,
                    })
                    .origin(&self.config.id)
                    .confidence(0.8)
                    .ttl(120.0)
                    .build();

                    let hash = field.emit(signal);
                    emitted_hashes.push(hash);
                }
                Err(e) => {
                    warn!("Failed to analyze {} address: {}", chain, e);
                }
            }
        }

        Ok(emitted_hashes)
    }

    fn heartbeat(&self, field: &mut Field) {
        let signal = Signal::builder(OsintPayload::Heartbeat {
            agent_id: self.config.id.clone(),
            agent_type: AgentType::BlockchainAnalyst,
            capacity: 1.0,
        })
        .origin(&self.config.id)
        .ttl(10.0)
        .build();
        field.emit(signal);
    }
}

// Blockstream API response types
#[derive(Debug, Deserialize)]
struct BlockstreamAddress {
    chain_stats: BlockstreamStats,
    mempool_stats: BlockstreamStats,
}

#[derive(Debug, Deserialize)]
struct BlockstreamStats {
    tx_count: u32,
    funded_txo_sum: u64,
    spent_txo_sum: u64,
}

#[derive(Debug, Deserialize)]
struct BlockstreamTx {
    status: BlockstreamTxStatus,
}

#[derive(Debug, Deserialize)]
struct BlockstreamTxStatus {
    block_time: Option<i64>,
}

// Etherscan API response types
#[derive(Debug, Deserialize)]
struct EtherscanResponse<T> {
    status: String,
    result: T,
}

#[derive(Debug, Deserialize)]
struct EtherscanTx {
    #[serde(rename = "timeStamp")]
    time_stamp: String,
    #[serde(default)]
    to: Option<String>,
    value: String,
    input: String,
    #[serde(rename = "isError")]
    is_error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_chain() {
        let btc = Artifact {
            artifact_type: ArtifactType::Bitcoin,
            value: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string(),
            source: None,
            context: None,
            confidence: 1.0,
        };
        assert_eq!(BlockchainAgent::detect_chain(&btc), Some("bitcoin"));

        let eth = Artifact {
            artifact_type: ArtifactType::Ethereum,
            value: "0x742d35Cc6634C0532925a3b844Bc9e7595f".to_string(),
            source: None,
            context: None,
            confidence: 1.0,
        };
        assert_eq!(BlockchainAgent::detect_chain(&eth), Some("ethereum"));

        let xmr = Artifact {
            artifact_type: ArtifactType::Monero,
            value: "4...".to_string(),
            source: None,
            context: None,
            confidence: 1.0,
        };
        assert_eq!(BlockchainAgent::detect_chain(&xmr), None); // Privacy coin
    }

    #[test]
    fn test_blockchain_config_default() {
        let config = BlockchainConfig::default();
        assert_eq!(config.request_timeout, Duration::from_secs(30));
        assert_eq!(config.min_tx_for_patterns, 3);
    }
}
