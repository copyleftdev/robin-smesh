//! Robin×SMESH CLI
//!
//! Decentralized Dark Web OSINT using SMESH signal diffusion.

use std::fs;
use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

use robin_agents::{AnthropicConfig, OpenAIBackendConfig, create_anthropic_backend, create_backend};
use robin_runtime::{Swarm, SwarmConfig};
use robin_tor::TorConfig;

#[derive(Parser)]
#[command(name = "robin-smesh")]
#[command(author, version, about = "Robin×SMESH: Decentralized Dark Web OSINT", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Verbosity level (0-3)
    #[arg(short, long, default_value = "1")]
    verbose: u8,
}

#[derive(Subcommand)]
enum Commands {
    /// Run an OSINT investigation
    Query {
        /// The search query
        #[arg(short, long)]
        query: String,

        /// LLM model to use
        #[arg(short, long, default_value = "claude-sonnet-4-20250514")]
        model: String,

        /// Anthropic API key (or set ANTHROPIC_API_KEY env var)
        #[arg(long, env = "ANTHROPIC_API_KEY")]
        anthropic_key: Option<String>,

        /// OpenAI API key (or set OPENAI_API_KEY env var)
        #[arg(long, env = "OPENAI_API_KEY")]
        api_key: Option<String>,

        /// OpenRouter API key (or set OPENROUTER_API_KEY env var)
        #[arg(long, env = "OPENROUTER_API_KEY")]
        openrouter_key: Option<String>,

        /// Use OpenAI instead of Anthropic
        #[arg(long)]
        openai: bool,

        /// Use OpenRouter instead of Anthropic
        #[arg(long)]
        openrouter: bool,

        /// Output file for the summary (default: summary_<timestamp>.md)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Maximum runtime in seconds
        #[arg(long, default_value = "300")]
        timeout: u64,

        /// Number of crawler agents
        #[arg(long, default_value = "2")]
        crawlers: usize,

        /// Number of scraper agents
        #[arg(long, default_value = "3")]
        scrapers: usize,

        /// Use multi-specialist analyst mode (6 experts + lead synthesis)
        #[arg(long)]
        specialists: bool,

        /// Enable external OSINT enrichment (GitHub, Brave search)
        #[arg(long)]
        enrich: bool,

        /// Enable blockchain temporal analysis (Blockstream, Etherscan)
        #[arg(long)]
        blockchain: bool,

        /// Enable paste site monitoring (Pastebin, Rentry, dpaste, etc.)
        #[arg(long)]
        pastes: bool,
    },

    /// Check Tor connection status
    Status,

    /// Show field statistics during a run
    Stats,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Set up logging
    let log_level = match cli.verbose {
        0 => Level::ERROR,
        1 => Level::INFO,
        2 => Level::DEBUG,
        _ => Level::TRACE,
    };

    FmtSubscriber::builder()
        .with_max_level(log_level)
        .with_target(false)
        .with_thread_ids(false)
        .compact()
        .init();

    match cli.command {
        Commands::Query {
            query,
            model,
            anthropic_key,
            api_key,
            openrouter_key,
            openai,
            openrouter,
            output,
            timeout,
            crawlers,
            scrapers,
            specialists,
            enrich,
            blockchain,
            pastes,
        } => {
            run_query(
                &query,
                &model,
                anthropic_key,
                api_key,
                openrouter_key,
                openai,
                openrouter,
                output,
                timeout,
                crawlers,
                scrapers,
                specialists,
                enrich,
                blockchain,
                pastes,
            )
            .await?;
        }
        Commands::Status => {
            check_status().await?;
        }
        Commands::Stats => {
            println!("Stats command shows field statistics during a run.");
            println!("Use: robin-smesh query -q \"your query\" -v 2");
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn run_query(
    query: &str,
    model: &str,
    anthropic_key: Option<String>,
    api_key: Option<String>,
    openrouter_key: Option<String>,
    use_openai: bool,
    use_openrouter: bool,
    output: Option<PathBuf>,
    timeout: u64,
    crawlers: usize,
    scrapers: usize,
    use_specialists: bool,
    enable_enrichment: bool,
    enable_blockchain: bool,
    enable_pastes: bool,
) -> Result<()> {
    println!("🕵️ Robin×SMESH - Decentralized Dark Web OSINT\n");

    // Configure backend (Anthropic is default)
    let backend = if use_openrouter {
        let key = openrouter_key.ok_or_else(|| {
            anyhow::anyhow!("OpenRouter API key required. Set OPENROUTER_API_KEY or use --openrouter-key")
        })?;
        create_backend(OpenAIBackendConfig::openrouter(&key, model))?
    } else if use_openai {
        let key = api_key.ok_or_else(|| {
            anyhow::anyhow!("OpenAI API key required. Set OPENAI_API_KEY or use --api-key")
        })?;
        create_backend(OpenAIBackendConfig::openai(&key, model))?
    } else {
        // Default: Anthropic
        let key = anthropic_key.ok_or_else(|| {
            anyhow::anyhow!("Anthropic API key required. Set ANTHROPIC_API_KEY or use --anthropic-key")
        })?;
        create_anthropic_backend(AnthropicConfig::new(&key, model))?
    };

    let provider = if use_openrouter { "OpenRouter" } else if use_openai { "OpenAI" } else { "Anthropic" };
    let analyst_mode = if use_specialists { "multi-specialist (6 experts)" } else { "single" };
    let enrichment_mode = if enable_enrichment { "enabled" } else { "disabled" };
    let blockchain_mode = if enable_blockchain { "enabled" } else { "disabled" };
    println!("📡 Provider: {} | Model: {}", provider, model);
    println!("🔍 Query: {}", query);
    println!("⏱️  Timeout: {}s", timeout);
    
    let pastes_mode = if enable_pastes { "enabled" } else { "disabled" };
    let optional_agents = [
        if enable_enrichment { Some("1 enricher") } else { None },
        if enable_blockchain { Some("1 blockchain") } else { None },
        if enable_pastes { Some("1 paste-monitor") } else { None },
    ].into_iter().flatten().collect::<Vec<_>>().join(", ");
    let optional_str = if optional_agents.is_empty() { String::new() } else { format!("{}, ", optional_agents) };
    
    println!("🤖 Agents: 1 refiner, {} crawlers, 1 filter, {} scrapers, 1 extractor, {}1 analyst ({})",
        crawlers, scrapers, optional_str, analyst_mode);
    println!("🌐 Enrichment: {} | ⛓️  Blockchain: {} | 📋 Pastes: {}\n", enrichment_mode, blockchain_mode, pastes_mode);

    // Check Tor connection
    println!("🔌 Checking Tor connection...");
    let tor_config = TorConfig::default();
    match robin_tor::check_tor_connection(&tor_config).await {
        Ok(true) => println!("✅ Tor connection OK\n"),
        Ok(false) => {
            println!("⚠️  Tor .onion check timed out (this is normal - continuing anyway)");
            println!("   Tip: Ensure Tor is running on port 9050\n");
        }
        Err(e) => {
            println!("⚠️  Tor check error: {} (continuing anyway)\n", e);
        }
    }

    // Create swarm
    let config = SwarmConfig {
        backend,
        tor_config,
        tick_interval_ms: 500,
        max_runtime_secs: timeout,
        num_crawlers: crawlers,
        num_scrapers: scrapers,
        use_specialists,
        enable_enrichment,
        enable_blockchain,
        enable_pastes,
    };

    let mut swarm = Swarm::new(config)?;

    // Submit query
    println!("🚀 Starting SMESH swarm...");
    swarm.submit_query(query, 1.0);

    // Run swarm
    let result = swarm.run().await?;

    // Handle result
    match result {
        Some(summary) => {
            let output_path = output.unwrap_or_else(|| {
                let timestamp = chrono::Utc::now().format("%Y-%m-%d_%H-%M-%S");
                PathBuf::from(format!("summary_{}.md", timestamp))
            });

            fs::write(&output_path, &summary)?;
            println!("\n✅ Investigation complete!");
            println!("📄 Summary saved to: {}", output_path.display());

            // Print summary preview
            println!("\n{}", "=".repeat(60));
            let preview: String = summary.chars().take(1000).collect();
            println!("{}", preview);
            if summary.len() > 1000 {
                println!("...\n[truncated - see full summary in output file]");
            }
        }
        None => {
            println!("\n⚠️  No summary generated within timeout.");
            println!("   Try increasing --timeout or check Tor connection.");

            // Show final stats
            let stats = swarm.stats();
            println!("\n📊 Final field stats:");
            println!("   Active signals: {}", stats.active_signals);
            println!("   Total reinforcements: {}", stats.total_reinforcements);
        }
    }

    Ok(())
}

async fn check_status() -> Result<()> {
    println!("🔌 Checking Tor connection...\n");

    let config = TorConfig::default();

    match robin_tor::check_tor_connection(&config).await {
        Ok(true) => {
            println!("✅ Tor is running and accessible");
            println!("   Proxy: {}", config.socks_addr);
        }
        Ok(false) => {
            println!("❌ Tor is not accessible");
            println!("   Expected proxy at: {}", config.socks_addr);
            println!("\n   To install Tor:");
            println!("   - Linux: sudo apt install tor");
            println!("   - Mac: brew install tor");
            println!("   - Then start: sudo systemctl start tor (or brew services start tor)");
        }
        Err(e) => {
            println!("❌ Error checking Tor: {}", e);
        }
    }

    Ok(())
}
