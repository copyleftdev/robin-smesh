<p align="center">
  <img src="media/logo.png" alt="Robin×SMESH Logo" width="300"/>
</p>

<h1 align="center">Robin×SMESH</h1>

<p align="center">
  <strong>🕸️ Decentralized Dark Web OSINT via Signal Diffusion 🕸️</strong>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#multi-specialist-analysis">Specialists</a> •
  <a href="#external-osint-enrichment">Enrichment</a> •
  <a href="./reports/">Reports</a>
</p>

A Rust reimagining of [Robin](https://github.com/apurvsinghgautam/robin) that replaces central LLM orchestration with [SMESH](https://github.com/copyleftdev/smesh-rust)'s plant-inspired signal diffusion protocol.

## The Difference

| Aspect | Python Robin | Robin×SMESH |
|--------|--------------|-------------|
| **Orchestration** | Sequential pipeline | Emergent via signals |
| **Search** | ThreadPool, 16 engines | N crawler agents, infinite scale |
| **Filtering** | Single LLM call | Multiple filter agents + consensus |
| **Fault tolerance** | Breaks on timeout | Signals decay, others pick up |
| **Performance** | ~seconds per stage | ~μs signal ops + async I/O |

## Architecture

```
┌────────────────────────────────────────────────────────────────────────────────┐
│                           SHARED SIGNAL FIELD                                   │
│  Signals decay over time · Reinforcement = consensus · No central controller   │
└────────────────────────────────────────────────────────────────────────────────┘
       ▲                    ▲                    ▲                    ▲
  ┌────┴────┐          ┌────┴────┐          ┌────┴────┐          ┌────┴────┐
  │ REFINER │          │ CRAWLER │          │ FILTER  │          │ ANALYST │
  │  Agent  │          │  Swarm  │          │  Agent  │          │  Agent  │
  └─────────┘          └─────────┘          └─────────┘          └─────────┘
```

### Signal Flow

1. **UserQuery** → Refiner senses, emits **RefinedQuery**
2. **RefinedQuery** → Crawlers sense, emit **RawResult** (per .onion link)
3. **RawResult** → Filter senses batch, emits **FilteredResult** (top 20)
4. **FilteredResult** → Scrapers sense, emit **ScrapedContent**
5. **ScrapedContent** → Extractor senses, emits **ExtractedArtifacts** (IOCs)
6. **ExtractedArtifacts** → Enricher senses, queries surface web, emits **EnrichedArtifacts**
7. **ScrapedContent + Artifacts** → Analyst senses, emits **Summary**

## Quick Start

```bash
# Build
cargo build --release

# Check Tor connection
./target/release/robin-smesh status

# Run investigation (Anthropic is default)
ANTHROPIC_API_KEY=sk-ant-... ./target/release/robin-smesh query \
  -q "ransomware payments" \
  --timeout 300

# Multi-specialist mode (6 expert analysts + lead synthesis)
ANTHROPIC_API_KEY=sk-ant-... ./target/release/robin-smesh query \
  -q "threat actor infrastructure" \
  --specialists

# External OSINT enrichment (GitHub + Brave search)
ANTHROPIC_API_KEY=sk-ant-... ./target/release/robin-smesh query \
  -q "data breach credentials" \
  --enrich \
  --specialists

# Blockchain temporal analysis (BTC/ETH wallet patterns)
ANTHROPIC_API_KEY=sk-ant-... ./target/release/robin-smesh query \
  -q "ransomware bitcoin wallets" \
  --blockchain \
  --specialists

# Use OpenAI instead
OPENAI_API_KEY=sk-... ./target/release/robin-smesh query \
  -q "ransomware payments" \
  --openai \
  -m gpt-4o-mini

# Use OpenRouter
OPENROUTER_API_KEY=... ./target/release/robin-smesh query \
  -q "data breach credentials" \
  --openrouter \
  -m anthropic/claude-3-haiku
```

## Requirements

- **Rust 1.75+** 
- **Tor** running on port 9050:
  ```bash
  # Linux
  sudo apt install tor && sudo systemctl start tor
  
  # Mac
  brew install tor && brew services start tor
  ```
- **LLM API Key**:
  - `ANTHROPIC_API_KEY` (default, recommended)
  - `OPENAI_API_KEY` (with `--openai` flag)
  - `OPENROUTER_API_KEY` (with `--openrouter` flag)
- **Optional for enrichment**:
  - `GITHUB_TOKEN` – Increases GitHub API rate limits
  - `BRAVE_API_KEY` – Enables Brave Search integration

## Crate Structure

```
robin-smesh/
├── robin-core/      # Signals, artifacts, field, search engines
├── robin-tor/       # Tor proxy, crawler, scraper
├── robin-agents/    # Specialized OSINT agents (refiner, crawler, filter, etc.)
├── robin-runtime/   # SMESH swarm coordinator
└── robin-cli/       # CLI binary
```

## Key Concepts from SMESH

- **Signals**: Messages with intensity that decays over time
- **Field**: Shared space where signals propagate
- **Reinforcement**: Agreement from multiple agents boosts confidence
- **Emergence**: No central controller; coordination emerges from simple rules

## Artifact Extraction

Automatically extracts:
- 🔗 Onion addresses
- 💰 Bitcoin/Ethereum/Monero addresses
- 📧 Email addresses
- 🔐 File hashes (MD5, SHA1, SHA256)
- 🐛 CVE identifiers
- ⚔️ MITRE ATT&CK TTPs
- 🌐 Domains and IPs

## Multi-Specialist Analysis

With `--specialists`, analysis is performed by 6 expert personas before synthesis:

| Specialist | Focus |
|------------|-------|
| 🎯 **Threat Intel** | Actor TTPs, campaign patterns, IOC correlation |
| 💰 **Financial Crime** | Cryptocurrency flows, money laundering, fraud |
| 🔐 **Technical** | Malware, exploits, infrastructure analysis |
| 🌍 **Geopolitical** | Nation-state activity, regional threats |
| ⚖️ **Legal/Regulatory** | Compliance, jurisdiction, evidence handling |
| 🔮 **Strategic** | Trend forecasting, risk assessment |

## External OSINT Enrichment

With `--enrich`, extracted artifacts are queried against surface web sources:

- **GitHub Code Search** – Emails, usernames, code snippets, hashes
- **Brave Search** – IPs, domains, malware hashes, threat intel

This bridges dark web findings with public attribution data.

## Blockchain Temporal Analysis

With `--blockchain`, extracted cryptocurrency addresses are analyzed for temporal patterns:

- **Bitcoin** – Blockstream API (no key required)
- **Ethereum** – Etherscan API (optional `ETHERSCAN_API_KEY` for higher rate limits)

Analysis includes:
- Wallet age (first/last transaction)
- Transaction frequency and volume
- **Temporal patterns** – Regular intervals, burst activity, dormancy periods
- **Timezone inference** – Activity concentration by hour
- Risk indicators (high volume, recent activity, contract interactions)

## Example Reports

Sample investigation reports are available in [`reports/`](./reports/):

```
reports/
├── summary_2026-01-20_15-24-29.md  # Ransomware payment investigation
├── summary_2026-01-20_15-26-30.md  # Threat actor infrastructure
├── summary_2026-01-20_15-51-10.md  # Multi-specialist analysis
└── summary_2026-01-20_16-09-02.md  # With external enrichment
```

## License

MIT OR Apache-2.0
