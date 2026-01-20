# Robin×SMESH

**Decentralized Dark Web OSINT using SMESH Signal Diffusion**

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
6. **ScrapedContent + Artifacts** → Analyst senses, emits **Summary**

## Quick Start

```bash
# Build
cargo build --release

# Check Tor connection
./target/release/robin-smesh status

# Run investigation
OPENAI_API_KEY=sk-... ./target/release/robin-smesh query \
  -q "ransomware payments" \
  -m gpt-4o-mini \
  --timeout 300

# Use OpenRouter instead
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
- **LLM API Key** (OpenAI, OpenRouter, or local)

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

## License

MIT OR Apache-2.0
