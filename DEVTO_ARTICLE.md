---
title: "I Replaced My LLM Orchestrator with Plant Biology — Here's What Happened"
published: true
description: How SMESH signal diffusion transformed a dark web OSINT tool from sequential pipeline to emergent swarm intelligence
tags: rust, ai, osint, cybersecurity
cover_image: https://github.com/copyleftdev/robin-smesh/raw/master/media/logo.png
---

# I Replaced My LLM Orchestrator with Plant Biology — Here's What Happened

What if your AI agents coordinated like plants instead of following a script?

That question led me down a rabbit hole that ended with **Robin×SMESH** — a dark web OSINT framework where agents discover, scrape, and analyze threat intelligence through *signal diffusion* rather than central orchestration.

## The Problem: LLM Pipelines Are Fragile

The original [Robin](https://github.com/apurvsinghgautam/robin) is a solid Python tool for dark web reconnaissance. It queries .onion search engines, filters results with an LLM, scrapes content, and extracts IOCs. Classic pipeline architecture:

```
Query → Search → Filter → Scrape → Extract → Analyze
```

But pipelines have problems:

1. **Single point of failure** — One timeout kills everything
2. **Sequential bottlenecks** — Each stage waits for the previous
3. **No emergent behavior** — Agents can't adapt or collaborate
4. **Rigid orchestration** — Adding new capabilities means rewriting the controller

I wanted something more... *organic*.

## Enter SMESH: Plant-Inspired Coordination

[SMESH](https://github.com/copyleftdev/smesh-rust) (Signal-Mediated Emergent Swarm Heuristics) is a coordination protocol inspired by how plants communicate through chemical signals.

Plants don't have brains, yet they:
- Coordinate growth toward light across millions of cells
- Respond to threats by releasing warning chemicals
- Share resources through root networks
- Adapt to damage without central control

The key insight: **coordination emerges from simple local rules + shared signals**.

### How SMESH Works

```
┌────────────────────────────────────────────────────────────┐
│                    SHARED SIGNAL FIELD                      │
│   Signals decay over time · Reinforcement = consensus       │
│              No central controller                          │
└────────────────────────────────────────────────────────────┘
       ▲              ▲              ▲              ▲
  ┌────┴────┐    ┌────┴────┐    ┌────┴────┐    ┌────┴────┐
  │ Agent A │    │ Agent B │    │ Agent C │    │ Agent D │
  └─────────┘    └─────────┘    └─────────┘    └─────────┘
```

Each agent follows three rules:
1. **Sense** — Detect signals above your threshold
2. **Process** — Do your specialized work
3. **Emit** — Broadcast results as new signals

Signals have:
- **Intensity** — How "loud" the signal is (decays over time)
- **Confidence** — How reliable (multiple agents agreeing = reinforcement)
- **TTL** — Time-to-live before signal dies

No agent knows the full plan. Coordination *emerges*.

## Marrying Robin + SMESH

Here's how I mapped OSINT operations to signal types:

| Signal Type | Emitter | Consumer | Purpose |
|-------------|---------|----------|---------|
| `UserQuery` | CLI | Refiner | Initial investigation request |
| `RefinedQuery` | Refiner | Crawlers | Optimized search terms |
| `RawResults` | Crawlers | Filter | .onion URLs from search engines |
| `FilteredResults` | Filter | Scrapers | Relevant URLs only |
| `ScrapedContent` | Scrapers | Extractor, Analyst | Page content |
| `ExtractedArtifacts` | Extractor | Enricher, Analyst | IOCs (IPs, emails, hashes) |
| `EnrichedArtifacts` | Enricher | Analyst | Surface web context |
| `Summary` | Analyst | CLI | Final intelligence report |

The magic: **agents don't know about each other**. The Crawler doesn't call the Filter. It just emits `RawResults` signals. The Filter happens to be listening for those.

## Key Discovery #1: Fault Tolerance for Free

With the pipeline approach, if one Tor request times out, you need retry logic, circuit breakers, and error handling spaghetti.

With SMESH? Signals just decay. Other crawlers pick up the slack. If `crawler-1` fails to emit results for a query, `crawler-2` and `crawler-3` might succeed. The Field doesn't care who produces the signal — it just propagates whatever arrives.

```rust
// No error handling needed at the orchestration level
// Agents fail silently, signals decay, life goes on
for agent in &mut self.agents {
    let _ = agent.process(&mut self.field).await;
}
self.field.tick(); // Advance time, decay signals
```

## Key Discovery #2: Multi-Agent Consensus

When multiple crawlers find the same URL, the signal gets *reinforced*:

```rust
pub fn reinforce(&mut self, signal_hash: &str, boost: f64) {
    if let Some(signal) = self.signals.get_mut(signal_hash) {
        signal.confidence = (signal.confidence + boost).min(1.0);
    }
}
```

This is huge for filtering noise. URLs that appear in multiple search engines naturally bubble up. Duplicate artifacts get higher confidence scores. **Agreement = signal strength**.

## Key Discovery #3: Specialists Emerge from Personas

I defined agent behaviors in TOML files:

```toml
# prompts/analyst_threat_intel.toml
[persona]
name = "Threat Intelligence Analyst"
role = "specialist"

[persona.expertise]
primary = "Threat actor TTPs and campaign analysis"
domains = [
    "APT group identification",
    "Malware family classification",
    "Attack pattern recognition",
]
```

Now I can run 6 specialist analysts in parallel, each sensing the same signals but interpreting through different lenses:

- 🎯 Threat Intel — Actor TTPs, campaigns
- 💰 Financial Crime — Crypto flows, money laundering  
- 🔐 Technical — Malware, exploits
- 🌍 Geopolitical — Nation-state attribution
- ⚖️ Legal — Evidence handling, jurisdiction
- 🔮 Strategic — Trend forecasting

A lead analyst then synthesizes their reports. **Emergent multi-perspective analysis**.

## Key Discovery #4: Bridging Dark ↔ Surface Web

The `EnrichmentAgent` was a late addition that proved surprisingly powerful:

```rust
// When we extract an email from a dark web forum...
let artifact = Artifact { 
    artifact_type: ArtifactType::Email,
    value: "h4ck3r@protonmail.com".into(),
};

// ...query GitHub for commits with that email
let github_results = self.search_github(&artifact).await;

// ...and Brave Search for breach mentions
let brave_results = self.search_brave(&artifact).await;
```

Dark web pseudonyms often leak into legitimate platforms. GitHub commits, forum posts, domain registrations. The enricher finds these connections automatically.

## The Architecture

```
robin-smesh/
├── robin-core/      # Signals, artifacts, field mechanics
├── robin-tor/       # Tor proxy, crawlers, scrapers
├── robin-agents/    # Specialized OSINT agents
│   ├── refiner.rs   # Query optimization
│   ├── crawler.rs   # .onion search engines
│   ├── filter.rs    # LLM-based relevance filtering
│   ├── scraper.rs   # Content extraction
│   ├── extractor.rs # IOC/artifact identification
│   ├── enricher.rs  # Surface web correlation
│   └── analyst.rs   # Intelligence synthesis
├── robin-runtime/   # SMESH swarm coordinator
└── robin-cli/       # User interface
```

## Results: Before vs After

| Metric | Python Robin | Robin×SMESH |
|--------|--------------|-------------|
| Fault tolerance | Manual retries | Automatic via decay |
| Parallelism | ThreadPool | N independent agents |
| Analysis depth | Single LLM call | 6 specialists + synthesis |
| Extensibility | Modify pipeline | Add new agent type |
| Dark↔Surface bridge | None | GitHub + Brave enrichment |

## Try It Yourself

```bash
# Clone and build
git clone https://github.com/copyleftdev/robin-smesh
cd robin-smesh
cargo build --release

# Run with multi-specialist analysis + enrichment
ANTHROPIC_API_KEY=sk-ant-... ./target/release/robin-smesh query \
  -q "ransomware bitcoin wallets" \
  --specialists \
  --enrich \
  --timeout 300
```

## What I Learned

1. **Bio-inspired != bio-realistic** — I'm not actually simulating plant hormones. I'm borrowing the *abstraction* of signal-mediated coordination.

2. **Emergence requires constraints** — Agents need clear sensing thresholds and signal types. Too much freedom = chaos.

3. **Decay is a feature** — Letting signals die naturally is more elegant than explicit garbage collection.

4. **LLMs are better as specialists** — Instead of one god-model orchestrating everything, use focused experts that emit structured signals.

5. **The dark web is surprisingly chatty** — Threat actors reuse emails, leak usernames, and leave breadcrumbs across platforms. Automated enrichment catches what manual analysis misses.

## What's Next

- **More enrichment sources** — Shodan, VirusTotal, Have I Been Pwned
- **Signal visualization** — Real-time field state dashboard
- **Agent breeding** — Spawn more of whichever agent type is most productive
- **Cross-investigation memory** — Signals that persist across runs

---

The code is MIT/Apache-2.0 licensed at [github.com/copyleftdev/robin-smesh](https://github.com/copyleftdev/robin-smesh).

If you've experimented with swarm intelligence or bio-inspired AI, I'd love to hear about it. Drop a comment or find me on GitHub.

*Happy hunting.* 🕸️
