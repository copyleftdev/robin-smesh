# Robin×SMESH Agent Prompts

This directory contains modular persona definitions for OSINT agents.

## Structure

Each `.toml` file defines a specialized expert persona:

```
prompts/
├── refiner.toml          # Query refinement expert
├── filter.toml           # Result relevance expert
├── analyst_lead.toml     # Lead analyst (orchestrates sub-analysts)
├── analyst_crypto.toml   # Cryptocurrency/blockchain expert
├── analyst_forensic.toml # Digital forensics expert
├── analyst_malware.toml  # Malware analysis expert
├── analyst_threat.toml   # Threat actor intelligence expert
├── analyst_network.toml  # Network/infrastructure expert
└── analyst_osint.toml    # General OSINT tradecraft expert
```

## Adding a New Expert

1. Create a new `.toml` file in this directory
2. Define the persona fields (see schema below)
3. The agent system will automatically discover and load it

## Persona Schema

```toml
[persona]
id = "analyst_crypto"           # Unique identifier
name = "Cryptocurrency Analyst" # Display name
category = "analyst"            # Category: refiner, filter, analyst
enabled = true                  # Toggle on/off

[expertise]
domains = ["bitcoin", "ethereum", "monero", "wallets", "mixers", "exchanges"]
artifact_types = ["bitcoin_address", "ethereum_address", "monero_address"]

[prompt]
system = """
Your system prompt here...
"""

[output]
format = "markdown"             # Output format
max_tokens = 2048               # Max response length
```
