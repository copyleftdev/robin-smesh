//! Robin×SMESH Agents
//!
//! Specialized agents for dark web OSINT:
//! - **Refiner**: Optimizes search queries for dark web engines
//! - **Crawler**: Searches .onion search engines
//! - **Filter**: Ranks results by relevance
//! - **Scraper**: Extracts content from dark web sites
//! - **Extractor**: Identifies IOCs and artifacts
//! - **Enricher**: Queries external OSINT sources (GitHub, Brave)
//! - **Analyst**: Synthesizes intelligence summaries
//!
//! ## Modular Personas
//!
//! Agent behaviors are defined via TOML persona files in `prompts/`.
//! See [`persona::PersonaRegistry`] for loading and managing personas.

pub mod backend;
pub mod persona;
pub mod specialists;
pub mod refiner;
pub mod crawler;
pub mod filter;
pub mod scraper;
pub mod extractor;
pub mod enricher;
pub mod analyst;
pub mod traits;

pub use backend::*;
pub use persona::*;
pub use specialists::*;
pub use refiner::*;
pub use crawler::*;
pub use filter::*;
pub use scraper::*;
pub use extractor::*;
pub use enricher::*;
pub use analyst::*;
pub use traits::*;
