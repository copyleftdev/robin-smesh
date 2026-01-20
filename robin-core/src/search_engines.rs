//! Dark web search engine registry
//!
//! Provides a list of known dark web search engines with their URL templates.

use serde::{Deserialize, Serialize};

/// A dark web search engine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchEngine {
    /// Human-readable name
    pub name: &'static str,
    /// URL template with {query} placeholder
    pub url_template: &'static str,
    /// Whether this engine is currently active/reliable
    pub active: bool,
    /// Estimated reliability (0.0 - 1.0)
    pub reliability: f64,
}

impl SearchEngine {
    /// Build search URL for a query
    pub fn build_url(&self, query: &str) -> String {
        self.url_template.replace("{query}", &urlencoded(query))
    }
}

/// URL-encode a query string
fn urlencoded(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' | '~' => c.to_string(),
            ' ' => "+".to_string(),
            _ => format!("%{:02X}", c as u8),
        })
        .collect()
}

/// Default list of dark web search engines
pub static DEFAULT_SEARCH_ENGINES: &[SearchEngine] = &[
    SearchEngine {
        name: "Ahmia",
        url_template: "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/search/?q={query}",
        active: true,
        reliability: 0.9,
    },
    SearchEngine {
        name: "OnionLand",
        url_template: "http://3bbad7fauom4d6sgppalyqddsqbf5u5p56b5k5uk2zxsy3d6ey2jobad.onion/search?q={query}",
        active: true,
        reliability: 0.8,
    },
    SearchEngine {
        name: "Torgle",
        url_template: "http://iy3544gmoeclh5de6gez2256v6pjh4omhpqdh2wpeeppjtvqmjhkfwad.onion/torgle/?query={query}",
        active: true,
        reliability: 0.7,
    },
    SearchEngine {
        name: "Amnesia",
        url_template: "http://amnesia7u5odx5xbwtpnqk3edybgud5bmiagu75bnqx2crntw5kry7ad.onion/search?query={query}",
        active: true,
        reliability: 0.75,
    },
    SearchEngine {
        name: "Kaizer",
        url_template: "http://kaizerwfvp5gxu6cppibp7jhcqptavq3iqef66wbxenh6a2fklibdvid.onion/search?q={query}",
        active: true,
        reliability: 0.7,
    },
    SearchEngine {
        name: "Anima",
        url_template: "http://anima4ffe27xmakwnseih3ic2y7y3l6e7fucwk4oerdn4odf7k74tbid.onion/search?q={query}",
        active: true,
        reliability: 0.65,
    },
    SearchEngine {
        name: "Tornado",
        url_template: "http://tornadoxn3viscgz647shlysdy7ea5zqzwda7hierekeuokh5eh5b3qd.onion/search?q={query}",
        active: true,
        reliability: 0.7,
    },
    SearchEngine {
        name: "TorNet",
        url_template: "http://tornetupfu7gcgidt33ftnungxzyfq2pygui5qdoyss34xbgx2qruzid.onion/search?q={query}",
        active: true,
        reliability: 0.65,
    },
    SearchEngine {
        name: "Torland",
        url_template: "http://torlbmqwtudkorme6prgfpmsnile7ug2zm4u3ejpcncxuhpu4k2j4kyd.onion/index.php?a=search&q={query}",
        active: true,
        reliability: 0.6,
    },
    SearchEngine {
        name: "FindTor",
        url_template: "http://findtorroveq5wdnipkaojfpqulxnkhblymc7aramjzajcvpptd4rjqd.onion/search?q={query}",
        active: true,
        reliability: 0.7,
    },
    SearchEngine {
        name: "Excavator",
        url_template: "http://2fd6cemt4gmccflhm6imvdfvli3nf7zn6rfrwpsy7uhxrgbypvwf5fad.onion/search?query={query}",
        active: true,
        reliability: 0.65,
    },
    SearchEngine {
        name: "Onionway",
        url_template: "http://oniwayzz74cv2puhsgx4dpjwieww4wdphsydqvf5q7eyz4myjvyw26ad.onion/search.php?s={query}",
        active: true,
        reliability: 0.6,
    },
    SearchEngine {
        name: "Tor66",
        url_template: "http://tor66sewebgixwhcqfnp5inzp5x5uohhdy3kvtnyfxc2e5mxiuh34iid.onion/search?q={query}",
        active: true,
        reliability: 0.75,
    },
    SearchEngine {
        name: "OSS",
        url_template: "http://3fzh7yuupdfyjhwt3ugzqqof6ulbcl27ecev33knxe3u7goi3vfn2qqd.onion/oss/index.php?search={query}",
        active: true,
        reliability: 0.5,
    },
    SearchEngine {
        name: "Torgol",
        url_template: "http://torgolnpeouim56dykfob6jh5r2ps2j73enc42s2um4ufob3ny4fcdyd.onion/?q={query}",
        active: true,
        reliability: 0.6,
    },
    SearchEngine {
        name: "TheDeepSearches",
        url_template: "http://searchgf7gdtauh7bhnbyed4ivxqmuoat3nm6zfrg3ymkq6mtnpye3ad.onion/search?q={query}",
        active: true,
        reliability: 0.7,
    },
];

/// Get all active search engines
pub fn active_engines() -> impl Iterator<Item = &'static SearchEngine> {
    DEFAULT_SEARCH_ENGINES.iter().filter(|e| e.active)
}

/// Get engines sorted by reliability (highest first)
pub fn engines_by_reliability() -> Vec<&'static SearchEngine> {
    let mut engines: Vec<_> = active_engines().collect();
    engines.sort_by(|a, b| b.reliability.partial_cmp(&a.reliability).unwrap());
    engines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_url() {
        let engine = &DEFAULT_SEARCH_ENGINES[0];
        let url = engine.build_url("ransomware payments");
        assert!(url.contains("ransomware+payments"));
        assert!(url.ends_with(".onion/search/?q=ransomware+payments"));
    }

    #[test]
    fn test_active_engines() {
        let count = active_engines().count();
        assert!(count >= 10);
    }
}
