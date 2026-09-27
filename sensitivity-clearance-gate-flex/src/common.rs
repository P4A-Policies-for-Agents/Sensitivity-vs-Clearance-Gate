// Copyright 2026 Salesforce, Inc. All rights reserved.
//! `jev-policy-common` primitives (inlined for this self-contained policy repo;
//! designed to be lifted into the shared `jev-policy-common` crate when the Jev
//! policy family is built out): operating mode, failure mode, threshold bands,
//! glob matching, and a cheap content fingerprint for cache keys and decision
//! logs (never log raw screened text by default — it can contain personal data).

/// Operating mode — every Jev policy has this. Default `shadow`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Enforce,
    Shadow,
    Off,
}

impl Mode {
    pub fn parse(s: &str) -> Mode {
        match s {
            "enforce" => Mode::Enforce,
            "off" => Mode::Off,
            _ => Mode::Shadow,
        }
    }
    /// In shadow the decision is computed and logged but the response is never mutated.
    pub fn mutates(self) -> bool {
        matches!(self, Mode::Enforce)
    }
}

/// Failure mode on a judge error/timeout — every Jev policy has this. Default `open`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailMode {
    Open,
    Closed,
}

impl FailMode {
    pub fn parse(s: &str) -> FailMode {
        match s {
            "closed" => FailMode::Closed,
            _ => FailMode::Open,
        }
    }
}

/// The three-way outcome of a screen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Flag,
    Block,
}

impl Decision {
    pub fn as_str(self) -> &'static str {
        match self {
            Decision::Allow => "allow",
            Decision::Flag => "flag",
            Decision::Block => "block",
        }
    }
}

/// Threshold bands: flag at `flag_at`, block at `block_at`, with `0 <= flag_at <= block_at <= 1`.
#[derive(Clone, Copy, Debug)]
pub struct Bands {
    pub flag_at: f64,
    pub block_at: f64,
}

impl Bands {
    /// Clamp into a valid ordering so a misconfiguration can never invert the bands.
    pub fn new(flag_at: f64, block_at: f64) -> Bands {
        let flag = flag_at.clamp(0.0, 1.0);
        let block = block_at.clamp(0.0, 1.0).max(flag);
        Bands { flag_at: flag, block_at: block }
    }
    pub fn classify(&self, p: f64) -> Decision {
        if p >= self.block_at {
            Decision::Block
        } else if p >= self.flag_at {
            Decision::Flag
        } else {
            Decision::Allow
        }
    }
}

/// Minimal case-sensitive glob: supports a single trailing `*` (prefix match),
/// a single leading `*` (suffix match), and exact match. Enough for tool
/// allowlists like `internal_*` without pulling in a glob/regex crate.
pub fn glob_match(pattern: &str, value: &str) -> bool {
    match (pattern.strip_suffix('*'), pattern.strip_prefix('*')) {
        (Some(prefix), _) if !prefix.is_empty() || pattern == "*" => {
            pattern == "*" || value.starts_with(prefix)
        }
        (_, Some(suffix)) => value.ends_with(suffix),
        _ => pattern == value,
    }
}

pub fn any_glob(patterns: &[String], value: &str) -> bool {
    patterns.iter().any(|p| glob_match(p, value))
}

/// Longest-matching path-prefix on segment boundaries (for REST route allowlists).
pub fn path_prefix_match(prefixes: &[String], path: &str) -> bool {
    if prefixes.is_empty() {
        return true; // empty allowlist = screen everything
    }
    prefixes.iter().any(|p| {
        path == p
            || path.starts_with(&format!("{}/", p.trim_end_matches('/')))
            || (p.ends_with('/') && path.starts_with(p.as_str()))
    })
}

/// FNV-1a 64-bit — a cheap, dependency-free content fingerprint for cache keys and
/// decision-log correlation. Not a cryptographic hash; we never need collision
/// resistance here, only "same text → same key".
pub fn fnv1a_64(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &b in bytes {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

/// Sampling gate: deterministically decide whether a given fingerprint is in the
/// screened fraction, so retries of the same content screen consistently.
pub fn sampled_in(fingerprint: u64, sample_rate: f64) -> bool {
    if sample_rate >= 1.0 {
        return true;
    }
    if sample_rate <= 0.0 {
        return false;
    }
    ((fingerprint % 10_000) as f64) < sample_rate * 10_000.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bands_classify_and_clamp() {
        let b = Bands::new(0.5, 0.85);
        assert_eq!(b.classify(0.4), Decision::Allow);
        assert_eq!(b.classify(0.5), Decision::Flag);
        assert_eq!(b.classify(0.84), Decision::Flag);
        assert_eq!(b.classify(0.85), Decision::Block);
        // Inverted config is clamped so block_at >= flag_at.
        let inv = Bands::new(0.9, 0.2);
        assert!(inv.block_at >= inv.flag_at);
    }

    #[test]
    fn glob_matches() {
        assert!(glob_match("internal_*", "internal_fetch"));
        assert!(!glob_match("internal_*", "public_fetch"));
        assert!(glob_match("*_debug", "tool_debug"));
        assert!(glob_match("exact", "exact"));
        assert!(!glob_match("exact", "exactly"));
        assert!(glob_match("*", "anything"));
    }

    #[test]
    fn path_prefix_segment_boundaries() {
        let p = vec!["/v1/customers".to_string()];
        assert!(path_prefix_match(&p, "/v1/customers"));
        assert!(path_prefix_match(&p, "/v1/customers/42"));
        assert!(!path_prefix_match(&p, "/v1/customers-internal"));
        assert!(path_prefix_match(&[], "/anything")); // empty = all
    }

    #[test]
    fn sampling_is_deterministic() {
        let fp = fnv1a_64(b"some content");
        assert_eq!(sampled_in(fp, 1.0), true);
        assert_eq!(sampled_in(fp, 0.0), false);
        // Same fingerprint decides the same way each call.
        assert_eq!(sampled_in(fp, 0.5), sampled_in(fp, 0.5));
    }
}
