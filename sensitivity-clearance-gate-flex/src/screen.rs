// Copyright 2026 Salesforce, Inc. All rights reserved.
//! The sensitivity-vs-clearance decision. Everything here runs in Rust (no model):
//! the judge only returns a *probability distribution over sensitivity levels* plus
//! a personal-data probability; this module turns that distribution into a decision
//! by comparing it to the caller's clearance. The key quantity is **`p_exceeds`** —
//! the probability MASS the content sits *above* the caller's clearance — not an
//! interpolated sensitivity score (a score question is only weakly calibrated as a
//! number; the mass above a cut point is the honest reading).

use crate::common::{Bands, Decision};

/// Probability at or above which the judge's `has_personal_data` answer is treated
/// as "this content contains personal data" for the `personalDataMinClearance` rule.
pub const PERSONAL_DATA_YES: f64 = 0.8;

/// The judge signals for one classified response.
#[derive(Clone, Debug, Default)]
pub struct Signals {
    /// Probability mass per sensitivity level, index-aligned to the configured
    /// `levels` (least → most sensitive). Ideally sums to ~1; we never require it to.
    pub probabilities: Vec<f64>,
    /// noul p(true): the content contains personal data.
    pub has_personal_data: f64,
}

/// Index of the highest-probability level — used only for the `x-jev-sensitivity`
/// flag header (a label), never for the block/flag decision.
pub fn argmax_level(probs: &[f64]) -> usize {
    let mut best = 0usize;
    let mut best_p = f64::NEG_INFINITY;
    for (i, &p) in probs.iter().enumerate() {
        if p > best_p {
            best_p = p;
            best = i;
        }
    }
    best
}

/// Probability mass on levels STRICTLY above the caller's clearance ordinal — the
/// chance the content is more sensitive than the caller is cleared for. A caller
/// cleared to the top level always gets 0 (nothing is above them).
pub fn p_exceeds(probs: &[f64], clearance_ordinal: usize) -> f64 {
    probs
        .iter()
        .enumerate()
        .filter(|(i, _)| *i > clearance_ordinal)
        .map(|(_, p)| *p)
        .sum::<f64>()
        .clamp(0.0, 1.0)
}

/// Inputs to the decision (all ordinals index into the configured `levels`).
#[derive(Clone, Copy, Debug)]
pub struct DecideInput<'a> {
    /// Mass above the caller's clearance (from `p_exceeds`).
    pub p_exceeds: f64,
    /// Judge `has_personal_data` probability.
    pub has_personal_data: f64,
    /// Caller's clearance ordinal.
    pub clearance_ordinal: usize,
    /// Minimum clearance ordinal to see personal data (`personalDataMinClearance`).
    pub personal_data_min_ordinal: usize,
    /// Optional per-route floor ordinal (`routeFloor`) — a route known to serve data
    /// at least this sensitive, enforced without the judge.
    pub route_floor_ordinal: Option<usize>,
    /// flag/block bands applied to `p_exceeds`.
    pub bands: &'a Bands,
}

/// The rule that fired, for the decision log and the error body.
pub fn reason_str(reason: Reason) -> &'static str {
    match reason {
        Reason::RouteFloor => "route_floor",
        Reason::PersonalData => "personal_data_above_clearance",
        Reason::MassExceeds => "sensitivity_exceeds_clearance",
        Reason::MassNear => "sensitivity_near_clearance",
        Reason::Within => "within_clearance",
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    RouteFloor,
    PersonalData,
    MassExceeds,
    MassNear,
    Within,
}

/// Combine the deterministic rules and the mass-above-clearance bands into a
/// decision. Order matters: the two hard rules (route floor, personal data) win
/// over the probabilistic bands, and a block from either is not softened to a flag.
pub fn decide(input: &DecideInput) -> (Decision, Reason) {
    // 1. Route floor — the route serves data at least this sensitive; a caller below
    //    the floor cannot see it regardless of how this particular body classifies.
    if let Some(floor) = input.route_floor_ordinal {
        if input.clearance_ordinal < floor {
            return (Decision::Block, Reason::RouteFloor);
        }
    }
    // 2. Personal-data rule — clear personal data plus a caller below the minimum
    //    clearance for personal data is a block on its own.
    if input.has_personal_data >= PERSONAL_DATA_YES && input.clearance_ordinal < input.personal_data_min_ordinal {
        return (Decision::Block, Reason::PersonalData);
    }
    // 3. Probability mass above the caller's clearance, against the bands.
    match input.bands.classify(input.p_exceeds) {
        Decision::Block => (Decision::Block, Reason::MassExceeds),
        Decision::Flag => (Decision::Flag, Reason::MassNear),
        Decision::Allow => (Decision::Allow, Reason::Within),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // levels = [public(0), internal(1), confidential(2), restricted(3)]
    fn bands() -> Bands {
        Bands::new(0.3, 0.6)
    }

    #[test]
    fn mass_above_clearance_sums_the_right_tail() {
        // A doc the judge thinks is 70% restricted, 20% confidential, rest low.
        let probs = vec![0.02, 0.08, 0.20, 0.70];
        // An `internal` (ordinal 1) caller: mass above = confidential + restricted = 0.90.
        assert!((p_exceeds(&probs, 1) - 0.90).abs() < 1e-9);
        // A `confidential` (ordinal 2) caller: mass above = restricted = 0.70.
        assert!((p_exceeds(&probs, 2) - 0.70).abs() < 1e-9);
        // A `restricted` (ordinal 3, top) caller: nothing above = 0.0.
        assert_eq!(p_exceeds(&probs, 3), 0.0);
    }

    #[test]
    fn argmax_picks_the_dominant_level() {
        assert_eq!(argmax_level(&[0.7, 0.1, 0.1, 0.1]), 0);
        assert_eq!(argmax_level(&[0.02, 0.08, 0.20, 0.70]), 3);
    }

    #[test]
    fn restricted_pii_blocks_internal_caller_allows_restricted_caller() {
        let probs = vec![0.02, 0.08, 0.20, 0.70];
        let b = bands();
        // internal caller — mass above clearance (0.90) >= blockAt.
        let (d, r) = decide(&DecideInput {
            p_exceeds: p_exceeds(&probs, 1),
            has_personal_data: 0.95,
            clearance_ordinal: 1,
            personal_data_min_ordinal: 2,
            route_floor_ordinal: None,
            bands: &b,
        });
        assert_eq!(d, Decision::Block);
        // personal-data rule fires first here (both would block); either way it's a block.
        assert!(r == Reason::PersonalData || r == Reason::MassExceeds);
        // restricted caller — nothing above, no personal-data shortfall.
        let (d2, r2) = decide(&DecideInput {
            p_exceeds: p_exceeds(&probs, 3),
            has_personal_data: 0.95,
            clearance_ordinal: 3,
            personal_data_min_ordinal: 2,
            route_floor_ordinal: None,
            bands: &b,
        });
        assert_eq!(d2, Decision::Allow);
        assert_eq!(r2, Reason::Within);
    }

    #[test]
    fn public_blurb_allows_internal_caller() {
        // 80% public, small tail.
        let probs = vec![0.80, 0.13, 0.04, 0.03];
        let b = bands();
        let (d, r) = decide(&DecideInput {
            p_exceeds: p_exceeds(&probs, 1), // 0.07
            has_personal_data: 0.02,
            clearance_ordinal: 1,
            personal_data_min_ordinal: 2,
            route_floor_ordinal: None,
            bands: &b,
        });
        assert_eq!(d, Decision::Allow);
        assert_eq!(r, Reason::Within);
    }

    #[test]
    fn near_band_flags() {
        // Mass above clearance lands between flagAt(0.3) and blockAt(0.6).
        let probs = vec![0.2, 0.35, 0.30, 0.15]; // above internal(1) = 0.45
        let b = bands();
        let (d, r) = decide(&DecideInput {
            p_exceeds: p_exceeds(&probs, 1),
            has_personal_data: 0.1,
            clearance_ordinal: 1,
            personal_data_min_ordinal: 2,
            route_floor_ordinal: None,
            bands: &b,
        });
        assert_eq!(d, Decision::Flag);
        assert_eq!(r, Reason::MassNear);
    }

    #[test]
    fn route_floor_blocks_below_floor_without_the_judge() {
        let b = bands();
        // Route floor = confidential(2); caller is internal(1). Body classification is
        // irrelevant (all-public here) — the floor blocks.
        let (d, r) = decide(&DecideInput {
            p_exceeds: 0.0,
            has_personal_data: 0.0,
            clearance_ordinal: 1,
            personal_data_min_ordinal: 2,
            route_floor_ordinal: Some(2),
            bands: &b,
        });
        assert_eq!(d, Decision::Block);
        assert_eq!(r, Reason::RouteFloor);
        // Same route, a confidential(2) caller clears the floor.
        let (d2, _) = decide(&DecideInput {
            p_exceeds: 0.0,
            has_personal_data: 0.0,
            clearance_ordinal: 2,
            personal_data_min_ordinal: 2,
            route_floor_ordinal: Some(2),
            bands: &b,
        });
        assert_eq!(d2, Decision::Allow);
    }

    #[test]
    fn personal_data_rule_needs_both_high_prob_and_low_clearance() {
        let b = bands();
        // High personal-data prob but caller already at the min clearance → no PII block.
        let (d, _) = decide(&DecideInput {
            p_exceeds: 0.0,
            has_personal_data: 0.95,
            clearance_ordinal: 2,
            personal_data_min_ordinal: 2,
            route_floor_ordinal: None,
            bands: &b,
        });
        assert_eq!(d, Decision::Allow);
        // Below min clearance but personal-data prob under threshold → no PII block.
        let (d2, _) = decide(&DecideInput {
            p_exceeds: 0.0,
            has_personal_data: 0.5,
            clearance_ordinal: 0,
            personal_data_min_ordinal: 2,
            route_floor_ordinal: None,
            bands: &b,
        });
        assert_eq!(d2, Decision::Allow);
    }
}
