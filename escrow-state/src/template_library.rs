//! Escrow template library (AV-143 — Solana): a named, versioned,
//! reusable registry of escrow blueprints.
//!
//! Relationship to AV-72: [`EscrowTemplate`](crate::EscrowTemplate) is
//! a client-side *composition helper* — a one-shot validated builder
//! for the four canonical escrow shapes. It is not named, not stored,
//! and not versioned. This module is the *library* on top of it: a
//! persistent registry where a blueprint packs amount, mint,
//! milestone plan, arbiter, fee tier ladder, and vesting curve under a
//! name; every publish mints a new immutable version; and
//! [`TemplateLibrary::from_template`] instantiates one call into a
//! fully-configured [`Escrow`] while bumping the version's use count.
//! Nothing here changes the vault account layout or the Anchor
//! program — like AV-72, the chain only ever sees the composed escrow.
//!
//! Audit: every blueprint records its creator, creation time, version,
//! and use count, so operators can see which template versions are
//! actually originating escrows.
//!
//! Off-chain by design: versioning and usage accounting are keeper/
//! operator state, exactly like the other off-chain registries in this
//! crate.

use std::collections::HashMap;

use crate::{
    Escrow, EscrowError, EscrowTemplate, KindParams, QuorumPolicy, TemplateError, TemplateKind,
    VestingCurve, VestingSchedule,
};

/// The release plan a blueprint packs, in owned form (the AV-72
/// [`KindParams`](crate::KindParams) is borrowed — the library owns
/// its blueprints).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlueprintPlan {
    /// Simple two-party escrow with an optional timelock.
    Auction {
        /// Expiry grace period in seconds (AV-21), `0` for none.
        grace_period_secs: u64,
    },
    /// Deliverable-gated milestone tranches (AV-15), in release order.
    MilestonePlan {
        tranches: Vec<u64>,
    },
    /// Clock-driven periodic payouts (AV-56).
    Subscription {
        period_secs: u64,
        periods: u8,
        per_period: u64,
    },
    /// Dispute-arbitrated escrow (AV-14).
    ArbitratedDispute {
        arbiter: [u8; 32],
        evidence_deadline_secs: Option<u64>,
    },
}

impl BlueprintPlan {
    fn kind(&self) -> TemplateKind {
        match self {
            BlueprintPlan::Auction { .. } => TemplateKind::Auction,
            BlueprintPlan::MilestonePlan { .. } => TemplateKind::MilestonePlan,
            BlueprintPlan::Subscription { .. } => TemplateKind::Subscription,
            BlueprintPlan::ArbitratedDispute { .. } => TemplateKind::ArbitratedDispute,
        }
    }

    fn kind_params(&self) -> KindParams<'_> {
        match self {
            BlueprintPlan::Auction { grace_period_secs } => KindParams::Auction {
                grace_period_secs: *grace_period_secs,
            },
            BlueprintPlan::MilestonePlan { tranches } => KindParams::MilestonePlan { tranches },
            BlueprintPlan::Subscription {
                period_secs,
                periods,
                per_period,
            } => KindParams::Subscription {
                period_secs: *period_secs,
                periods: *periods,
                per_period: *per_period,
            },
            BlueprintPlan::ArbitratedDispute {
                arbiter,
                evidence_deadline_secs,
            } => KindParams::ArbitratedDispute {
                arbiter: *arbiter,
                evidence_deadline_secs: *evidence_deadline_secs,
            },
        }
    }
}

/// One immutable version of a named escrow template.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EscrowBlueprint {
    /// Registry name, e.g. `"freelance-milestone-v1"`. Versions share
    /// the name; [`TemplateLibrary::publish`] assigns
    /// [`EscrowBlueprint::version`].
    pub name: String,
    /// 1-based version assigned at publish time. Immutable after.
    pub version: u32,
    /// The release plan.
    pub plan: BlueprintPlan,
    /// The locked amount in base units.
    pub amount: u64,
    /// Expiry is relative: `from_template` sets
    /// `expires_at = now + expires_in_secs`.
    pub expires_in_secs: u64,
    /// Optional SPL token mint binding (AV-16).
    pub mint: Option<[u8; 32]>,
    /// Absolute timelock (AV-27), mutually exclusive with
    /// `relative_timelock_secs`.
    pub timelock: Option<u64>,
    /// Relative timelock (AV-64), mutually exclusive with `timelock`.
    pub relative_timelock_secs: Option<u64>,
    /// Dual-signature activation (AV-12).
    pub dual_sig: bool,
    /// Optional weighted attestor quorum gating `release`.
    pub quorum: Option<QuorumPolicy>,
    /// Opt-in protocol-fee tier ladder (AV-66), as
    /// `(min_amount, bps)` pairs applied via
    /// [`Escrow::with_fee_schedule`]. Empty means the flat default.
    pub fee_tiers: Vec<(u64, u16)>,
    /// Opt-in vesting schedule + unlock curve (AV-13 / AV-90).
    pub vesting: Option<(VestingSchedule, VestingCurve)>,
    // --- audit (assigned / maintained by the library) ---
    /// Who published this version.
    pub creator: [u8; 32],
    /// Unix timestamp of publication.
    pub created_at: u64,
    /// How many escrows were instantiated from this version.
    pub use_count: u64,
    /// Last instantiation time, `None` when never used.
    pub last_used_at: Option<u64>,
}

/// What the library can reject.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LibraryError {
    /// No template published under this name.
    UnknownTemplate,
    /// The name exists but has no such version.
    UnknownVersion(u32),
    /// The blueprint fails AV-72 combination validation (or its fee
    /// tiers / vesting fail builder validation at publish time).
    InvalidBlueprint(TemplateError),
    /// The blueprint validated at publish but a builder rejected the
    /// instantiation anyway (defensive — unreachable for a published
    /// blueprint with honest inputs).
    InstantiationFailed(EscrowError),
}

/// Named, versioned registry of escrow blueprints (AV-143).
#[derive(Debug, Clone, Default)]
pub struct TemplateLibrary {
    /// Name → versions in publish order (`versions[i].version ==
    /// i + 1`).
    templates: HashMap<String, Vec<EscrowBlueprint>>,
}

impl TemplateLibrary {
    /// Empty library.
    pub fn new() -> Self {
        Self::default()
    }

    /// Publish a blueprint: validate it by instantiating a probe
    /// escrow (dummy parties — the validation is shape-based), then
    /// store it as the next immutable version under `blueprint.name`.
    /// Returns the assigned version. Rejects
    /// [`LibraryError::InvalidBlueprint`] when the configuration is
    /// not buildable, so the library can never hold a template that
    /// `from_template` would fail to instantiate.
    pub fn publish(
        &mut self,
        mut blueprint: EscrowBlueprint,
        creator: [u8; 32],
        at: u64,
    ) -> Result<u32, LibraryError> {
        Self::instantiate(&blueprint, [0x01; 32], [0x02; 32], at)
            .map_err(LibraryError::InvalidBlueprint)?;
        let entry = self.templates.entry(blueprint.name.clone()).or_default();
        let version = entry.len() as u32 + 1;
        blueprint.version = version;
        blueprint.creator = creator;
        blueprint.created_at = at;
        blueprint.use_count = 0;
        blueprint.last_used_at = None;
        entry.push(blueprint);
        Ok(version)
    }

    /// Look up one version (1-based). `None` for an unknown name or
    /// version.
    pub fn get(&self, name: &str, version: u32) -> Option<&EscrowBlueprint> {
        self.templates
            .get(name)?
            .iter()
            .find(|b| b.version == version)
    }

    /// The newest version of a template, or `None` when unknown.
    pub fn latest(&self, name: &str) -> Option<&EscrowBlueprint> {
        self.templates.get(name)?.last()
    }

    /// How many versions exist under `name`.
    pub fn version_count(&self, name: &str) -> usize {
        self.templates.get(name).map_or(0, Vec::len)
    }

    /// Every registered template name.
    pub fn names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.templates.keys().map(String::as_str).collect();
        names.sort_unstable();
        names
    }

    /// Instantiate a template into a fully-configured escrow in one
    /// call: build the AV-72 composition from the blueprint, apply the
    /// fee tier ladder and vesting curve, and bump the version's use
    /// count. `version == None` takes the latest version. The
    /// instantiated escrow locks the blueprint's version — a later
    /// publish under the same name does not change already-created
    /// escrows.
    pub fn from_template(
        &mut self,
        name: &str,
        version: Option<u32>,
        initializer: [u8; 32],
        taker: [u8; 32],
        now: u64,
    ) -> Result<Escrow, LibraryError> {
        let (version, escrow) = {
            let entry = self.templates.get(name).ok_or(LibraryError::UnknownTemplate)?;
            let bp = match version {
                Some(v) => entry
                    .iter()
                    .find(|b| b.version == v)
                    .ok_or(LibraryError::UnknownVersion(v))?,
                None => entry.last().ok_or(LibraryError::UnknownTemplate)?,
            };
            (
                bp.version,
                Self::instantiate(bp, initializer, taker, now)
                    .map_err(|e| LibraryError::InstantiationFailed(template_error_to_escrow(e)))?,
            )
        };
        let bp = self
            .templates
            .get_mut(name)
            .and_then(|e| e.iter_mut().find(|b| b.version == version))
            .expect("version resolved above");
        bp.use_count += 1;
        bp.last_used_at = Some(now);
        Ok(escrow)
    }

    /// Build the escrow a blueprint describes. The AV-72 template
    /// validates the *combination* (timelock conflicts, tranche sums,
    /// cadences); the fee ladder and vesting apply on top through the
    /// state machine's own builders, so a blueprint can only produce
    /// configurations the vault understands. Builder rejections after
    /// template validation surface as
    /// [`TemplateError::InvalidConfiguration`] — the variant's
    /// documented purpose.
    fn instantiate(
        bp: &EscrowBlueprint,
        initializer: [u8; 32],
        taker: [u8; 32],
        now: u64,
    ) -> Result<Escrow, TemplateError> {
        let template = EscrowTemplate {
            kind: bp.plan.kind(),
            initializer,
            taker,
            amount: bp.amount,
            expires_at: now.saturating_add(bp.expires_in_secs),
            dual_sig: bp.dual_sig,
            timelock: bp.timelock,
            relative_timelock_secs: bp.relative_timelock_secs,
            quorum: bp.quorum,
            mint: bp.mint,
            kind_params: bp.plan.kind_params(),
        };
        let mut escrow = template.build()?;
        if !bp.fee_tiers.is_empty() {
            escrow = escrow
                .with_fee_schedule(&bp.fee_tiers)
                .map_err(TemplateError::InvalidConfiguration)?;
        }
        if let Some((schedule, curve)) = bp.vesting {
            escrow = escrow
                .with_vesting_curve(schedule, curve)
                .map_err(TemplateError::InvalidConfiguration)?;
        }
        Ok(escrow)
    }
}

/// Project a [`TemplateError`] onto the program error surface for the
/// defensive [`LibraryError::InstantiationFailed`] path (same mapping
/// AV-72's `map_template_error` uses for its program-facing errors).
fn template_error_to_escrow(e: TemplateError) -> EscrowError {
    match e {
        TemplateError::InvalidConfiguration(inner) => inner,
        TemplateError::ZeroAmount => EscrowError::AmountMismatch,
        TemplateError::ConflictingTimelocks | TemplateError::TimelockPastExpiry => {
            EscrowError::InvalidTimelock
        }
        TemplateError::EmptyTranches | TemplateError::TrancheSumMismatch => {
            EscrowError::InvalidMilestones
        }
        TemplateError::InvalidSubscriptionParams => EscrowError::InvalidSubscription,
        TemplateError::MissingArbiter => EscrowError::InvalidArbiter,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(i: u8) -> [u8; 32] {
        [i; 32]
    }

    fn milestone_blueprint(name: &str) -> EscrowBlueprint {
        EscrowBlueprint {
            name: name.to_string(),
            version: 0, // assigned by publish
            plan: BlueprintPlan::MilestonePlan {
                tranches: vec![400, 600],
            },
            amount: 1_000,
            expires_in_secs: 86_400,
            mint: None,
            timelock: None,
            relative_timelock_secs: None,
            dual_sig: false,
            quorum: None,
            fee_tiers: vec![(0, 100), (10_000, 25)],
            vesting: None,
            creator: [0; 32],
            created_at: 0,
            use_count: 0,
            last_used_at: None,
        }
    }

    #[test]
    fn publish_assigns_versions_and_validates() {
        let mut lib = TemplateLibrary::new();
        assert_eq!(lib.publish(milestone_blueprint("gig"), key(1), 1_000), Ok(1));
        assert_eq!(lib.publish(milestone_blueprint("gig"), key(1), 2_000), Ok(2));
        assert_eq!(lib.version_count("gig"), 2);
        let v1 = lib.get("gig", 1).unwrap();
        assert_eq!(v1.creator, key(1));
        assert_eq!(v1.created_at, 1_000);
        assert_eq!(v1.use_count, 0);
        assert_eq!(v1.last_used_at, None);
        assert_eq!(lib.latest("gig").unwrap().version, 2);
        assert_eq!(lib.names(), vec!["gig"]);
    }

    #[test]
    fn publish_rejects_unbuildable_blueprint() {
        let mut lib = TemplateLibrary::new();
        // Tranches do not sum to the amount: AV-72 rejects.
        let mut bad = milestone_blueprint("bad");
        bad.plan = BlueprintPlan::MilestonePlan {
            tranches: vec![400, 500],
        };
        assert!(matches!(
            lib.publish(bad, key(1), 1_000),
            Err(LibraryError::InvalidBlueprint(
                TemplateError::TrancheSumMismatch
            ))
        ));
        assert_eq!(lib.version_count("bad"), 0);
        // Conflicting timelocks: also rejected at publish.
        let mut bad2 = milestone_blueprint("bad2");
        bad2.timelock = Some(5_000);
        bad2.relative_timelock_secs = Some(60);
        assert!(matches!(
            lib.publish(bad2, key(1), 1_000),
            Err(LibraryError::InvalidBlueprint(
                TemplateError::ConflictingTimelocks
            ))
        ));
    }

    #[test]
    fn from_template_builds_and_audits_usage() {
        let mut lib = TemplateLibrary::new();
        lib.publish(milestone_blueprint("gig"), key(1), 1_000).unwrap();
        let e = lib
            .from_template("gig", None, key(9), key(10), 5_000)
            .unwrap();
        assert_eq!(e.initializer(), key(9));
        assert_eq!(e.taker(), key(10));
        // expires_at = now + blueprint's relative expiry.
        assert_eq!(e.expires_at(), 5_000 + 86_400);
        // Fee ladder applied from the blueprint.
        assert_eq!(e.fee_schedule().bps_for(5_000), 100);
        assert_eq!(e.fee_schedule().bps_for(50_000), 25);
        let v1 = lib.get("gig", 1).unwrap();
        assert_eq!(v1.use_count, 1);
        assert_eq!(v1.last_used_at, Some(5_000));
        // Pinning a version keeps working after a new publish.
        lib.publish(milestone_blueprint("gig"), key(1), 6_000).unwrap();
        let old = lib.from_template("gig", Some(1), key(9), key(10), 7_000).unwrap();
        assert_eq!(old.expires_at(), 7_000 + 86_400);
        assert_eq!(lib.get("gig", 1).unwrap().use_count, 2);
        assert_eq!(lib.get("gig", 2).unwrap().use_count, 0);
    }

    #[test]
    fn unknown_template_and_version_errors() {
        let mut lib = TemplateLibrary::new();
        lib.publish(milestone_blueprint("gig"), key(1), 1_000).unwrap();
        assert_eq!(
            lib.from_template("nope", None, key(1), key(2), 1_000),
            Err(LibraryError::UnknownTemplate)
        );
        assert_eq!(
            lib.from_template("gig", Some(7), key(1), key(2), 1_000),
            Err(LibraryError::UnknownVersion(7))
        );
        assert!(lib.get("gig", 7).is_none());
    }

    #[test]
    fn arbitrated_blueprint_binds_arbiter() {
        let mut lib = TemplateLibrary::new();
        let mut bp = milestone_blueprint("dispute");
        bp.plan = BlueprintPlan::ArbitratedDispute {
            arbiter: key(42),
            evidence_deadline_secs: Some(3_600),
        };
        lib.publish(bp, key(1), 1_000).unwrap();
        let e = lib
            .from_template("dispute", None, key(9), key(10), 5_000)
            .unwrap();
        assert_eq!(e.arbiter(), Some(key(42)));
    }
}
