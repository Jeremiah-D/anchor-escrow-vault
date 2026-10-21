//! AV-173: application-level PDA seed-domain registry (off-chain, zero
//! dependencies).
//!
//! Solana mixes one protocol-level domain separator into every PDA
//! derivation (`"ProgramDerivedAddress"`,
//! [`PDA_DOMAIN`](super::pda::PDA_DOMAIN)) — that stops cross-*program*
//! collisions. It says nothing about collisions *within* this program:
//! a vault PDA and a config PDA are both perfectly valid PDAs, and
//! off-chain tooling that parses "the PDA for X" from a bare seed list
//! can silently confuse one for the other (a vault PDA parsed as a
//! config PDA, or vice versa).
//!
//! This module adds the application layer: every PDA this program owns
//! lives in exactly one [`SeedDomain`], the domain's canonical prefix is
//! the *first* seed of every derivation in that domain, and the prefix
//! table ([`SeedDomain::prefix`]) is the single source of truth.
//! Canonical derivation paths ([`derive_domain_address`] and the
//! `derive_*_pda` conveniences) prepend the prefix themselves, so
//! callers cannot get it wrong; [`classify_seeds`] rejects any raw seed
//! list whose first seed is not a registered prefix — unregistered
//! domains and bare ad-hoc seeds fail explicit instead of deriving a
//! lookalike address.
//!
//! Orthogonal to [`pda`](super::pda)'s protocol-level `PDA_DOMAIN`
//! (the hash domain, shared by every Solana program) and to AV-92's
//! [`validate_pda_seeds`](super::pda::validate_pda_seeds) (the seed
//! *length* limits): this is the application *purpose* domain. Seed
//! lists that fail the registry are refused with
//! [`EscrowError::InvalidVaultSeeds`] — the derivation is never
//! attempted with seeds that belong to no registered domain.

use super::pda::{find_program_address, validate_pda_seeds};
use super::EscrowError;

/// The application purpose a program-owned PDA serves. Each variant
/// owns a canonical seed prefix ([`SeedDomain::prefix`]); no prefix is
/// a prefix of another, so a seed list parses into at most one domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SeedDomain {
    /// Per-escrow vault PDA.
    Vault,
    /// Program-wide configuration PDA.
    Config,
    /// Program-wide state PDA.
    State,
    /// Durable-nonce / replay-protection PDA.
    Nonce,
    /// Keeper registry PDA.
    Keeper,
}

impl SeedDomain {
    /// Every registered domain, in canonical order.
    pub fn all() -> [SeedDomain; 5] {
        [
            SeedDomain::Vault,
            SeedDomain::Config,
            SeedDomain::State,
            SeedDomain::Nonce,
            SeedDomain::Keeper,
        ]
    }

    /// The canonical first-seed prefix for this domain — the single
    /// source of truth. The Anchor skeleton's `seeds = [...]`
    /// constraints align to these prefixes; nothing else in the
    /// program may invent a domain prefix.
    pub fn prefix(self) -> &'static [u8] {
        match self {
            SeedDomain::Vault => b"escrow-vault",
            SeedDomain::Config => b"escrow-config",
            SeedDomain::State => b"escrow-state",
            SeedDomain::Nonce => b"escrow-nonce",
            SeedDomain::Keeper => b"escrow-keeper",
        }
    }

    /// Look a raw first seed up in the registry. Returns `None` for
    /// unregistered prefixes and for ad-hoc seeds that predate the
    /// registry (e.g. a bare `b"vault"`).
    pub fn from_prefix(prefix: &[u8]) -> Option<SeedDomain> {
        Self::all().into_iter().find(|d| d.prefix() == prefix)
    }
}

/// Classify a raw seed list into its [`SeedDomain`]: the first seed
/// must be a registered domain prefix. Seed *length* limits are
/// checked first (AV-92); an empty list, an over-long seed, or an
/// unregistered / ad-hoc first seed is
/// [`EscrowError::InvalidVaultSeeds`].
pub fn classify_seeds(seeds: &[&[u8]]) -> Result<SeedDomain, EscrowError> {
    validate_pda_seeds(seeds)?;
    let first = seeds.first().ok_or(EscrowError::InvalidVaultSeeds)?;
    SeedDomain::from_prefix(first).ok_or(EscrowError::InvalidVaultSeeds)
}

/// The canonical derivation path for a domain: the domain prefix is
/// prepended by the function itself, so the first seed of the
/// derivation is *always* a registered prefix — by construction, not
/// by caller discipline. `seeds` are the domain-specific suffix seeds.
/// Returns `None` when the suffixed seed list is invalid (e.g. more
/// than [`MAX_PDA_SEEDS`](super::pda::MAX_PDA_SEEDS) suffix seeds) or
/// no bump qualifies.
pub fn derive_domain_address(
    domain: SeedDomain,
    seeds: &[&[u8]],
    program_id: &[u8; 32],
) -> Option<([u8; 32], u8)> {
    let mut full: Vec<&[u8]> = Vec::with_capacity(seeds.len() + 1);
    full.push(domain.prefix());
    full.extend_from_slice(seeds);
    find_program_address(&full, program_id)
}

/// The canonical vault PDA: the [`SeedDomain::Vault`] domain with the
/// vault id as the single suffix seed.
pub fn derive_vault_pda(program_id: &[u8; 32], vault_id: &[u8]) -> Option<([u8; 32], u8)> {
    derive_domain_address(SeedDomain::Vault, &[vault_id], program_id)
}

/// The canonical program-wide config PDA: the
/// [`SeedDomain::Config`] domain with no suffix seeds.
pub fn derive_config_pda(program_id: &[u8; 32]) -> Option<([u8; 32], u8)> {
    derive_domain_address(SeedDomain::Config, &[], program_id)
}

#[cfg(test)]
mod seed_domain_tests {
    use super::super::pda::{find_program_address, MAX_PDA_SEEDS, MAX_PDA_SEED_LEN};
    use super::*;

    const PROGRAM_ID: [u8; 32] = [0x11; 32];

    #[test]
    fn prefix_table_is_pinned() {
        assert_eq!(SeedDomain::Vault.prefix(), b"escrow-vault");
        assert_eq!(SeedDomain::Config.prefix(), b"escrow-config");
        assert_eq!(SeedDomain::State.prefix(), b"escrow-state");
        assert_eq!(SeedDomain::Nonce.prefix(), b"escrow-nonce");
        assert_eq!(SeedDomain::Keeper.prefix(), b"escrow-keeper");
        assert_eq!(SeedDomain::all().len(), 5);
    }

    #[test]
    fn prefixes_fit_seed_limit_and_are_pairwise_non_prefixing() {
        let prefixes: Vec<&[u8]> = SeedDomain::all().iter().map(|d| d.prefix()).collect();
        for p in &prefixes {
            // A domain prefix must itself be a legal PDA seed.
            assert!(p.len() <= MAX_PDA_SEED_LEN, "prefix too long: {:?}", p);
            assert!(!p.is_empty());
        }
        // No prefix may be a proper prefix of another: otherwise a
        // seed list could parse into two domains and the registry
        // would not separate them.
        for (i, a) in prefixes.iter().enumerate() {
            for (j, b) in prefixes.iter().enumerate() {
                if i != j {
                    assert!(
                        !b.starts_with(a),
                        "prefix {:?} is a prefix of {:?}: ambiguous domains",
                        a,
                        b
                    );
                }
            }
        }
    }

    #[test]
    fn from_prefix_roundtrips_all_domains() {
        for d in SeedDomain::all() {
            assert_eq!(SeedDomain::from_prefix(d.prefix()), Some(d));
        }
        assert_eq!(SeedDomain::from_prefix(b"escrow"), None);
        assert_eq!(SeedDomain::from_prefix(b"vault"), None);
        assert_eq!(SeedDomain::from_prefix(b""), None);
        assert_eq!(SeedDomain::from_prefix(b"escrow-vaults"), None);
    }

    #[test]
    fn classify_seeds_accepts_every_registered_domain() {
        for d in SeedDomain::all() {
            let seeds: [&[u8]; 2] = [d.prefix(), b"some-id"];
            assert_eq!(classify_seeds(&seeds), Ok(d));
        }
    }

    #[test]
    fn classify_rejects_unregistered_and_adhoc_seeds() {
        // The pre-AV-173 ad-hoc convention (a bare b"vault" first
        // seed, as the old skeleton comments showed) is now an
        // explicit rejection, not a lookalike derivation.
        assert_eq!(
            classify_seeds(&[b"vault", b"some-id"]),
            Err(EscrowError::InvalidVaultSeeds)
        );
        assert_eq!(
            classify_seeds(&[b"escrow", b"some-id"]),
            Err(EscrowError::InvalidVaultSeeds)
        );
        assert_eq!(
            classify_seeds(&[b"", b"some-id"]),
            Err(EscrowError::InvalidVaultSeeds)
        );
    }

    #[test]
    fn classify_rejects_empty_seed_list() {
        let empty: [&[u8]; 0] = [];
        assert_eq!(
            classify_seeds(&empty),
            Err(EscrowError::InvalidVaultSeeds)
        );
    }

    #[test]
    fn classify_rejects_overlong_seed_before_registry_lookup() {
        // AV-92 length limits still apply: a 33-byte first seed is
        // rejected even if it would otherwise parse.
        let long = [0xAAu8; MAX_PDA_SEED_LEN + 1];
        let seeds: [&[u8]; 2] = [&long, b"id"];
        assert_eq!(
            classify_seeds(&seeds),
            Err(EscrowError::InvalidVaultSeeds)
        );
    }

    #[test]
    fn same_suffix_in_different_domains_derives_different_addresses() {
        // The anti-confusion guarantee: identical suffix seeds under
        // different domains must never collide, so a vault PDA can
        // never be mistaken for a config PDA.
        let suffix = b"shared-id";
        let mut addrs = Vec::new();
        for d in SeedDomain::all() {
            let (addr, _) = derive_domain_address(d, &[suffix], &PROGRAM_ID)
                .expect("canonical derivation must succeed");
            addrs.push(addr);
        }
        for i in 0..addrs.len() {
            for j in (i + 1)..addrs.len() {
                assert_ne!(addrs[i], addrs[j], "domain collision");
            }
        }
    }

    #[test]
    fn canonical_path_matches_manual_prefix_prepend() {
        // derive_domain_address is exactly find_program_address with
        // the registered prefix first — the registry, not the caller,
        // owns the first seed.
        let id = b"vault-42";
        let canonical = derive_domain_address(SeedDomain::Vault, &[id], &PROGRAM_ID).unwrap();
        let manual =
            find_program_address(&[b"escrow-vault".as_slice(), id.as_slice()], &PROGRAM_ID)
                .unwrap();
        assert_eq!(canonical, manual);
    }

    #[test]
    fn conveniences_match_the_generic_path() {
        let id = b"vault-42";
        assert_eq!(
            derive_vault_pda(&PROGRAM_ID, id),
            derive_domain_address(SeedDomain::Vault, &[id], &PROGRAM_ID)
        );
        assert_eq!(
            derive_config_pda(&PROGRAM_ID),
            derive_domain_address(SeedDomain::Config, &[], &PROGRAM_ID)
        );
    }

    #[test]
    fn derivation_is_deterministic_with_canonical_bump() {
        let (a1, b1) = derive_vault_pda(&PROGRAM_ID, b"vault-7").unwrap();
        let (a2, b2) = derive_vault_pda(&PROGRAM_ID, b"vault-7").unwrap();
        assert_eq!((a1, b1), (a2, b2));
        // The bump is the canonical first-off-curve bump from 255.
        let expected_bump =
            super::super::pda::find_vault_bump(&[b"escrow-vault".as_slice(), b"vault-7".as_slice()], &PROGRAM_ID)
                .unwrap();
        assert_eq!(b1, expected_bump);
    }

    #[test]
    fn too_many_suffix_seeds_returns_none() {
        // 16 suffix seeds + the prepended prefix = 17 > MAX_PDA_SEEDS:
        // refused, never hashed.
        let one = b"x";
        let seeds: [&[u8]; MAX_PDA_SEEDS] = [&one[..]; MAX_PDA_SEEDS];
        assert_eq!(
            derive_domain_address(SeedDomain::Vault, &seeds, &PROGRAM_ID),
            None
        );
    }

    #[test]
    fn overlong_suffix_seed_returns_none() {
        let long = [0xBBu8; MAX_PDA_SEED_LEN + 1];
        assert_eq!(
            derive_domain_address(SeedDomain::Vault, &[&long], &PROGRAM_ID),
            None
        );
    }
}
