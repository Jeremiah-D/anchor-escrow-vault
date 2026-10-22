//! AV-180: SPL freeze/thaw authority custody for managed token accounts
//! (Solana / payments risk: freezing tainted funds).
//!
//! The escrow program is the freeze authority of the vaults' SPL token
//! accounts (bound at token-account initialization — the program, not a
//! user key, holds the freeze switch). [`ManagedFreezeAuthority`] is the
//! executable spec of that custody:
//!
//! - **Strict toggle**: [`freeze`](ManagedFreezeAuthority::freeze) /
//!   [`thaw`](ManagedFreezeAuthority::thaw) flip only through the bound
//!   freeze authority; freezing a frozen account (or thawing an unfrozen
//!   one) is a loud refuse, never a silent no-op (the AV-163 toggle
//!   semantics).
//! - **The settlement lock**:
//!   [`require_unfrozen`](ManagedFreezeAuthority::require_unfrozen) is
//!   the guard the program calls at the top of `release` / `cancel` /
//!   `claim` — while the token account is frozen, no settlement moves
//!   funds. This is the payments-risk tool for tainted funds: the
//!   account is immobilized in place, not drained. It is orthogonal to
//!   the AV-46 per-escrow pause (an escrow-level switch) and the AV-163
//!   program breaker (a program-wide halt) — this is a
//!   *token-account-level* freeze, the finest-grained stop in the
//!   stack.
//! - **Authority rotation with audit**:
//!   [`set_freeze_authority`](ManagedFreezeAuthority::set_freeze_authority)
//!   rotates the bound key; every freeze / thaw / rotation appends a
//!   [`FreezeAuditEntry`] to the bounded 32-entry ring (the AV-163
//!   convention — fixed-size tail, oldest evicts first).
//!
//! # What is deliberately NOT here (honesty labels)
//!
//! - **This does not CPI to the SPL Token program.** Real
//!   `FreezeAccount` / `ThawAccount` are token-program instructions the
//!   on-chain program issues *after* this custody check; this module is
//!   the off-chain executable spec both the program and the keeper
//!   tooling pin against (the same honesty contract as AV-163).
//! - **The guard is not wired into `Escrow` methods.** Per the AV-163
//!   precedent, the program consults `require_unfrozen` at the
//!   instruction boundary of release / cancel / claim; wiring it into
//!   all settlement paths is a program-deployment change, not a
//!   state-machine change — the skeleton documents the call-site rule.
//! - **One struct per managed token account.** Fleet-wide registries
//!   are program-side; this module models a single account's custody so
//!   the state machine stays small and auditable. The token account is
//!   bound once at construction — custody is never silently rebound.
//! - **Freeze is not confiscation.** A frozen account still belongs to
//!   its owner; `thaw` restores full mobility. Freezing is the
//!   investigate-then-decide tool, not the verdict.

use super::EscrowError;

/// How many freeze/thaw events the custody remembers: a bounded ring,
/// mirroring the AV-163 circuit-breaker convention (fixed-size tail,
/// oldest evicts first).
pub const MAX_FREEZE_AUDIT_ENTRIES: usize = 32;

/// The custody lifecycle events carried by [`FreezeAuditEntry`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FreezeAuthorityEventKind {
    /// The token account was frozen by the freeze authority.
    AccountFrozen,
    /// The token account was thawed by the freeze authority.
    AccountThawed,
    /// The bound freeze authority was rotated.
    FreezeAuthorityRotated,
}

/// One structured audit entry: what happened, when, who acted, and
/// the freeze authority in effect after the event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FreezeAuditEntry {
    /// Freeze, thaw, or rotation.
    pub kind: FreezeAuthorityEventKind,
    /// Unix timestamp of the event (clock sysvar on-chain).
    pub at: u64,
    /// The key that acted.
    pub actor: [u8; 32],
    /// The freeze authority bound after this event (the rotated key on
    /// rotation, the unchanged key otherwise).
    pub freeze_authority: [u8; 32],
}

/// The escrow program's SPL freeze-authority custody over one managed
/// token account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedFreezeAuthority {
    /// The managed SPL token account.
    token_account: [u8; 32],
    /// The bound freeze authority: the only key that may freeze, thaw,
    /// or rotate.
    freeze_authority: [u8; 32],
    /// Whether the token account is currently frozen.
    frozen: bool,
    /// Bounded audit ring of custody events.
    audit: [Option<FreezeAuditEntry>; MAX_FREEZE_AUDIT_ENTRIES],
    /// Number of valid entries in `audit`.
    audit_len: usize,
    /// Ring index of the oldest entry.
    audit_start: usize,
}

impl ManagedFreezeAuthority {
    /// Bind custody over a token account to a freeze authority. Both
    /// keys must be live (non-zero): a zero token account binds custody
    /// to nothing, and a zero freeze authority is unfreezable-by-anyone
    /// — both silent footguns.
    pub fn new(
        token_account: [u8; 32],
        freeze_authority: [u8; 32],
    ) -> Result<Self, EscrowError> {
        if token_account == [0u8; 32] || freeze_authority == [0u8; 32] {
            return Err(EscrowError::InvalidFreezeAuthority);
        }
        Ok(ManagedFreezeAuthority {
            token_account,
            freeze_authority,
            frozen: false,
            audit: [None; MAX_FREEZE_AUDIT_ENTRIES],
            audit_len: 0,
            audit_start: 0,
        })
    }

    /// The managed SPL token account.
    pub fn token_account(&self) -> [u8; 32] {
        self.token_account
    }

    /// The bound freeze authority.
    pub fn freeze_authority(&self) -> [u8; 32] {
        self.freeze_authority
    }

    /// Whether the token account is currently frozen.
    pub fn is_frozen(&self) -> bool {
        self.frozen
    }

    /// Freeze the token account: the SPL `FreezeAccount` instruction
    /// equivalent. Only the bound freeze authority; freezing an
    /// already-frozen account is
    /// [`EscrowError::TokenAccountAlreadyFrozen`](crate::EscrowError::TokenAccountAlreadyFrozen).
    /// Check order mirrors AV-163: authority first, then toggle state.
    pub fn freeze(&mut self, caller: [u8; 32], now: u64) -> Result<(), EscrowError> {
        if caller != self.freeze_authority {
            return Err(EscrowError::Unauthorized);
        }
        if self.frozen {
            return Err(EscrowError::TokenAccountAlreadyFrozen);
        }
        self.frozen = true;
        self.push_audit(FreezeAuditEntry {
            kind: FreezeAuthorityEventKind::AccountFrozen,
            at: now,
            actor: caller,
            freeze_authority: self.freeze_authority,
        });
        Ok(())
    }

    /// Thaw the token account: the SPL `ThawAccount` instruction
    /// equivalent. Only the bound freeze authority; thawing an
    /// unfrozen account is
    /// [`EscrowError::TokenAccountNotFrozen`](crate::EscrowError::TokenAccountNotFrozen).
    pub fn thaw(&mut self, caller: [u8; 32], now: u64) -> Result<(), EscrowError> {
        if caller != self.freeze_authority {
            return Err(EscrowError::Unauthorized);
        }
        if !self.frozen {
            return Err(EscrowError::TokenAccountNotFrozen);
        }
        self.frozen = false;
        self.push_audit(FreezeAuditEntry {
            kind: FreezeAuthorityEventKind::AccountThawed,
            at: now,
            actor: caller,
            freeze_authority: self.freeze_authority,
        });
        Ok(())
    }

    /// Rotate the bound freeze authority (the AV-180 "authority
    /// changes enter the audit" leg). Only the current freeze
    /// authority; the successor must be a live, distinct key. The
    /// rotation itself is audited with the new key in effect.
    pub fn set_freeze_authority(
        &mut self,
        caller: [u8; 32],
        new_authority: [u8; 32],
        now: u64,
    ) -> Result<(), EscrowError> {
        if caller != self.freeze_authority {
            return Err(EscrowError::Unauthorized);
        }
        if new_authority == [0u8; 32] || new_authority == self.freeze_authority {
            return Err(EscrowError::InvalidFreezeAuthority);
        }
        self.freeze_authority = new_authority;
        self.push_audit(FreezeAuditEntry {
            kind: FreezeAuthorityEventKind::FreezeAuthorityRotated,
            at: now,
            actor: caller,
            freeze_authority: new_authority,
        });
        Ok(())
    }

    /// The settlement lock: call at the top of the program's
    /// `release` / `cancel` / `claim` handlers for this token account.
    /// While frozen this returns
    /// [`EscrowError::EscrowFrozen`](crate::EscrowError::EscrowFrozen) —
    /// fail fast, before any settlement state is touched. Unfrozen
    /// accounts pass through with zero cost.
    pub fn require_unfrozen(&self) -> Result<(), EscrowError> {
        if self.frozen {
            return Err(EscrowError::EscrowFrozen);
        }
        Ok(())
    }

    /// The structured audit log, oldest first.
    pub fn audit_log(&self) -> Vec<FreezeAuditEntry> {
        let mut out = Vec::with_capacity(self.audit_len);
        for i in 0..self.audit_len {
            let idx = (self.audit_start + i) % MAX_FREEZE_AUDIT_ENTRIES;
            if let Some(e) = self.audit[idx] {
                out.push(e);
            }
        }
        out
    }

    fn push_audit(&mut self, entry: FreezeAuditEntry) {
        if self.audit_len < MAX_FREEZE_AUDIT_ENTRIES {
            let idx = (self.audit_start + self.audit_len) % MAX_FREEZE_AUDIT_ENTRIES;
            self.audit[idx] = Some(entry);
            self.audit_len += 1;
        } else {
            // Ring full: overwrite the oldest.
            self.audit[self.audit_start] = Some(entry);
            self.audit_start = (self.audit_start + 1) % MAX_FREEZE_AUDIT_ENTRIES;
        }
    }
}

#[cfg(test)]
mod freeze_authority_tests {
    use super::*;

    const TOKEN_ACCOUNT: [u8; 32] = [0x70; 32];
    const AUTHORITY: [u8; 32] = [0xA1; 32];
    const SUCCESSOR: [u8; 32] = [0xB2; 32];
    const STRANGER: [u8; 32] = [0xCC; 32];

    fn custody() -> ManagedFreezeAuthority {
        ManagedFreezeAuthority::new(TOKEN_ACCOUNT, AUTHORITY).unwrap()
    }

    #[test]
    fn new_rejects_zero_keys() {
        assert_eq!(
            ManagedFreezeAuthority::new([0u8; 32], AUTHORITY),
            Err(EscrowError::InvalidFreezeAuthority)
        );
        assert_eq!(
            ManagedFreezeAuthority::new(TOKEN_ACCOUNT, [0u8; 32]),
            Err(EscrowError::InvalidFreezeAuthority)
        );
        let c = custody();
        assert_eq!(c.token_account(), TOKEN_ACCOUNT);
        assert_eq!(c.freeze_authority(), AUTHORITY);
        assert!(!c.is_frozen());
        assert!(c.require_unfrozen().is_ok());
        assert!(c.audit_log().is_empty());
    }

    #[test]
    fn freeze_immobilizes_and_audits() {
        let mut c = custody();
        c.freeze(AUTHORITY, 1_000).unwrap();
        assert!(c.is_frozen());
        assert_eq!(c.require_unfrozen(), Err(EscrowError::EscrowFrozen));
        let log = c.audit_log();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].kind, FreezeAuthorityEventKind::AccountFrozen);
        assert_eq!(log[0].at, 1_000);
        assert_eq!(log[0].actor, AUTHORITY);
        assert_eq!(log[0].freeze_authority, AUTHORITY);
    }

    #[test]
    fn freeze_rejects_strangers_and_double_freeze() {
        let mut c = custody();
        assert_eq!(c.freeze(STRANGER, 1_000), Err(EscrowError::Unauthorized));
        assert!(!c.is_frozen());
        c.freeze(AUTHORITY, 1_000).unwrap();
        assert_eq!(
            c.freeze(AUTHORITY, 2_000),
            Err(EscrowError::TokenAccountAlreadyFrozen)
        );
        // The failed second freeze audits nothing.
        assert_eq!(c.audit_log().len(), 1);
    }

    #[test]
    fn thaw_restores_mobility_and_audits() {
        let mut c = custody();
        c.freeze(AUTHORITY, 1_000).unwrap();
        c.thaw(AUTHORITY, 2_000).unwrap();
        assert!(!c.is_frozen());
        assert!(c.require_unfrozen().is_ok());
        let log = c.audit_log();
        assert_eq!(log.len(), 2);
        assert_eq!(log[1].kind, FreezeAuthorityEventKind::AccountThawed);
        assert_eq!(log[1].at, 2_000);
        assert_eq!(log[1].actor, AUTHORITY);
    }

    #[test]
    fn thaw_rejects_strangers_and_unfrozen_accounts() {
        let mut c = custody();
        assert_eq!(c.thaw(AUTHORITY, 1_000), Err(EscrowError::TokenAccountNotFrozen));
        assert_eq!(c.thaw(STRANGER, 1_000), Err(EscrowError::Unauthorized));
        assert!(c.audit_log().is_empty());
        c.freeze(AUTHORITY, 1_000).unwrap();
        assert_eq!(c.thaw(STRANGER, 2_000), Err(EscrowError::Unauthorized));
        assert!(c.is_frozen());
    }

    #[test]
    fn freeze_authority_rotation_is_audited() {
        let mut c = custody();
        c.set_freeze_authority(AUTHORITY, SUCCESSOR, 1_000).unwrap();
        assert_eq!(c.freeze_authority(), SUCCESSOR);
        let log = c.audit_log();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].kind, FreezeAuthorityEventKind::FreezeAuthorityRotated);
        assert_eq!(log[0].actor, AUTHORITY);
        assert_eq!(log[0].freeze_authority, SUCCESSOR);
        // The old authority loses the switch immediately.
        assert_eq!(c.freeze(STRANGER, 2_000), Err(EscrowError::Unauthorized));
        assert_eq!(c.freeze(AUTHORITY, 2_000), Err(EscrowError::Unauthorized));
        c.freeze(SUCCESSOR, 2_000).unwrap();
        assert!(c.is_frozen());
    }

    #[test]
    fn rotation_rejects_strangers_and_bad_successors() {
        let mut c = custody();
        assert_eq!(
            c.set_freeze_authority(STRANGER, SUCCESSOR, 1_000),
            Err(EscrowError::Unauthorized)
        );
        assert_eq!(
            c.set_freeze_authority(AUTHORITY, [0u8; 32], 1_000),
            Err(EscrowError::InvalidFreezeAuthority)
        );
        assert_eq!(
            c.set_freeze_authority(AUTHORITY, AUTHORITY, 1_000),
            Err(EscrowError::InvalidFreezeAuthority)
        );
        assert_eq!(c.freeze_authority(), AUTHORITY);
        assert!(c.audit_log().is_empty());
    }

    #[test]
    fn rotation_while_frozen_keeps_the_lock() {
        // Rotating the authority does not thaw the account: the freeze
        // survives custody changes.
        let mut c = custody();
        c.freeze(AUTHORITY, 1_000).unwrap();
        c.set_freeze_authority(AUTHORITY, SUCCESSOR, 2_000).unwrap();
        assert!(c.is_frozen());
        assert_eq!(c.require_unfrozen(), Err(EscrowError::EscrowFrozen));
        c.thaw(SUCCESSOR, 3_000).unwrap();
        assert!(!c.is_frozen());
    }

    #[test]
    fn audit_ring_is_bounded_and_chronological() {
        let mut c = custody();
        // 40 freeze/thaw pairs > 32 slots: oldest 8 evict.
        for i in 0..40u64 {
            c.freeze(AUTHORITY, 2 * i).unwrap();
            c.thaw(AUTHORITY, 2 * i + 1).unwrap();
        }
        let log = c.audit_log();
        assert_eq!(log.len(), MAX_FREEZE_AUDIT_ENTRIES);
        for w in log.windows(2) {
            assert!(w[0].at < w[1].at);
        }
        // The surviving 32 are pairs 24..40.
        assert_eq!(log[0].at, 48);
        assert_eq!(log[31].at, 79);
        assert_eq!(log[0].kind, FreezeAuthorityEventKind::AccountFrozen);
        assert_eq!(log[31].kind, FreezeAuthorityEventKind::AccountThawed);
    }

    #[test]
    fn error_codes_are_stable() {
        assert_eq!(EscrowError::InvalidFreezeAuthority.code(), 246);
        assert_eq!(EscrowError::TokenAccountAlreadyFrozen.code(), 247);
        assert_eq!(EscrowError::TokenAccountNotFrozen.code(), 248);
        assert_eq!(EscrowError::EscrowFrozen.code(), 249);
    }
}
