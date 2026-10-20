//! AV-163: program-level emergency circuit breaker.
//!
//! [`ProgramCircuitBreaker`] is the program-wide kill switch: when
//! engaged, the program refuses every state-changing instruction except
//! `unpause_program` and `close_vault` (rent reclamation must stay
//! available — the breaker must never brick funds). It is orthogonal
//! to the AV-46 per-escrow pause: AV-46 freezes one escrow by its
//! opted-in pause authority; this freezes the whole program by an
//! independent pauser role (a security key / multisig, not any escrow's
//! initializer or taker — those are per-escrow roles and mean nothing
//! at program scope).
//!
//! # What is real here
//!
//! - **The switch**: `paused` flips only through [`ProgramCircuitBreaker::pause`]
//!   / [`unpause`], both gated on the bound pauser
//!   ([`EscrowError::InvalidPauser`](crate::EscrowError::InvalidPauser)
//!   for anyone else) and on the toggle state
//!   ([`EscrowError::ProgramAlreadyPaused`](crate::EscrowError::ProgramAlreadyPaused)
//!   / [`EscrowError::ProgramNotPaused`](crate::EscrowError::ProgramNotPaused)
//!   — the strict toggle mirrors AV-46's per-escrow semantics, and the
//!   check order is the same: authority first, then state).
//! - **The halt**: [`ProgramCircuitBreaker::require_running`] is the
//!   guard the program calls at the top of every state-changing
//!   instruction handler except `unpause_program` (and `close_vault`,
//!   the rent-reclamation exception). While engaged it returns
//!   [`EscrowError::ProgramPaused`](crate::EscrowError::ProgramPaused)
//!   (code 221) — fail fast, before any state is touched.
//! - **Structured audit**: every successful toggle appends a
//!   [`CircuitAuditEntry`] (`ProgramPaused` / `ProgramResumed` with the
//!   actor and the timestamp) to a bounded 32-entry ring — the
//!   program-level event log. Oldest entries evict first; the ring is
//!   the on-chain account's fixed-size tail.
//!
//! # What is deliberately NOT here (honesty labels)
//!
//! - **The breaker does not reach into `Escrow` methods.** Per-escrow
//!   transitions are unchanged; the program (Anchor skeleton) consults
//!   the guard at the instruction boundary. Wiring the guard into all
//!   ~150 instruction handlers is a program-deployment change, not a
//!   state-machine change — the skeleton documents the call site rule.
//! - **The pauser is bound at construction.** There is no rotation
//!   instruction in this round (the AV-47 per-escrow rotation exists;
//!   a program-level rotation is a governance action for a later item).
//! - **"Independent role" is an operator discipline.** The breaker is
//!   program-global while initializer/taker are per-escrow, so no
//!   single check can prove "not an escrow party" — the program binds
//!   a dedicated key (e.g. the security multisig) at deployment and
//!   never an escrow party key. The zero key is rejected at
//!   construction.
//! - **Off-chain only in this crate.** The on-chain account mirrors
//!   this struct (see the skeleton's `CircuitBreaker` account and the
//!   `pause_program` / `unpause_program` instructions); this module is
//!   the executable spec both sides pin against.

use super::EscrowError;

/// How many pause/resume events the breaker remembers: a bounded ring,
/// mirroring the per-escrow event-history convention (fixed-size tail,
/// oldest evicts first).
pub const MAX_CIRCUIT_AUDIT_ENTRIES: usize = 32;

/// The program-level breaker events: the pause engage and the resume.
/// These are the "熔断/恢复进事件" leg — each carries the actor and the
/// timestamp in the audit entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitBreakerEventKind {
    /// The breaker engaged: the program halted.
    ProgramPaused,
    /// The breaker released: the program resumed.
    ProgramResumed,
}

/// One structured audit entry: what happened, when, and who did it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CircuitAuditEntry {
    /// Pause or resume.
    pub kind: CircuitBreakerEventKind,
    /// Unix timestamp of the toggle (clock sysvar on-chain).
    pub at: u64,
    /// The pauser key that toggled.
    pub actor: [u8; 32],
}

/// The program-level emergency circuit breaker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramCircuitBreaker {
    /// Whether the program is currently halted.
    paused: bool,
    /// The independent pauser role: the only key that may toggle.
    pauser: [u8; 32],
    /// Bounded audit ring of toggle events.
    audit: [Option<CircuitAuditEntry>; MAX_CIRCUIT_AUDIT_ENTRIES],
    /// Number of valid entries in `audit`.
    audit_len: usize,
    /// Ring index of the oldest entry.
    audit_start: usize,
}

impl ProgramCircuitBreaker {
    /// Bind the pauser and create a running (unpaused) breaker. The
    /// zero key is rejected — an unbound breaker would be unpausable or
    /// pausable-by-nobody, both silent footguns.
    pub fn new(pauser: [u8; 32]) -> Result<Self, EscrowError> {
        if pauser == [0u8; 32] {
            return Err(EscrowError::InvalidPauser);
        }
        Ok(ProgramCircuitBreaker {
            paused: false,
            pauser,
            audit: [None; MAX_CIRCUIT_AUDIT_ENTRIES],
            audit_len: 0,
            audit_start: 0,
        })
    }

    /// Whether the program is currently halted.
    pub fn is_paused(&self) -> bool {
        self.paused
    }

    /// The bound pauser key.
    pub fn pauser(&self) -> [u8; 32] {
        self.pauser
    }

    /// Engage the breaker: the program halts. Only the bound pauser;
    /// pausing an already-paused breaker is
    /// [`EscrowError::ProgramAlreadyPaused`](crate::EscrowError::ProgramAlreadyPaused).
    /// Check order mirrors AV-46: authority first, then toggle state.
    pub fn pause(&mut self, caller: [u8; 32], now: u64) -> Result<(), EscrowError> {
        if caller != self.pauser {
            return Err(EscrowError::InvalidPauser);
        }
        if self.paused {
            return Err(EscrowError::ProgramAlreadyPaused);
        }
        self.paused = true;
        self.push_audit(CircuitAuditEntry {
            kind: CircuitBreakerEventKind::ProgramPaused,
            at: now,
            actor: caller,
        });
        Ok(())
    }

    /// Release the breaker: the program resumes. Only the bound pauser;
    /// unpausing a running breaker is
    /// [`EscrowError::ProgramNotPaused`](crate::EscrowError::ProgramNotPaused).
    pub fn unpause(&mut self, caller: [u8; 32], now: u64) -> Result<(), EscrowError> {
        if caller != self.pauser {
            return Err(EscrowError::InvalidPauser);
        }
        if !self.paused {
            return Err(EscrowError::ProgramNotPaused);
        }
        self.paused = false;
        self.push_audit(CircuitAuditEntry {
            kind: CircuitBreakerEventKind::ProgramResumed,
            at: now,
            actor: caller,
        });
        Ok(())
    }

    /// The halt guard: call at the top of every state-changing program
    /// instruction handler except `unpause_program` and `close_vault`.
    /// While the breaker is engaged this returns
    /// [`EscrowError::ProgramPaused`](crate::EscrowError::ProgramPaused)
    /// — fail fast, before any state is touched.
    pub fn require_running(&self) -> Result<(), EscrowError> {
        if self.paused {
            return Err(EscrowError::ProgramPaused);
        }
        Ok(())
    }

    /// The structured audit log, oldest first.
    pub fn audit_log(&self) -> Vec<CircuitAuditEntry> {
        let mut out = Vec::with_capacity(self.audit_len);
        for i in 0..self.audit_len {
            let idx = (self.audit_start + i) % MAX_CIRCUIT_AUDIT_ENTRIES;
            if let Some(e) = self.audit[idx] {
                out.push(e);
            }
        }
        out
    }

    fn push_audit(&mut self, entry: CircuitAuditEntry) {
        if self.audit_len < MAX_CIRCUIT_AUDIT_ENTRIES {
            let idx = (self.audit_start + self.audit_len) % MAX_CIRCUIT_AUDIT_ENTRIES;
            self.audit[idx] = Some(entry);
            self.audit_len += 1;
        } else {
            // Ring full: overwrite the oldest.
            self.audit[self.audit_start] = Some(entry);
            self.audit_start = (self.audit_start + 1) % MAX_CIRCUIT_AUDIT_ENTRIES;
        }
    }
}

#[cfg(test)]
mod circuit_breaker_tests {
    use super::*;

    const PAUSER: [u8; 32] = [0xC1; 32];
    const STRANGER: [u8; 32] = [0xCC; 32];

    #[test]
    fn new_rejects_the_zero_pauser_key() {
        assert_eq!(
            ProgramCircuitBreaker::new([0u8; 32]),
            Err(EscrowError::InvalidPauser)
        );
        let b = ProgramCircuitBreaker::new(PAUSER).unwrap();
        assert!(!b.is_paused());
        assert_eq!(b.pauser(), PAUSER);
        assert!(b.audit_log().is_empty());
    }

    #[test]
    fn pause_engages_and_audits() {
        let mut b = ProgramCircuitBreaker::new(PAUSER).unwrap();
        b.pause(PAUSER, 1_000).unwrap();
        assert!(b.is_paused());
        let log = b.audit_log();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].kind, CircuitBreakerEventKind::ProgramPaused);
        assert_eq!(log[0].at, 1_000);
        assert_eq!(log[0].actor, PAUSER);
    }

    #[test]
    fn pause_rejects_a_stranger_and_changes_nothing() {
        let mut b = ProgramCircuitBreaker::new(PAUSER).unwrap();
        assert_eq!(b.pause(STRANGER, 1_000), Err(EscrowError::InvalidPauser));
        assert!(!b.is_paused());
        assert!(b.audit_log().is_empty());
    }

    #[test]
    fn pause_twice_is_program_already_paused() {
        let mut b = ProgramCircuitBreaker::new(PAUSER).unwrap();
        b.pause(PAUSER, 1_000).unwrap();
        assert_eq!(
            b.pause(PAUSER, 2_000),
            Err(EscrowError::ProgramAlreadyPaused)
        );
        // The failed toggle audits nothing.
        assert_eq!(b.audit_log().len(), 1);
    }

    #[test]
    fn unpause_resumes_and_audits() {
        let mut b = ProgramCircuitBreaker::new(PAUSER).unwrap();
        b.pause(PAUSER, 1_000).unwrap();
        b.unpause(PAUSER, 2_000).unwrap();
        assert!(!b.is_paused());
        let log = b.audit_log();
        assert_eq!(log.len(), 2);
        assert_eq!(log[1].kind, CircuitBreakerEventKind::ProgramResumed);
        assert_eq!(log[1].at, 2_000);
        assert_eq!(log[1].actor, PAUSER);
    }

    #[test]
    fn unpause_rejects_a_stranger_and_stays_paused() {
        let mut b = ProgramCircuitBreaker::new(PAUSER).unwrap();
        b.pause(PAUSER, 1_000).unwrap();
        assert_eq!(b.unpause(STRANGER, 2_000), Err(EscrowError::InvalidPauser));
        assert!(b.is_paused());
    }

    #[test]
    fn unpause_when_running_is_program_not_paused() {
        let mut b = ProgramCircuitBreaker::new(PAUSER).unwrap();
        assert_eq!(
            b.unpause(PAUSER, 1_000),
            Err(EscrowError::ProgramNotPaused)
        );
        assert!(b.audit_log().is_empty());
    }

    #[test]
    fn require_running_is_the_halt_guard() {
        let mut b = ProgramCircuitBreaker::new(PAUSER).unwrap();
        assert!(b.require_running().is_ok());
        b.pause(PAUSER, 1_000).unwrap();
        assert_eq!(b.require_running(), Err(EscrowError::ProgramPaused));
        b.unpause(PAUSER, 2_000).unwrap();
        assert!(b.require_running().is_ok());
    }

    #[test]
    fn audit_ring_is_bounded_and_chronological() {
        let mut b = ProgramCircuitBreaker::new(PAUSER).unwrap();
        // 40 toggles > 32 slots: oldest 8 evict.
        for i in 0..40u64 {
            if i % 2 == 0 {
                b.pause(PAUSER, i).unwrap();
            } else {
                b.unpause(PAUSER, i).unwrap();
            }
        }
        let log = b.audit_log();
        assert_eq!(log.len(), MAX_CIRCUIT_AUDIT_ENTRIES);
        // Chronological: timestamps strictly increase.
        for w in log.windows(2) {
            assert!(w[0].at < w[1].at);
        }
        // The surviving 32 are toggles 8..40.
        assert_eq!(log[0].at, 8);
        assert_eq!(log[31].at, 39);
        assert_eq!(log[0].kind, CircuitBreakerEventKind::ProgramPaused);
        assert_eq!(log[31].kind, CircuitBreakerEventKind::ProgramResumed);
    }

    #[test]
    fn failed_toggles_audit_nothing() {
        let mut b = ProgramCircuitBreaker::new(PAUSER).unwrap();
        let _ = b.pause(STRANGER, 1);
        let _ = b.unpause(PAUSER, 2);
        let _ = b.unpause(STRANGER, 3);
        assert!(b.audit_log().is_empty());
        b.pause(PAUSER, 4).unwrap();
        let _ = b.pause(PAUSER, 5);
        let _ = b.pause(STRANGER, 6);
        assert_eq!(b.audit_log().len(), 1);
    }

    #[test]
    fn error_codes_are_stable() {
        assert_eq!(EscrowError::ProgramPaused.code(), 221);
        assert_eq!(EscrowError::ProgramAlreadyPaused.code(), 222);
        assert_eq!(EscrowError::ProgramNotPaused.code(), 223);
        assert_eq!(EscrowError::InvalidPauser.code(), 224);
    }

    #[test]
    fn breaker_is_independent_of_any_escrow() {
        // The pauser is a program-level role: the breaker never sees an
        // escrow, an initializer, or a taker — constructing one with a
        // key that happens to be some escrow's initializer is legal
        // here; keeping it distinct is the operator's deployment
        // discipline (see module docs).
        let initializer_key = [0xAA; 32];
        let b = ProgramCircuitBreaker::new(initializer_key).unwrap();
        assert_eq!(b.pauser(), initializer_key);
        assert!(b.require_running().is_ok());
    }
}
