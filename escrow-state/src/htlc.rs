//! AV-186: HTLC hash-time-locked release for cross-chain atomic swaps.
//!
//! A hashed time-lock contract (HTLC) is the cross-chain atomic-swap
//! primitive: the maker locks funds behind `SHA-256(preimage)` (the
//! *hashlock*) and a slot deadline (the *timelock*). The taker claims
//! by revealing the preimage before the deadline; the maker refunds
//! after it. The same hashlock on both chains makes the two legs
//! settle-or-refund together — atomicity without a trusted relayer.
//!
//! The two locks are checked together but are independent conditions:
//! the hashlock alone never releases (the deadline must not have
//! passed), and the timelock alone never releases to the taker (only
//! the maker can refund after expiry). Release requires *both*:
//! `sha256(preimage) == hashlock && current_slot < expiry_slot`.
//!
//! The preimage is **never stored**: [`HtlcLock`] carries only the
//! digest, and [`HtlcLock::claim`] compares `sha256(preimage)` against
//! it in memory. There is no field, log line, or serialization path
//! in this module that retains the preimage after the call returns.
//!
//! Orthogonal to:
//!
//! - [`crate::secp256k1::release_authorization_hash`] (AV-185): an EVM
//!   *signature* authorizes a release; here a hash *preimage* does.
//!   The two release conditions compose but neither implies the other
//!   — signature authorization and preimage revelation are separate
//!   unlocks.
//! - AV-137 commit-reveal (arbitration blind voting): a SHA-256 commit
//!   hides a *vote* so arbiters cannot copy each other; here the hash
//!   hides the *payment secret* that unlocks a swap leg. Same
//!   primitive ([`sha256`]), disjoint mechanisms — votes are never
//!   claimable funds, and HTLC preimages are never revealed on a
//!   judgment timeline.
//! - the SLOT_TIMELOCK tail on the escrow (pure time lock): that lock
//!   releases on slot expiry alone; HTLC is a hash + time *double*
//!   lock, where expiry switches the winner from taker to maker
//!   instead of releasing anything.
//!
//! Pure logic, zero dependencies: the Anchor program would drive this
//! from vault/account state, but the decision procedure itself needs
//! no on-chain account — so no Vault layout change and no
//! `VAULT_SPACE` bump (the layout pin tests still hold).

use crate::sha256;
use crate::EscrowError;

/// Maximum preimage length accepted by [`HtlcLock::claim`].
/// Large enough for any sane swap secret (32-byte hashes,
/// domain-separated payloads), small enough to bound the hashing
/// cost on the claiming path. A longer preimage is rejected rather
/// than hashed — fail-closed, like the rest of the state machine.
pub const MAX_HTLC_PREIMAGE_LEN: usize = 512;

/// Lifecycle of one HTLC lock. `Locked` is the only state that admits
/// transitions; `Claimed` and `Refunded` are terminal. Any transition
/// attempted from a terminal state (double-claim, double-refund,
/// claim-after-refund) is [`EscrowError::InvalidStateTransition`] —
/// funds are never double-spent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HtlcState {
    /// Funds are locked; the taker may claim (preimage + before
    /// expiry) or the maker may refund (after expiry).
    Locked,
    /// The taker revealed a valid preimage before expiry; the locked
    /// amount moved to the taker.
    Claimed,
    /// The maker refunded after expiry; the locked amount returned to
    /// the maker.
    Refunded,
}

/// One hash-time-locked release.
///
/// `Copy` and heap-free like the rest of the state machine. The
/// digest is public so off-chain indexers can watch for the matching
/// preimage on the counterparty chain; the preimage itself is never
/// a field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HtlcLock {
    /// The maker who funded the lock and may refund after expiry.
    pub maker: [u8; 32],
    /// The taker who may claim with the preimage before expiry.
    pub taker: [u8; 32],
    /// `SHA-256(preimage)` committed at lock time. `Copy`d, never
    /// reconstructed from a stored secret.
    pub hashlock: [u8; 32],
    /// The claim window closes at this slot: the taker may claim only
    /// while `current_slot < expiry_slot`; the maker may refund only
    /// at `current_slot >= expiry_slot`.
    pub expiry_slot: u64,
    /// Lamports (or base units) locked. Both exits return this amount
    /// so the caller can size the transfer exactly.
    pub amount: u64,
    /// Current lifecycle state; see [`HtlcState`].
    pub state: HtlcState,
}

impl HtlcLock {
    /// Open a new lock. Fail-closed on configuration errors:
    ///
    /// - zero maker or taker key → [`EscrowError::InvalidHtlcLock`]
    ///   (a lock with an unownable endpoint is unopenable);
    /// - zero amount → [`EscrowError::InvalidHtlcLock`] (a zero-value
    ///   lock is a no-op that still occupies chain state);
    /// - `expiry_slot <= current_slot` → [`EscrowError::InvalidHtlcLock`]
    ///   (the claim window must be non-empty — a lock that is already
    ///   expired at creation is a maker-only refund with no taker
    ///   chance, which the atomic-swap protocol forbids).
    pub fn new(
        maker: [u8; 32],
        taker: [u8; 32],
        hashlock: [u8; 32],
        expiry_slot: u64,
        amount: u64,
        current_slot: u64,
    ) -> Result<Self, EscrowError> {
        if maker == [0u8; 32] || taker == [0u8; 32] {
            return Err(EscrowError::InvalidHtlcLock);
        }
        if amount == 0 {
            return Err(EscrowError::InvalidHtlcLock);
        }
        if expiry_slot <= current_slot {
            return Err(EscrowError::InvalidHtlcLock);
        }
        Ok(Self {
            maker,
            taker,
            hashlock,
            expiry_slot,
            amount,
            state: HtlcState::Locked,
        })
    }

    /// Stateless claim check: whether `preimage` would release this
    /// lock at `current_slot` right now, without moving state. Useful
    /// for off-chain keepers simulating a claim, and for wallets
    /// testing a candidate preimage before submitting.
    pub fn can_claim(
        &self,
        preimage: &[u8],
        current_slot: u64,
    ) -> Result<u64, EscrowError> {
        self.check_claim(self.taker, preimage, current_slot)
    }

    /// Claim the locked funds by revealing the preimage.
    ///
    /// Check order is authority → state → timelock → preimage shape →
    /// hashlock, mirroring the state machine's fail-closed ordering
    /// (a stranger learns nothing about the lock's state from the
    /// error they get):
    ///
    /// 1. `caller == taker`, else [`EscrowError::Unauthorized`];
    /// 2. `state == Locked`, else
    ///    [`EscrowError::InvalidStateTransition`] (double-claim and
    ///    claim-after-refund are terminal transitions);
    /// 3. `current_slot < expiry_slot`, else
    ///    [`EscrowError::HtlcClaimExpired`] — the claim window closed;
    ///    only the maker can refund now;
    /// 4. preimage non-empty and within [`MAX_HTLC_PREIMAGE_LEN`],
    ///    else [`EscrowError::HtlcInvalidPreimage`];
    /// 5. `sha256(preimage) == hashlock`, else
    ///    [`EscrowError::HtlcHashlockMismatch`].
    ///
    /// On success the state moves to `Claimed` and the locked amount
    /// is returned for transfer sizing. The preimage is compared in
    /// memory only — it is never stored, logged, or serialized.
    pub fn claim(
        &mut self,
        caller: [u8; 32],
        preimage: &[u8],
        current_slot: u64,
    ) -> Result<u64, EscrowError> {
        let amount = self.check_claim(caller, preimage, current_slot)?;
        self.state = HtlcState::Claimed;
        Ok(amount)
    }

    fn check_claim(
        &self,
        caller: [u8; 32],
        preimage: &[u8],
        current_slot: u64,
    ) -> Result<u64, EscrowError> {
        if caller != self.taker {
            return Err(EscrowError::Unauthorized);
        }
        if self.state != HtlcState::Locked {
            return Err(EscrowError::InvalidStateTransition);
        }
        if current_slot >= self.expiry_slot {
            return Err(EscrowError::HtlcClaimExpired);
        }
        if preimage.is_empty() || preimage.len() > MAX_HTLC_PREIMAGE_LEN {
            return Err(EscrowError::HtlcInvalidPreimage);
        }
        if !verify_htlc_preimage(&self.hashlock, preimage) {
            return Err(EscrowError::HtlcHashlockMismatch);
        }
        Ok(self.amount)
    }

    /// Refund the locked funds to the maker after expiry.
    ///
    /// Check order is authority → state → timelock:
    ///
    /// 1. `caller == maker`, else [`EscrowError::Unauthorized`];
    /// 2. `state == Locked`, else
    ///    [`EscrowError::InvalidStateTransition`] (a claimed lock has
    ///    no funds left to refund);
    /// 3. `current_slot >= expiry_slot`, else
    ///    [`EscrowError::HtlcRefundNotExpired`] — the taker's claim
    ///    window is still open and the maker cannot race it.
    ///
    /// On success the state moves to `Refunded` and the locked amount
    /// is returned for transfer sizing.
    pub fn refund(
        &mut self,
        caller: [u8; 32],
        current_slot: u64,
    ) -> Result<u64, EscrowError> {
        if caller != self.maker {
            return Err(EscrowError::Unauthorized);
        }
        if self.state != HtlcState::Locked {
            return Err(EscrowError::InvalidStateTransition);
        }
        if current_slot < self.expiry_slot {
            return Err(EscrowError::HtlcRefundNotExpired);
        }
        self.state = HtlcState::Refunded;
        Ok(self.amount)
    }

    /// Revise the claim window (AV-339).
    ///
    /// The two legs of an atomic swap must coordinate their timeouts:
    /// when the counterparty chain's lock is delayed or re-locked,
    /// this leg's window has to follow, or the maker refunds while
    /// the taker can still claim (or vice versa). Before this method
    /// the only remedy was abandoning the lock and rebuilding it with
    /// a new hashlock and fresh funding.
    ///
    /// Check order is authority → state → value, mirroring
    /// [`OptionEscrow::amend_option_expiry`] (AV-299):
    ///
    /// 1. `maker` + `taker` must both match the lock, else
    ///    [`EscrowError::Unauthorized`] — moving the window rewrites
    ///    the other party's claim/refund boundary, so one side alone
    ///    cannot do it (a maker shortening the window could race the
    ///    refund; a taker lengthening it could hold funds hostage);
    /// 2. `state == Locked`, else
    ///    [`EscrowError::InvalidStateTransition`] (`Claimed` /
    ///    `Refunded` are terminal — there is no window left to move);
    /// 3. `new_expiry_slot > current_slot`, else
    ///    [`EscrowError::InvalidHtlcLock`] — the new window must be
    ///    non-empty, reusing [`HtlcLock::new`]'s threshold. The value
    ///    gate runs before the no-op check, so re-affirming an
    ///    already-lapsed window fails the gate rather than silently
    ///    succeeding (same ordering as `amend_option_expiry`).
    ///
    /// Re-affirming the current window in a live window is `Ok(())`
    /// and changes nothing. Only `expiry_slot` moves — hashlock,
    /// amount, maker, taker, and state are untouched. The new window
    /// governs the next evaluation: [`HtlcLock::claim`],
    /// [`HtlcLock::refund`], [`HtlcLock::can_claim`], and
    /// [`HtlcLock::claim_window_open`] all read the live value; an
    /// action already executed keeps the window it settled under.
    /// There is no event layer on `HtlcLock` (like `OptionEscrow`),
    /// so no event is emitted.
    pub fn amend_htlc_expiry_slot(
        &mut self,
        maker: [u8; 32],
        taker: [u8; 32],
        new_expiry_slot: u64,
        current_slot: u64,
    ) -> Result<(), EscrowError> {
        if maker != self.maker || taker != self.taker {
            return Err(EscrowError::Unauthorized);
        }
        if self.state != HtlcState::Locked {
            return Err(EscrowError::InvalidStateTransition);
        }
        if new_expiry_slot <= current_slot {
            return Err(EscrowError::InvalidHtlcLock);
        }
        if new_expiry_slot == self.expiry_slot {
            return Ok(());
        }
        self.expiry_slot = new_expiry_slot;
        Ok(())
    }

    /// Revise the hashlock (AV-343).
    ///
    /// A mis-committed digest locks the swap leg permanently: the
    /// maker hashed the wrong secret, used the wrong domain separator,
    /// or committed a digest that does not match the counterparty
    /// chain's leg, and then every correct secret fails
    /// [`HtlcLock::check_claim`]'s `sha256(preimage) == hashlock`
    /// with [`EscrowError::HtlcHashlockMismatch`]. Before this method
    /// the only remedy was abandoning the lock and rebuilding it with
    /// a new hashlock and fresh funding; the funds were otherwise
    /// stuck until `expiry_slot`, when only the maker could refund.
    ///
    /// Check order is authority → state → timelock → value, mirroring
    /// [`HtlcLock::amend_htlc_expiry_slot`] (AV-339):
    ///
    /// 1. `maker` + `taker` must both match the lock, else
    ///    [`EscrowError::Unauthorized`] — the hashlock is the taker's
    ///    claim condition, so the maker alone could swap in a digest
    ///    the taker can never satisfy (griefing), and the taker alone
    ///    could re-key the swap and break the counterparty leg's
    ///    atomicity. The taker must verify offline that
    ///    `sha256(own secret) == new_hashlock` before co-signing;
    ///    [`HtlcLock::can_claim`] can simulate the new digest;
    /// 2. `state == Locked`, else
    ///    [`EscrowError::InvalidStateTransition`] (`Claimed` /
    ///    `Refunded` are terminal — there is no digest left to fix);
    /// 3. `current_slot < expiry_slot`, else
    ///    [`EscrowError::HtlcClaimExpired`] — once the window closes
    ///    only the refund path remains, and revising the digest
    ///    cannot revive a claim. Revival needs
    ///    [`HtlcLock::amend_htlc_expiry_slot`] first (also dual-signed),
    ///    deliberately *not* reusing AV-339's "a lapsed window can be
    ///    extended" semantics for the digest itself;
    /// 4. re-affirming the current digest is `Ok(())` and changes
    ///    nothing. The timelock gate runs before the no-op check, so
    ///    re-affirming a digest in an expired window still fails with
    ///    `HtlcClaimExpired`.
    ///
    /// No non-zero gate on the new digest: it is opaque, and
    /// [`HtlcLock::new`] accepts zero / `0xFF` digests (pinned by
    /// `zero_and_all_ff_digests_are_valid_hashlocks`). Only the 32
    /// `hashlock` bytes move — maker, taker, amount, `expiry_slot`,
    /// and state are untouched. The new digest governs the next
    /// evaluation: [`HtlcLock::claim`] and [`HtlcLock::can_claim`]
    /// read the live value; an action already executed keeps the
    /// digest it settled under. There is no event layer on `HtlcLock`
    /// (like `OptionEscrow`), so no event is emitted.
    pub fn amend_htlc_hashlock(
        &mut self,
        maker: [u8; 32],
        taker: [u8; 32],
        new_hashlock: [u8; 32],
        current_slot: u64,
    ) -> Result<(), EscrowError> {
        if maker != self.maker || taker != self.taker {
            return Err(EscrowError::Unauthorized);
        }
        if self.state != HtlcState::Locked {
            return Err(EscrowError::InvalidStateTransition);
        }
        if current_slot >= self.expiry_slot {
            return Err(EscrowError::HtlcClaimExpired);
        }
        if new_hashlock == self.hashlock {
            return Ok(());
        }
        self.hashlock = new_hashlock;
        Ok(())
    }

    /// Revise the taker (AV-344).
    ///
    /// A mis-addressed taker locks the swap leg permanently: the
    /// maker filled in an old address, an associated address, or a
    /// wallet the counterparty has since rotated away from, and then
    /// every claim by the rightful party fails
    /// [`HtlcLock::check_claim`]'s `caller == taker` with
    /// [`EscrowError::Unauthorized`]. Before this method the only
    /// remedy was abandoning the lock and rebuilding it with a new
    /// hashlock and fresh funding; the funds were otherwise stuck
    /// until `expiry_slot`, when only the maker could refund.
    ///
    /// Check order is authority → state → timelock → value, mirroring
    /// [`HtlcLock::amend_htlc_hashlock`] (AV-343):
    ///
    /// 1. `maker` + current `taker` must both match the lock, else
    ///    [`EscrowError::Unauthorized`] — the taker is the claim
    ///    right itself, so the maker alone could re-point the claim
    ///    to their own address and, holding the preimage, claim
    ///    before expiry and steal the swap; the current taker alone
    ///    could transfer the claim right without the funder's
    ///    consent. The *new* taker does not co-sign, mirroring
    ///    [`Escrow::rotate_taker`] (AV-52): only the current parties
    ///    authorize;
    /// 2. `state == Locked`, else
    ///    [`EscrowError::InvalidStateTransition`] (`Claimed` /
    ///    `Refunded` are terminal — there is no claim right left to
    ///    move);
    /// 3. `current_slot < expiry_slot`, else
    ///    [`EscrowError::HtlcClaimExpired`] — once the window closes
    ///    only the refund path remains, and revising the taker
    ///    cannot revive a claim. Revival needs
    ///    [`HtlcLock::amend_htlc_expiry_slot`] first (also
    ///    dual-signed);
    /// 4. `new_taker` must be non-zero, else
    ///    [`EscrowError::InvalidHtlcLock`] — reusing
    ///    [`HtlcLock::new`]'s threshold for an unownable endpoint.
    ///    The value gate runs before the no-op check, so a zero
    ///    address fails rather than silently succeeding (a zero
    ///    address can never equal the current taker, which `new()`
    ///    already guarantees non-zero).
    ///
    /// Re-affirming the current taker is `Ok(())` and changes
    /// nothing. `new_taker == maker` is not separately gated: dual
    /// signature is both parties' consent to an early settlement in
    /// advance, and the maker claiming with the known preimage is
    /// equivalent to an agreed refund — mirroring `rotate_taker`,
    /// which has no such gate either.
    ///
    /// Only the 32 `taker` bytes move — maker, hashlock, amount,
    /// `expiry_slot`, and state are untouched. The new taker governs
    /// the next evaluation: [`HtlcLock::claim`] and
    /// [`HtlcLock::can_claim`] read the live value; the refund path
    /// reads only the maker and is unaffected; an action already
    /// executed keeps the taker it settled under. There is no event
    /// layer on `HtlcLock` (like `OptionEscrow`), so no event is
    /// emitted.
    pub fn amend_htlc_taker(
        &mut self,
        maker: [u8; 32],
        taker: [u8; 32],
        new_taker: [u8; 32],
        current_slot: u64,
    ) -> Result<(), EscrowError> {
        if maker != self.maker || taker != self.taker {
            return Err(EscrowError::Unauthorized);
        }
        if self.state != HtlcState::Locked {
            return Err(EscrowError::InvalidStateTransition);
        }
        if current_slot >= self.expiry_slot {
            return Err(EscrowError::HtlcClaimExpired);
        }
        if new_taker == [0u8; 32] {
            return Err(EscrowError::InvalidHtlcLock);
        }
        if new_taker == self.taker {
            return Ok(());
        }
        self.taker = new_taker;
        Ok(())
    }

    /// Whether the taker's claim window is still open at
    /// `current_slot` (`current_slot < expiry_slot`), independent of
    /// state — a convenience for keeper scans.
    pub fn claim_window_open(&self, current_slot: u64) -> bool {
        current_slot < self.expiry_slot
    }
}

/// Pure preimage check: `sha256(preimage) == hashlock`.
///
/// The digest comparison accumulates XOR differences instead of
/// short-circuiting, so a wrong guess reveals nothing about which
/// bytes matched. Like `secp256k1.rs`, this is cross-chain tooling,
/// not consensus — no constant-time guarantees are claimed against
/// the host's own memory access patterns; the point is that the
/// comparison itself leaks no per-byte oracle.
pub fn verify_htlc_preimage(hashlock: &[u8; 32], preimage: &[u8]) -> bool {
    let digest = sha256(preimage);
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= digest[i] ^ hashlock[i];
    }
    diff == 0
}

#[cfg(test)]
mod htlc_tests {
    use super::*;

    const MAKER: [u8; 32] = [0x11; 32];
    const TAKER: [u8; 32] = [0x22; 32];
    const STRANGER: [u8; 32] = [0x33; 32];
    const CURRENT_SLOT: u64 = 1_000;
    const EXPIRY_SLOT: u64 = 2_000;
    const AMOUNT: u64 = 500_000;

    fn preimage() -> Vec<u8> {
        b"atomic-swap-secret-42".to_vec()
    }

    fn lock() -> HtlcLock {
        let hashlock = sha256(&preimage());
        HtlcLock::new(MAKER, TAKER, hashlock, EXPIRY_SLOT, AMOUNT, CURRENT_SLOT).unwrap()
    }

    #[test]
    fn happy_path_claim_before_expiry() {
        let mut lock = lock();
        assert_eq!(lock.state, HtlcState::Locked);
        let got = lock.claim(TAKER, &preimage(), CURRENT_SLOT).unwrap();
        assert_eq!(got, AMOUNT);
        assert_eq!(lock.state, HtlcState::Claimed);
    }

    #[test]
    fn wrong_preimage_rejected_state_unchanged() {
        let mut lock = lock();
        let err = lock.claim(TAKER, b"wrong-secret", CURRENT_SLOT).unwrap_err();
        assert_eq!(err, EscrowError::HtlcHashlockMismatch);
        assert_eq!(err.code(), 253);
        // A failed claim leaves the lock claimable — the taker can try
        // again with the right secret.
        assert_eq!(lock.state, HtlcState::Locked);
        lock.claim(TAKER, &preimage(), CURRENT_SLOT).unwrap();
        assert_eq!(lock.state, HtlcState::Claimed);
    }

    #[test]
    fn maker_refund_before_expiry_rejected() {
        let mut lock = lock();
        let err = lock.refund(MAKER, CURRENT_SLOT).unwrap_err();
        assert_eq!(err, EscrowError::HtlcRefundNotExpired);
        assert_eq!(err.code(), 255);
        assert_eq!(lock.state, HtlcState::Locked);
    }

    #[test]
    fn taker_claim_after_expiry_rejected() {
        let mut lock = lock();
        let err = lock
            .claim(TAKER, &preimage(), EXPIRY_SLOT + 1)
            .unwrap_err();
        assert_eq!(err, EscrowError::HtlcClaimExpired);
        assert_eq!(err.code(), 254);
        assert_eq!(lock.state, HtlcState::Locked);
        // The maker's refund path is now open.
        let got = lock.refund(MAKER, EXPIRY_SLOT + 1).unwrap();
        assert_eq!(got, AMOUNT);
        assert_eq!(lock.state, HtlcState::Refunded);
    }

    #[test]
    fn boundary_slot_equals_expiry() {
        // Claim AT the expiry slot is already too late (the claim
        // window is `current_slot < expiry_slot`, strict).
        let mut lock = lock();
        assert_eq!(
            lock.claim(TAKER, &preimage(), EXPIRY_SLOT).unwrap_err(),
            EscrowError::HtlcClaimExpired
        );
        // Refund AT the expiry slot is allowed (maker's window is
        // `current_slot >= expiry_slot`, inclusive).
        assert_eq!(lock.refund(MAKER, EXPIRY_SLOT).unwrap(), AMOUNT);
        assert_eq!(lock.state, HtlcState::Refunded);
    }

    #[test]
    fn double_claim_is_invalid_transition() {
        let mut lock = lock();
        lock.claim(TAKER, &preimage(), CURRENT_SLOT).unwrap();
        let err = lock.claim(TAKER, &preimage(), CURRENT_SLOT).unwrap_err();
        assert_eq!(err, EscrowError::InvalidStateTransition);
        // Refund after a claim: no funds left.
        let err = lock.refund(MAKER, EXPIRY_SLOT + 1).unwrap_err();
        assert_eq!(err, EscrowError::InvalidStateTransition);
    }

    #[test]
    fn double_refund_is_invalid_transition() {
        let mut lock = lock();
        lock.refund(MAKER, EXPIRY_SLOT).unwrap();
        let err = lock.refund(MAKER, EXPIRY_SLOT).unwrap_err();
        assert_eq!(err, EscrowError::InvalidStateTransition);
        // Claim after a refund: the secret arrived too late.
        let err = lock
            .claim(TAKER, &preimage(), EXPIRY_SLOT)
            .unwrap_err();
        assert_eq!(err, EscrowError::InvalidStateTransition);
    }

    #[test]
    fn authority_checked_before_state_and_timelock() {
        let mut lock = lock();
        // Stranger claiming a locked, in-window lock: Unauthorized, not
        // a state or timelock error — outsiders learn nothing about
        // the lock.
        assert_eq!(
            lock.claim(STRANGER, &preimage(), CURRENT_SLOT).unwrap_err(),
            EscrowError::Unauthorized
        );
        assert_eq!(
            lock.refund(STRANGER, EXPIRY_SLOT).unwrap_err(),
            EscrowError::Unauthorized
        );
        // Maker attempting a claim, taker attempting a refund: both are
        // the wrong role for the exit.
        assert_eq!(
            lock.claim(MAKER, &preimage(), CURRENT_SLOT).unwrap_err(),
            EscrowError::Unauthorized
        );
        assert_eq!(
            lock.refund(TAKER, EXPIRY_SLOT).unwrap_err(),
            EscrowError::Unauthorized
        );
        // Authority outranks an expired window: a stranger after expiry
        // still gets Unauthorized, not HtlcClaimExpired.
        assert_eq!(
            lock.claim(STRANGER, &preimage(), EXPIRY_SLOT + 1).unwrap_err(),
            EscrowError::Unauthorized
        );
    }

    #[test]
    fn constructor_rejects_bad_config() {
        let hashlock = sha256(&preimage());
        // Zero maker.
        assert_eq!(
            HtlcLock::new([0u8; 32], TAKER, hashlock, EXPIRY_SLOT, AMOUNT, CURRENT_SLOT)
                .unwrap_err(),
            EscrowError::InvalidHtlcLock
        );
        // Zero taker.
        assert_eq!(
            HtlcLock::new(MAKER, [0u8; 32], hashlock, EXPIRY_SLOT, AMOUNT, CURRENT_SLOT)
                .unwrap_err(),
            EscrowError::InvalidHtlcLock
        );
        // Zero amount.
        assert_eq!(
            HtlcLock::new(MAKER, TAKER, hashlock, EXPIRY_SLOT, 0, CURRENT_SLOT).unwrap_err(),
            EscrowError::InvalidHtlcLock
        );
        // Expiry already passed / at the creation slot: the taker would
        // have no claim window.
        assert_eq!(
            HtlcLock::new(MAKER, TAKER, hashlock, CURRENT_SLOT, AMOUNT, CURRENT_SLOT)
                .unwrap_err(),
            EscrowError::InvalidHtlcLock
        );
        assert_eq!(
            HtlcLock::new(MAKER, TAKER, hashlock, CURRENT_SLOT - 1, AMOUNT, CURRENT_SLOT)
                .unwrap_err(),
            EscrowError::InvalidHtlcLock
        );
        assert_eq!(EscrowError::InvalidHtlcLock.code(), 251);
    }

    #[test]
    fn zero_and_all_ff_digests_are_valid_hashlocks() {
        // The digest is opaque: even degenerate digests are accepted at
        // lock time and only the preimage check decides. (A real
        // deployment would hash a random secret; these pins guard
        // against a misguided "non-zero digest" validation.)
        let zero = HtlcLock::new(MAKER, TAKER, [0u8; 32], EXPIRY_SLOT, AMOUNT, CURRENT_SLOT);
        assert!(zero.is_ok());
        let ff = HtlcLock::new(MAKER, TAKER, [0xFF; 32], EXPIRY_SLOT, AMOUNT, CURRENT_SLOT);
        assert!(ff.is_ok());
        // And a wrong preimage against them still fails the hashlock
        // check rather than anything else.
        let mut z = zero.unwrap();
        assert_eq!(
            z.claim(TAKER, b"anything", CURRENT_SLOT).unwrap_err(),
            EscrowError::HtlcHashlockMismatch
        );
    }

    #[test]
    fn oversized_and_empty_preimages_rejected() {
        let mut lock = lock();
        // 513 bytes: one over the bound.
        let big = vec![0xABu8; MAX_HTLC_PREIMAGE_LEN + 1];
        assert_eq!(
            lock.claim(TAKER, &big, CURRENT_SLOT).unwrap_err(),
            EscrowError::HtlcInvalidPreimage
        );
        assert_eq!(EscrowError::HtlcInvalidPreimage.code(), 252);
        // Empty preimage.
        assert_eq!(
            lock.claim(TAKER, &[], CURRENT_SLOT).unwrap_err(),
            EscrowError::HtlcInvalidPreimage
        );
        // Exactly at the bound: passes the shape check (then fails the
        // hashlock, since it is not the real secret).
        let at_bound = vec![0xABu8; MAX_HTLC_PREIMAGE_LEN];
        assert_eq!(
            lock.claim(TAKER, &at_bound, CURRENT_SLOT).unwrap_err(),
            EscrowError::HtlcHashlockMismatch
        );
    }

    #[test]
    fn verify_preimage_pure_helper() {
        let secret = preimage();
        let hashlock = sha256(&secret);
        assert!(verify_htlc_preimage(&hashlock, &secret));
        assert!(!verify_htlc_preimage(&hashlock, b"nope"));
        // A single flipped bit in the preimage flips the digest.
        let mut tampered = secret.clone();
        tampered[0] ^= 1;
        assert!(!verify_htlc_preimage(&hashlock, &tampered));
        // A single flipped bit in the digest rejects the true secret.
        let mut bad_digest = hashlock;
        bad_digest[31] ^= 1;
        assert!(!verify_htlc_preimage(&bad_digest, &secret));
    }

    #[test]
    fn can_claim_simulates_without_moving_state() {
        let lock = lock();
        assert_eq!(lock.can_claim(&preimage(), CURRENT_SLOT).unwrap(), AMOUNT);
        assert_eq!(lock.state, HtlcState::Locked);
        assert_eq!(
            lock.can_claim(b"wrong", CURRENT_SLOT).unwrap_err(),
            EscrowError::HtlcHashlockMismatch
        );
        assert_eq!(lock.state, HtlcState::Locked);
    }

    #[test]
    fn claim_window_open_helper() {
        let lock = lock();
        assert!(lock.claim_window_open(CURRENT_SLOT));
        assert!(lock.claim_window_open(EXPIRY_SLOT - 1));
        assert!(!lock.claim_window_open(EXPIRY_SLOT));
        assert!(!lock.claim_window_open(EXPIRY_SLOT + 1_000));
    }

    // AV-339: amend_htlc_expiry_slot.

    fn assert_lock_intact(lock: &HtlcLock, expiry_slot: u64, hashlock: [u8; 32], state: HtlcState) {
        assert_lock_intact_taker(lock, TAKER, expiry_slot, hashlock, state);
    }

    fn assert_lock_intact_taker(
        lock: &HtlcLock,
        taker: [u8; 32],
        expiry_slot: u64,
        hashlock: [u8; 32],
        state: HtlcState,
    ) {
        assert_eq!(lock.expiry_slot, expiry_slot);
        assert_eq!(lock.maker, MAKER);
        assert_eq!(lock.taker, taker);
        assert_eq!(lock.hashlock, hashlock);
        assert_eq!(lock.amount, AMOUNT);
        assert_eq!(lock.state, state);
    }

    #[test]
    fn amend_rejects_stranger_and_single_sided_pairs() {
        // Stranger pair: neither side matches.
        let mut lock = lock();
        let err = lock
            .amend_htlc_expiry_slot(STRANGER, STRANGER, 3_000, CURRENT_SLOT)
            .unwrap_err();
        assert_eq!(err, EscrowError::Unauthorized);
        assert_eq!(err.code(), 100);
        assert_lock_intact(&lock, EXPIRY_SLOT, sha256(&preimage()), HtlcState::Locked);
        // Maker alone: the taker slot is a stranger.
        let err = lock
            .amend_htlc_expiry_slot(MAKER, STRANGER, 3_000, CURRENT_SLOT)
            .unwrap_err();
        assert_eq!(err, EscrowError::Unauthorized);
        assert_lock_intact(&lock, EXPIRY_SLOT, sha256(&preimage()), HtlcState::Locked);
        // Taker alone: the maker slot is a stranger.
        let err = lock
            .amend_htlc_expiry_slot(STRANGER, TAKER, 3_000, CURRENT_SLOT)
            .unwrap_err();
        assert_eq!(err, EscrowError::Unauthorized);
        assert_lock_intact(&lock, EXPIRY_SLOT, sha256(&preimage()), HtlcState::Locked);
        // Swapped roles are not the maker/taker pair either.
        let err = lock
            .amend_htlc_expiry_slot(TAKER, MAKER, 3_000, CURRENT_SLOT)
            .unwrap_err();
        assert_eq!(err, EscrowError::Unauthorized);
        assert_lock_intact(&lock, EXPIRY_SLOT, sha256(&preimage()), HtlcState::Locked);
    }

    #[test]
    fn amend_rejects_claimed_lock() {
        let mut lock = lock();
        lock.claim(TAKER, &preimage(), CURRENT_SLOT).unwrap();
        let err = lock
            .amend_htlc_expiry_slot(MAKER, TAKER, 3_000, CURRENT_SLOT)
            .unwrap_err();
        assert_eq!(err, EscrowError::InvalidStateTransition);
        assert_eq!(err.code(), 101);
        assert_lock_intact(&lock, EXPIRY_SLOT, sha256(&preimage()), HtlcState::Claimed);
    }

    #[test]
    fn amend_rejects_refunded_lock() {
        let mut lock = lock();
        lock.refund(MAKER, EXPIRY_SLOT).unwrap();
        let err = lock
            .amend_htlc_expiry_slot(MAKER, TAKER, 3_000, EXPIRY_SLOT)
            .unwrap_err();
        assert_eq!(err, EscrowError::InvalidStateTransition);
        assert_lock_intact(&lock, EXPIRY_SLOT, sha256(&preimage()), HtlcState::Refunded);
    }

    #[test]
    fn amend_rejects_new_expiry_at_or_before_current_slot() {
        let mut lock = lock();
        // Equal to the current slot: the new window would be empty.
        let err = lock
            .amend_htlc_expiry_slot(MAKER, TAKER, CURRENT_SLOT, CURRENT_SLOT)
            .unwrap_err();
        assert_eq!(err, EscrowError::InvalidHtlcLock);
        assert_eq!(err.code(), 251);
        assert_lock_intact(&lock, EXPIRY_SLOT, sha256(&preimage()), HtlcState::Locked);
        // In the past.
        let err = lock
            .amend_htlc_expiry_slot(MAKER, TAKER, CURRENT_SLOT - 1, CURRENT_SLOT)
            .unwrap_err();
        assert_eq!(err, EscrowError::InvalidHtlcLock);
        assert_lock_intact(&lock, EXPIRY_SLOT, sha256(&preimage()), HtlcState::Locked);
    }

    #[test]
    fn amend_equal_value_is_noop() {
        let mut lock = lock();
        assert!(lock
            .amend_htlc_expiry_slot(MAKER, TAKER, EXPIRY_SLOT, CURRENT_SLOT)
            .is_ok());
        assert_lock_intact(&lock, EXPIRY_SLOT, sha256(&preimage()), HtlcState::Locked);
        // Still claimable under the re-affirmed window.
        assert_eq!(lock.claim(TAKER, &preimage(), CURRENT_SLOT).unwrap(), AMOUNT);
    }

    #[test]
    fn amend_extends_window_and_readers_follow() {
        let mut lock = lock();
        lock.amend_htlc_expiry_slot(MAKER, TAKER, 3_000, CURRENT_SLOT)
            .unwrap();
        assert_eq!(lock.expiry_slot, 3_000);
        assert_eq!(lock.state, HtlcState::Locked);
        // Past the old window, inside the new one: the claim window
        // is open again and the maker still cannot refund.
        assert!(lock.claim_window_open(2_500));
        assert_eq!(lock.can_claim(&preimage(), 2_500).unwrap(), AMOUNT);
        assert_eq!(
            lock.refund(MAKER, 2_500).unwrap_err(),
            EscrowError::HtlcRefundNotExpired
        );
        assert_eq!(lock.claim(TAKER, &preimage(), 2_500).unwrap(), AMOUNT);
        assert_eq!(lock.state, HtlcState::Claimed);
    }

    #[test]
    fn amend_shortens_window_and_readers_follow() {
        let mut lock = lock();
        lock.amend_htlc_expiry_slot(MAKER, TAKER, 1_500, CURRENT_SLOT)
            .unwrap();
        assert_eq!(lock.expiry_slot, 1_500);
        assert_eq!(lock.state, HtlcState::Locked);
        // Past the new window: the taker's claim is expired and the
        // maker's refund is open, even though the old window ran to
        // slot 2_000.
        assert!(!lock.claim_window_open(1_600));
        assert_eq!(
            lock.claim(TAKER, &preimage(), 1_600).unwrap_err(),
            EscrowError::HtlcClaimExpired
        );
        assert_eq!(lock.refund(MAKER, 1_600).unwrap(), AMOUNT);
        assert_eq!(lock.state, HtlcState::Refunded);
    }

    #[test]
    fn amend_moves_only_the_expiry_slot() {
        let mut lock = lock();
        lock.amend_htlc_expiry_slot(MAKER, TAKER, 3_000, CURRENT_SLOT)
            .unwrap();
        assert_eq!(lock.expiry_slot, 3_000);
        assert_eq!(lock.maker, MAKER);
        assert_eq!(lock.taker, TAKER);
        assert_eq!(lock.hashlock, sha256(&preimage()));
        assert_eq!(lock.amount, AMOUNT);
        assert_eq!(lock.state, HtlcState::Locked);
        // The revised window is itself revisable, in either direction.
        lock.amend_htlc_expiry_slot(MAKER, TAKER, 1_500, CURRENT_SLOT)
            .unwrap();
        assert_eq!(lock.expiry_slot, 1_500);
        assert_lock_intact(&lock, 1_500, sha256(&preimage()), HtlcState::Locked);
    }

    #[test]
    fn amend_reaffirming_a_lapsed_window_fails_the_value_gate() {
        // The old window (2_000) has already lapsed at slot 2_500, but
        // the lock is still Locked (nobody refunded yet). Re-affirming
        // the current value is not a no-op here: the value gate runs
        // first, mirroring amend_option_expiry (AV-299).
        let mut lock = lock();
        let err = lock
            .amend_htlc_expiry_slot(MAKER, TAKER, EXPIRY_SLOT, 2_500)
            .unwrap_err();
        assert_eq!(err, EscrowError::InvalidHtlcLock);
        assert_lock_intact(&lock, EXPIRY_SLOT, sha256(&preimage()), HtlcState::Locked);
        // Extending past the current slot from the lapsed window is
        // still allowed: the lock is live, only its window moved.
        lock.amend_htlc_expiry_slot(MAKER, TAKER, 3_000, 2_500)
            .unwrap();
        assert!(lock.claim_window_open(2_500));
        assert_eq!(lock.claim(TAKER, &preimage(), 2_500).unwrap(), AMOUNT);
    }

    // AV-343: amend_htlc_hashlock.

    fn new_preimage() -> Vec<u8> {
        b"corrected-swap-secret-7".to_vec()
    }

    fn new_hashlock() -> [u8; 32] {
        sha256(&new_preimage())
    }

    #[test]
    fn amend_hashlock_rejects_stranger_and_single_sided_pairs() {
        let mut lock = lock();
        let new = new_hashlock();
        // Stranger pair: neither side matches.
        let err = lock
            .amend_htlc_hashlock(STRANGER, STRANGER, new, CURRENT_SLOT)
            .unwrap_err();
        assert_eq!(err, EscrowError::Unauthorized);
        assert_eq!(err.code(), 100);
        assert_lock_intact(&lock, EXPIRY_SLOT, sha256(&preimage()), HtlcState::Locked);
        // Maker alone: the taker slot is a stranger.
        let err = lock
            .amend_htlc_hashlock(MAKER, STRANGER, new, CURRENT_SLOT)
            .unwrap_err();
        assert_eq!(err, EscrowError::Unauthorized);
        assert_lock_intact(&lock, EXPIRY_SLOT, sha256(&preimage()), HtlcState::Locked);
        // Taker alone: the maker slot is a stranger.
        let err = lock
            .amend_htlc_hashlock(STRANGER, TAKER, new, CURRENT_SLOT)
            .unwrap_err();
        assert_eq!(err, EscrowError::Unauthorized);
        assert_lock_intact(&lock, EXPIRY_SLOT, sha256(&preimage()), HtlcState::Locked);
        // Swapped roles are not the maker/taker pair either.
        let err = lock
            .amend_htlc_hashlock(TAKER, MAKER, new, CURRENT_SLOT)
            .unwrap_err();
        assert_eq!(err, EscrowError::Unauthorized);
        assert_lock_intact(&lock, EXPIRY_SLOT, sha256(&preimage()), HtlcState::Locked);
    }

    #[test]
    fn amend_hashlock_rejects_claimed_lock() {
        let mut lock = lock();
        lock.claim(TAKER, &preimage(), CURRENT_SLOT).unwrap();
        let err = lock
            .amend_htlc_hashlock(MAKER, TAKER, new_hashlock(), CURRENT_SLOT)
            .unwrap_err();
        assert_eq!(err, EscrowError::InvalidStateTransition);
        assert_eq!(err.code(), 101);
        assert_lock_intact(&lock, EXPIRY_SLOT, sha256(&preimage()), HtlcState::Claimed);
    }

    #[test]
    fn amend_hashlock_rejects_refunded_lock() {
        let mut lock = lock();
        lock.refund(MAKER, EXPIRY_SLOT).unwrap();
        let err = lock
            .amend_htlc_hashlock(MAKER, TAKER, new_hashlock(), EXPIRY_SLOT)
            .unwrap_err();
        assert_eq!(err, EscrowError::InvalidStateTransition);
        assert_lock_intact(&lock, EXPIRY_SLOT, sha256(&preimage()), HtlcState::Refunded);
    }

    #[test]
    fn amend_hashlock_rejects_expired_window() {
        // The window has closed (slot == expiry) but nobody refunded
        // yet, so the lock is still Locked — and still unrevisable:
        // revising the digest cannot revive a claim.
        let mut lock = lock();
        let err = lock
            .amend_htlc_hashlock(MAKER, TAKER, new_hashlock(), EXPIRY_SLOT)
            .unwrap_err();
        assert_eq!(err, EscrowError::HtlcClaimExpired);
        assert_eq!(err.code(), 254);
        assert_lock_intact(&lock, EXPIRY_SLOT, sha256(&preimage()), HtlcState::Locked);
        // Past expiry: same error, and the digest is still the old one.
        let err = lock
            .amend_htlc_hashlock(MAKER, TAKER, new_hashlock(), EXPIRY_SLOT + 1)
            .unwrap_err();
        assert_eq!(err, EscrowError::HtlcClaimExpired);
        assert_lock_intact(&lock, EXPIRY_SLOT, sha256(&preimage()), HtlcState::Locked);
        // The timelock gate runs before the no-op check: re-affirming
        // the current digest in an expired window still fails.
        let err = lock
            .amend_htlc_hashlock(MAKER, TAKER, sha256(&preimage()), EXPIRY_SLOT)
            .unwrap_err();
        assert_eq!(err, EscrowError::HtlcClaimExpired);
    }

    #[test]
    fn amend_hashlock_equal_value_is_noop() {
        let mut lock = lock();
        assert!(lock
            .amend_htlc_hashlock(MAKER, TAKER, sha256(&preimage()), CURRENT_SLOT)
            .is_ok());
        assert_lock_intact(&lock, EXPIRY_SLOT, sha256(&preimage()), HtlcState::Locked);
        // The original secret still claims under the re-affirmed digest.
        assert_eq!(lock.claim(TAKER, &preimage(), CURRENT_SLOT).unwrap(), AMOUNT);
    }

    #[test]
    fn amend_hashlock_retargets_claim() {
        let mut lock = lock();
        lock.amend_htlc_hashlock(MAKER, TAKER, new_hashlock(), CURRENT_SLOT)
            .unwrap();
        assert_eq!(lock.hashlock, new_hashlock());
        // The old secret no longer satisfies the digest.
        let err = lock.claim(TAKER, &preimage(), CURRENT_SLOT).unwrap_err();
        assert_eq!(err, EscrowError::HtlcHashlockMismatch);
        assert_eq!(lock.state, HtlcState::Locked);
        // The new secret claims and returns the amount.
        assert_eq!(
            lock.claim(TAKER, &new_preimage(), CURRENT_SLOT).unwrap(),
            AMOUNT
        );
        assert_eq!(lock.state, HtlcState::Claimed);
    }

    #[test]
    fn amend_hashlock_moves_only_the_hashlock() {
        let mut lock = lock();
        lock.amend_htlc_hashlock(MAKER, TAKER, new_hashlock(), CURRENT_SLOT)
            .unwrap();
        assert_lock_intact(&lock, EXPIRY_SLOT, new_hashlock(), HtlcState::Locked);
        // The revised digest is itself revisable, back to the original.
        lock.amend_htlc_hashlock(MAKER, TAKER, sha256(&preimage()), CURRENT_SLOT)
            .unwrap();
        assert_lock_intact(&lock, EXPIRY_SLOT, sha256(&preimage()), HtlcState::Locked);
    }

    #[test]
    fn amend_hashlock_can_claim_follows_live_hashlock() {
        let mut lock = lock();
        lock.amend_htlc_hashlock(MAKER, TAKER, new_hashlock(), CURRENT_SLOT)
            .unwrap();
        // The old secret no longer simulates as claimable...
        assert_eq!(
            lock.can_claim(&preimage(), CURRENT_SLOT).unwrap_err(),
            EscrowError::HtlcHashlockMismatch
        );
        // ...while the new secret does, without moving state.
        assert_eq!(lock.can_claim(&new_preimage(), CURRENT_SLOT).unwrap(), AMOUNT);
        assert_eq!(lock.state, HtlcState::Locked);
    }

    #[test]
    fn amend_hashlock_combines_with_av339_window_extension() {
        // Expired window: revising the digest is refused outright.
        let mut lock = lock();
        let err = lock
            .amend_htlc_hashlock(MAKER, TAKER, new_hashlock(), 2_500)
            .unwrap_err();
        assert_eq!(err, EscrowError::HtlcClaimExpired);
        assert_lock_intact(&lock, EXPIRY_SLOT, sha256(&preimage()), HtlcState::Locked);
        // AV-339 first: extend the window (also dual-signed).
        lock.amend_htlc_expiry_slot(MAKER, TAKER, 3_000, 2_500)
            .unwrap();
        // Now the digest revision succeeds, and the new secret claims
        // inside the new window.
        lock.amend_htlc_hashlock(MAKER, TAKER, new_hashlock(), 2_500)
            .unwrap();
        assert_eq!(lock.hashlock, new_hashlock());
        assert_eq!(
            lock.claim(TAKER, &new_preimage(), 2_500).unwrap(),
            AMOUNT
        );
        assert_eq!(lock.state, HtlcState::Claimed);
    }

    #[test]
    fn amend_hashlock_accepts_degenerate_digests() {
        // No non-zero gate: the digest is opaque, like at `new()` time.
        let mut lock = lock();
        lock.amend_htlc_hashlock(MAKER, TAKER, [0u8; 32], CURRENT_SLOT)
            .unwrap();
        assert_eq!(lock.hashlock, [0u8; 32]);
        // No preimage hashes to the zero digest, so claims fail the
        // hashlock check rather than anything else.
        assert_eq!(
            lock.claim(TAKER, b"anything", CURRENT_SLOT).unwrap_err(),
            EscrowError::HtlcHashlockMismatch
        );
        lock.amend_htlc_hashlock(MAKER, TAKER, [0xFF; 32], CURRENT_SLOT)
            .unwrap();
        assert_eq!(lock.hashlock, [0xFF; 32]);
        assert_lock_intact(&lock, EXPIRY_SLOT, [0xFF; 32], HtlcState::Locked);
    }

    #[test]
    fn amend_hashlock_failed_calls_leave_no_state_change() {
        // Every failure mode on one lock, then a single intact check.
        let mut lock = lock();
        let new = new_hashlock();
        assert_eq!(
            lock.amend_htlc_hashlock(STRANGER, TAKER, new, CURRENT_SLOT)
                .unwrap_err(),
            EscrowError::Unauthorized
        );
        assert_eq!(
            lock.amend_htlc_hashlock(MAKER, TAKER, new, EXPIRY_SLOT)
                .unwrap_err(),
            EscrowError::HtlcClaimExpired
        );
        assert_lock_intact(&lock, EXPIRY_SLOT, sha256(&preimage()), HtlcState::Locked);
        // And the lock is still fully usable afterwards.
        assert_eq!(lock.claim(TAKER, &preimage(), CURRENT_SLOT).unwrap(), AMOUNT);
    }

    // AV-344: amend_htlc_taker.

    const NEW_TAKER: [u8; 32] = [0x44; 32];

    #[test]
    fn amend_taker_rejects_stranger_and_single_sided_pairs() {
        let mut lock = lock();
        // Stranger pair: neither side matches.
        let err = lock
            .amend_htlc_taker(STRANGER, STRANGER, NEW_TAKER, CURRENT_SLOT)
            .unwrap_err();
        assert_eq!(err, EscrowError::Unauthorized);
        assert_eq!(err.code(), 100);
        assert_lock_intact(&lock, EXPIRY_SLOT, sha256(&preimage()), HtlcState::Locked);
        // Maker alone: the taker slot is a stranger.
        let err = lock
            .amend_htlc_taker(MAKER, STRANGER, NEW_TAKER, CURRENT_SLOT)
            .unwrap_err();
        assert_eq!(err, EscrowError::Unauthorized);
        assert_lock_intact(&lock, EXPIRY_SLOT, sha256(&preimage()), HtlcState::Locked);
        // Taker alone: the maker slot is a stranger.
        let err = lock
            .amend_htlc_taker(STRANGER, TAKER, NEW_TAKER, CURRENT_SLOT)
            .unwrap_err();
        assert_eq!(err, EscrowError::Unauthorized);
        assert_lock_intact(&lock, EXPIRY_SLOT, sha256(&preimage()), HtlcState::Locked);
        // Swapped roles are not the maker/taker pair either.
        let err = lock
            .amend_htlc_taker(TAKER, MAKER, NEW_TAKER, CURRENT_SLOT)
            .unwrap_err();
        assert_eq!(err, EscrowError::Unauthorized);
        assert_lock_intact(&lock, EXPIRY_SLOT, sha256(&preimage()), HtlcState::Locked);
    }

    #[test]
    fn amend_taker_rejects_claimed_lock() {
        let mut lock = lock();
        lock.claim(TAKER, &preimage(), CURRENT_SLOT).unwrap();
        let err = lock
            .amend_htlc_taker(MAKER, TAKER, NEW_TAKER, CURRENT_SLOT)
            .unwrap_err();
        assert_eq!(err, EscrowError::InvalidStateTransition);
        assert_eq!(err.code(), 101);
        assert_lock_intact(&lock, EXPIRY_SLOT, sha256(&preimage()), HtlcState::Claimed);
    }

    #[test]
    fn amend_taker_rejects_refunded_lock() {
        let mut lock = lock();
        lock.refund(MAKER, EXPIRY_SLOT).unwrap();
        let err = lock
            .amend_htlc_taker(MAKER, TAKER, NEW_TAKER, EXPIRY_SLOT)
            .unwrap_err();
        assert_eq!(err, EscrowError::InvalidStateTransition);
        assert_lock_intact(&lock, EXPIRY_SLOT, sha256(&preimage()), HtlcState::Refunded);
    }

    #[test]
    fn amend_taker_rejects_expired_window() {
        // The window has closed (slot == expiry) but nobody refunded
        // yet, so the lock is still Locked — and still unrevisable:
        // revising the taker cannot revive a claim.
        let mut lock = lock();
        let err = lock
            .amend_htlc_taker(MAKER, TAKER, NEW_TAKER, EXPIRY_SLOT)
            .unwrap_err();
        assert_eq!(err, EscrowError::HtlcClaimExpired);
        assert_eq!(err.code(), 254);
        assert_lock_intact(&lock, EXPIRY_SLOT, sha256(&preimage()), HtlcState::Locked);
        // Past expiry: same error, and the taker is still the old one.
        let err = lock
            .amend_htlc_taker(MAKER, TAKER, NEW_TAKER, EXPIRY_SLOT + 1)
            .unwrap_err();
        assert_eq!(err, EscrowError::HtlcClaimExpired);
        assert_lock_intact(&lock, EXPIRY_SLOT, sha256(&preimage()), HtlcState::Locked);
        // The timelock gate runs before the no-op check: re-affirming
        // the current taker in an expired window still fails.
        let err = lock
            .amend_htlc_taker(MAKER, TAKER, TAKER, EXPIRY_SLOT)
            .unwrap_err();
        assert_eq!(err, EscrowError::HtlcClaimExpired);
    }

    #[test]
    fn amend_taker_rejects_zero_address() {
        let mut lock = lock();
        let err = lock
            .amend_htlc_taker(MAKER, TAKER, [0u8; 32], CURRENT_SLOT)
            .unwrap_err();
        assert_eq!(err, EscrowError::InvalidHtlcLock);
        assert_eq!(err.code(), 251);
        // The original taker is untouched.
        assert_lock_intact(&lock, EXPIRY_SLOT, sha256(&preimage()), HtlcState::Locked);
        // A zero-address amendment attempt never locks the taker out:
        // the original taker still claims afterwards.
        assert_eq!(lock.claim(TAKER, &preimage(), CURRENT_SLOT).unwrap(), AMOUNT);
    }

    #[test]
    fn amend_taker_equal_value_is_noop() {
        let mut lock = lock();
        assert!(lock
            .amend_htlc_taker(MAKER, TAKER, TAKER, CURRENT_SLOT)
            .is_ok());
        assert_lock_intact(&lock, EXPIRY_SLOT, sha256(&preimage()), HtlcState::Locked);
        // The original taker still claims under the re-affirmed value.
        assert_eq!(lock.claim(TAKER, &preimage(), CURRENT_SLOT).unwrap(), AMOUNT);
    }

    #[test]
    fn amend_taker_retargets_claim() {
        let mut lock = lock();
        lock.amend_htlc_taker(MAKER, TAKER, NEW_TAKER, CURRENT_SLOT)
            .unwrap();
        assert_eq!(lock.taker, NEW_TAKER);
        // The old taker no longer satisfies the authority check.
        let err = lock.claim(TAKER, &preimage(), CURRENT_SLOT).unwrap_err();
        assert_eq!(err, EscrowError::Unauthorized);
        assert_eq!(lock.state, HtlcState::Locked);
        // The new taker claims with the same preimage and returns the
        // amount.
        assert_eq!(
            lock.claim(NEW_TAKER, &preimage(), CURRENT_SLOT).unwrap(),
            AMOUNT
        );
        assert_eq!(lock.state, HtlcState::Claimed);
    }

    #[test]
    fn amend_taker_moves_only_the_taker() {
        let mut lock = lock();
        lock.amend_htlc_taker(MAKER, TAKER, NEW_TAKER, CURRENT_SLOT)
            .unwrap();
        assert_lock_intact_taker(
            &lock,
            NEW_TAKER,
            EXPIRY_SLOT,
            sha256(&preimage()),
            HtlcState::Locked,
        );
        // The revised taker is itself revisable, back to the original
        // — with the *new* taker co-signing as the current taker.
        lock.amend_htlc_taker(MAKER, NEW_TAKER, TAKER, CURRENT_SLOT)
            .unwrap();
        assert_lock_intact(&lock, EXPIRY_SLOT, sha256(&preimage()), HtlcState::Locked);
    }

    #[test]
    fn amend_taker_can_claim_follows_live_taker() {
        let mut lock = lock();
        lock.amend_htlc_taker(MAKER, TAKER, NEW_TAKER, CURRENT_SLOT)
            .unwrap();
        // The old taker's simulation is now refused as a stranger...
        assert_eq!(
            lock.check_claim(TAKER, &preimage(), CURRENT_SLOT)
                .unwrap_err(),
            EscrowError::Unauthorized
        );
        // ...while `can_claim` — which reads the live taker — succeeds
        // for the new taker, without moving state.
        assert_eq!(lock.can_claim(&preimage(), CURRENT_SLOT).unwrap(), AMOUNT);
        assert_eq!(lock.state, HtlcState::Locked);
        // And the refund path still reads only the maker: the taker
        // revision did not touch it.
        assert_eq!(
            lock.refund(MAKER, CURRENT_SLOT).unwrap_err(),
            EscrowError::HtlcRefundNotExpired
        );
    }

    #[test]
    fn amend_taker_combines_with_av339_window_extension() {
        // Expired window: revising the taker is refused outright.
        let mut lock = lock();
        let err = lock
            .amend_htlc_taker(MAKER, TAKER, NEW_TAKER, 2_500)
            .unwrap_err();
        assert_eq!(err, EscrowError::HtlcClaimExpired);
        assert_lock_intact(&lock, EXPIRY_SLOT, sha256(&preimage()), HtlcState::Locked);
        // AV-339 first: extend the window (also dual-signed).
        lock.amend_htlc_expiry_slot(MAKER, TAKER, 3_000, 2_500)
            .unwrap();
        // Now the taker revision succeeds, and the new taker claims
        // inside the new window.
        lock.amend_htlc_taker(MAKER, TAKER, NEW_TAKER, 2_500)
            .unwrap();
        assert_eq!(lock.taker, NEW_TAKER);
        assert_eq!(
            lock.claim(NEW_TAKER, &preimage(), 2_500).unwrap(),
            AMOUNT
        );
        assert_eq!(lock.state, HtlcState::Claimed);
    }

    #[test]
    fn amend_taker_failed_calls_leave_no_state_change() {
        // Every failure mode on one lock, then a single intact check.
        let mut lock = lock();
        assert_eq!(
            lock.amend_htlc_taker(STRANGER, TAKER, NEW_TAKER, CURRENT_SLOT)
                .unwrap_err(),
            EscrowError::Unauthorized
        );
        assert_eq!(
            lock.amend_htlc_taker(MAKER, TAKER, [0u8; 32], CURRENT_SLOT)
                .unwrap_err(),
            EscrowError::InvalidHtlcLock
        );
        assert_eq!(
            lock.amend_htlc_taker(MAKER, TAKER, NEW_TAKER, EXPIRY_SLOT)
                .unwrap_err(),
            EscrowError::HtlcClaimExpired
        );
        assert_lock_intact(&lock, EXPIRY_SLOT, sha256(&preimage()), HtlcState::Locked);
        // And the lock is still fully usable afterwards.
        assert_eq!(lock.claim(TAKER, &preimage(), CURRENT_SLOT).unwrap(), AMOUNT);
    }

    #[test]
    fn error_codes_pinned() {
        assert_eq!(EscrowError::InvalidHtlcLock.code(), 251);
        assert_eq!(EscrowError::HtlcInvalidPreimage.code(), 252);
        assert_eq!(EscrowError::HtlcHashlockMismatch.code(), 253);
        assert_eq!(EscrowError::HtlcClaimExpired.code(), 254);
        assert_eq!(EscrowError::HtlcRefundNotExpired.code(), 255);
        for e in [
            EscrowError::InvalidHtlcLock,
            EscrowError::HtlcInvalidPreimage,
            EscrowError::HtlcHashlockMismatch,
            EscrowError::HtlcClaimExpired,
            EscrowError::HtlcRefundNotExpired,
        ] {
            assert!(EscrowError::all().contains(&e));
        }
        // AV-187 pins its own codes in nft_escrow::nft_tests.
        // AV-188 pins its own codes in merkle_distributor::merkle_tests.
        // AV-189 pins its own codes in english_auction::english_auction_tests.
        // AV-190 pins its own codes in rental_escrow::rental_escrow_tests.
        assert_eq!(EscrowError::all().len(), 253); // AV-195: +7 social-recovery errors, AV-196: +6 jury-sortition errors, AV-197: +5 payment-channel errors; AV-209: +4; AV-214: +6; AV-215: +1; AV-217: +3; AV-218: +2; AV-220: +1; AV-225: +1; AV-228: +1; AV-266: +1; AV-284: +1; AV-287: +1 auto-unpause-at error; AV-337: +1 governance-proposal-expired error; AV-342: +1 distribution-claims-started error
    }
}
