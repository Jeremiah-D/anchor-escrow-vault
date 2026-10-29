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
        assert_eq!(EscrowError::all().len(), 250); // AV-195: +7 social-recovery errors, AV-196: +6 jury-sortition errors, AV-197: +5 payment-channel errors; AV-209: +4; AV-214: +6; AV-215: +1; AV-217: +3; AV-218: +2; AV-220: +1; AV-225: +1; AV-228: +1; AV-266: +1; AV-284: +1
    }
}
