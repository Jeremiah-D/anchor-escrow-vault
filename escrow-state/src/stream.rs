//! AV-198: Sablier-style payment stream — per-second salary stream.
//!
//! A `PaymentStream` pays a recipient continuously at a fixed
//! `rate_per_sec`: the *earned* amount grows with every passing second
//! (`earned = rate × elapsed`, all in `u128` so it cannot overflow) and
//! the recipient may withdraw any earned-but-unwithdrawn amount at any
//! time — withdraws are idempotent and a zero-earn withdraw is a no-op,
//! not an error. The initializer funds the stream up front
//! (`total = rate_per_sec × duration_secs`) and may `cancel` at any
//! time: earned-so-far goes to the recipient, the unearned remainder
//! returns to the initializer, terminally.
//!
//! An optional `cliff_secs` gates the first payout: before
//! `start_ts + cliff_secs` the earned amount reports `0` (accrual still
//! runs from `start_ts` — the cliff delays payout, it does not eat into
//! the stream). The initializer may also `pause`/`resume` the stream;
//! paused intervals are tracked and excluded from accrual, so a paused
//! second never earns.
//!
//! AV-202: the *current* recipient may transfer the whole stream to a
//! new recipient (`transfer_recipient`) — the payroll-to-new-wallet
//! scenario: the stream survives, earned-but-unwithdrawn funds and the
//! accrual schedule move with it, only the payee key changes.
//!
//! AV-204: the rate itself may be renegotiated mid-flight with
//! `update_stream_rate` — dual-signed by initializer *and* recipient,
//! checkpointed so only *future* accrual changes: the amount already
//! earned under the old rate is locked in at change time and never
//! repriced, and the funded total (`total_funded`, set at creation)
//! still caps everything. Orthogonal to AV-13 vesting (one lump sum
//! that unlocks whole at expiry — the release is a single gate) and to
//! AV-197 bidirectional channels (both parties co-sign off-chain
//! state): here the release is *continuous* per-second and unilateral.
//! Orthogonal to AV-190 rental escrow (day-granularity rent tranches):
//! the stream accrues at second granularity and has no tranches.
//! `Copy`, heap-free, `no_std`-friendly.
//!
//! AV-297: the payout cliff itself may be renegotiated mid-flight with
//! `amend_stream_cliff_secs` — dual-signed like the rate, and likewise
//! only *future* payouts change: the cliff gates payout, not accrual,
//! so moving it never reprices anything and needs no checkpoint — the
//! checkpoint stores the ungated accrued amount, and `earned`/`withdraw`
//! read the live cliff on every call. Orthogonal to `update_stream_rate`
//! (that is the per-second price, this item is the first-payout gate)
//! and to `stream_cancel`/`pause` (those are lifecycle, this item is a
//! parameter revision).
//!
//! AV-298: the stream *length* itself may be renegotiated mid-flight
//! with `amend_stream_duration_secs` — dual-signed like the rate and
//! the cliff, and checkpointed like the rate: the amount already
//! earned under the old window is locked in at change time and never
//! repriced or reduced, so `earned(now)` is identical immediately
//! before and after the change. Only the accrual window's end moves
//! (`end_ts = start_ts + duration_secs`): lengthening lets accrual
//! run longer, shortening caps it earlier — but `total_funded` (set
//! at creation) still caps everything, so lengthening creates no new
//! funding obligation and shortening refunds nothing already funded;
//! any on-chain funding difference is the caller's to settle, the
//! state machine moves no funds. Orthogonal to `update_stream_rate`
//! (that is the per-second price, this item is the window length),
//! to `amend_stream_cliff_secs` (that is the first-payout gate, this
//! item is the window length), and to `stream_cancel` (that is
//! lifecycle, this item is a parameter revision).
//!
//! AV-300: the stream *start* itself may be renegotiated mid-flight
//! with `amend_stream_start_ts` — dual-signed like the rate, the
//! cliff, and the duration — but only while the stream has not
//! started yet: `now` must be before the live `start_ts` and the new
//! start must be after `now`, so a revision only moves a future
//! start moment and never backdates the stream open. Only the
//! window's start moves (`end_ts = start_ts + duration_secs` shifts
//! with it): the window slides, it does not stretch —
//! `duration_secs` and `total_funded` (`rate × duration`,
//! independent of start) never move, and no checkpoint is needed:
//! with no accrual or withdrawal history the checkpoint is `(0, 0)`
//! and `earned` / `stream_withdraw` read the live `start_ts` on
//! every call, so the new start takes effect from the next
//! evaluation. A stream with any history — a non-`(0, 0)`
//! checkpoint pair or a non-zero `withdrawn` — is refused outright,
//! fail-closed: changing the start after accrual began would rewrite
//! accrued history, and the gate blocks bypassing the
//! `now < start_ts` check by pre-setting a checkpoint with a future
//! `now`. Orthogonal to `update_stream_rate` (that is the per-second
//! price, this item is the window start), to
//! `amend_stream_cliff_secs` (that is the first-payout gate, this
//! item is the window start), to `amend_stream_duration_secs` (that
//! is the window length, this item is the window start), and to
//! `stream_cancel` (that is lifecycle, this item is a parameter
//! revision).

use crate::EscrowError;

/// Lifecycle of a [`PaymentStream`]. `Active` covers the paused
/// sub-state (`paused_at.is_some()`); the other two are terminal.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum StreamState {
    /// Live: accrual runs unless paused, withdrawals and cancel are
    /// allowed.
    #[default]
    Active,
    /// The initializer cancelled — earned went to the recipient, the
    /// remainder returned to the initializer (terminal).
    Cancelled,
    /// Everything funded was withdrawn (auto, terminal).
    Exhausted,
}

/// A Sablier-style per-second payment stream.
///
/// The initializer deposits `rate_per_sec × duration_secs` (the Anchor
/// program owns custody — this module tracks the arithmetic only) and
/// the recipient earns `rate_per_sec` per accruing second from
/// `start_ts`, subject to the optional cliff and any paused intervals.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PaymentStream {
    /// Funder; may cancel, pause, and resume.
    initializer: [u8; 32],
    /// Payee; may withdraw earned funds.
    recipient: [u8; 32],
    /// Lamports (or base units) earned per accruing second.
    rate_per_sec: u64,
    /// Unix timestamp at which accrual begins.
    start_ts: u64,
    /// Stream length in seconds; total funded is `rate × duration`.
    duration_secs: u64,
    /// Payout gate: no payout before `start_ts + cliff_secs`.
    cliff_secs: u64,
    /// Total funded: `rate_per_sec × duration_secs` (fits `u64` by
    /// construction — [`PaymentStream::create_stream`] refuses a config
    /// whose product does not).
    total_funded: u64,
    /// Amount already withdrawn by the recipient.
    withdrawn: u64,
    /// `Some(ts)` while paused (accrual frozen since `ts`).
    paused_at: Option<u64>,
    /// Seconds spent paused across completed pause intervals.
    paused_total: u64,
    /// AV-204 rate-change checkpoint: the earned amount locked in under
    /// the previous rate(s) at the last rate change (ungated — the
    /// cliff gates payout, not accrual, so a pre-cliff change must not
    /// erase pre-change accrual).
    checkpoint_earned: u64,
    /// AV-204 rate-change checkpoint: `accruing_seconds` at the last
    /// rate change. Post-change accrual is
    /// `rate × (accruing_seconds(now) - checkpoint_seconds)`.
    checkpoint_seconds: u64,
    /// Lifecycle state.
    state: StreamState,
}

impl PaymentStream {
    /// Creates a stream. The initializer funds it; `total_funded` is
    /// computed as `rate_per_sec × duration_secs` in `u128`
    /// (saturating) and the config is refused if the product does not
    /// fit `u64`.
    ///
    /// Fails ([`EscrowError::InvalidStream`], code 304) on a zero
    /// `rate_per_sec`, a zero `duration_secs`, `cliff_secs >
    /// duration_secs`, a zero initializer key, or a zero recipient key.
    pub fn create_stream(
        initializer: [u8; 32],
        recipient: [u8; 32],
        rate_per_sec: u64,
        start_ts: u64,
        duration_secs: u64,
        cliff_secs: u64,
    ) -> Result<Self, EscrowError> {
        if rate_per_sec == 0
            || duration_secs == 0
            || cliff_secs > duration_secs
            || initializer == [0u8; 32]
            || recipient == [0u8; 32]
        {
            return Err(EscrowError::InvalidStream);
        }
        // u128 saturating multiply — the only place two u64s are
        // multiplied in this module. A product that does not fit u64
        // is a config error (the program cannot move more lamports
        // than a u64).
        let total = (rate_per_sec as u128).saturating_mul(duration_secs as u128);
        let total_funded: u64 = u64::try_from(total).map_err(|_| EscrowError::InvalidStream)?;
        Ok(PaymentStream {
            initializer,
            recipient,
            rate_per_sec,
            start_ts,
            duration_secs,
            cliff_secs,
            total_funded,
            withdrawn: 0,
            paused_at: None,
            paused_total: 0,
            checkpoint_earned: 0,
            checkpoint_seconds: 0,
            state: StreamState::Active,
        })
    }

    /// Stream end: `start_ts + duration_secs` (saturating). Accrual
    /// never counts seconds past this point.
    pub fn end_ts(&self) -> u64 {
        self.start_ts.saturating_add(self.duration_secs)
    }

    /// Seconds that have accrued as of `now`: the interval
    /// `[start_ts, min(now, end_ts))` minus all paused seconds.
    ///
    /// The currently-open pause interval contributes
    /// `min(now, end) - paused_at` (saturating) so accrual freezes the
    /// instant `pause` is called. Zero before `start_ts`; saturating —
    /// never underflows.
    fn accruing_seconds(&self, now: u64) -> u64 {
        let acc_end = now.min(self.end_ts());
        if acc_end <= self.start_ts {
            return 0;
        }
        let mut elapsed = acc_end - self.start_ts;
        elapsed = elapsed.saturating_sub(self.paused_total);
        if let Some(paused_at) = self.paused_at {
            if acc_end > paused_at {
                elapsed = elapsed.saturating_sub(acc_end - paused_at);
            }
        }
        elapsed
    }

    /// Amount earned as of `now`: the AV-204 checkpoint plus
    /// `rate_per_sec × (accruing_seconds(now) - checkpoint_seconds)`,
    /// computed in `u128` (cannot overflow) and capped at
    /// `total_funded`. With no rate change the checkpoint is `(0, 0)`
    /// and this is exactly `rate × accruing_seconds`.
    ///
    /// Reports `0` before `start_ts + cliff_secs` — the cliff gates
    /// payout, it does not consume the stream: accrual itself runs
    /// from `start_ts`. (The checkpoint stores the *ungated* accrued
    /// amount, so a rate change before the cliff elapses does not erase
    /// the pre-change accrual — it simply stays gated until the cliff.)
    pub fn earned(&self, now: u64) -> u64 {
        if now < self.start_ts.saturating_add(self.cliff_secs) {
            return 0;
        }
        let elapsed =
            (self.accruing_seconds(now).saturating_sub(self.checkpoint_seconds)) as u128;
        let earned = (self.checkpoint_earned as u128)
            .saturating_add((self.rate_per_sec as u128).saturating_mul(elapsed));
        earned.min(self.total_funded as u128) as u64
    }

    /// Requires the stream to be live; every op below runs
    /// authority → state → config → amount.
    fn require_active(&self) -> Result<(), EscrowError> {
        if self.state != StreamState::Active {
            return Err(EscrowError::StreamNotActive);
        }
        Ok(())
    }

    /// Withdraws the newly-earned amount as of `now` (earned minus
    /// previously withdrawn). Recipient-only
    /// ([`EscrowError::StreamUnauthorized`], code 305).
    ///
    /// A zero-earn withdraw is an idempotent no-op (`Ok(0)`), not an
    /// error. When the withdraw drains the stream the state flips to
    /// `Exhausted` automatically.
    pub fn stream_withdraw(&mut self, caller: [u8; 32], now: u64) -> Result<u64, EscrowError> {
        // Authority first: strangers learn nothing about state.
        if caller != self.recipient {
            return Err(EscrowError::StreamUnauthorized);
        }
        self.require_active()?;
        let due = self.earned(now).saturating_sub(self.withdrawn);
        self.withdrawn = self.withdrawn.saturating_add(due);
        if self.withdrawn >= self.total_funded {
            self.state = StreamState::Exhausted;
        }
        Ok(due)
    }

    /// Cancels the stream: `(earned - withdrawn)` goes to the
    /// recipient, the unearned remainder goes back to the initializer.
    /// Initializer-only ([`EscrowError::StreamUnauthorized`], code
    /// 305); terminal (`Cancelled`).
    pub fn stream_cancel(
        &mut self,
        caller: [u8; 32],
        now: u64,
    ) -> Result<(u64, u64), EscrowError> {
        if caller != self.initializer {
            return Err(EscrowError::StreamUnauthorized);
        }
        self.require_active()?;
        let earned_now = self.earned(now);
        let to_recipient = earned_now.saturating_sub(self.withdrawn);
        let to_initializer = self.total_funded.saturating_sub(earned_now);
        self.withdrawn = earned_now;
        self.state = StreamState::Cancelled;
        Ok((to_recipient, to_initializer))
    }

    /// Transfers the stream's recipient to `new_recipient` — the
    /// payroll-to-new-wallet scenario (lost recipient key, invoice
    /// reassigned to a new contractor). Recipient-only: only the
    /// *current* recipient may call; a stranger (including the
    /// initializer) gets [`EscrowError::StreamUnauthorized`] (code
    /// 305), checked before state so strangers learn nothing.
    ///
    /// The stream *survives*: `initializer`, `rate_per_sec`,
    /// `start_ts`, `duration_secs`, `cliff_secs`, `total_funded`,
    /// `withdrawn`, `paused_at`/`paused_total` and `state` are all
    /// untouched — only the payee key changes. The new recipient
    /// inherits the earned-but-unwithdrawn balance
    /// (`earned(now) - withdrawn`) and keeps accruing at the same
    /// rate; the old recipient's withdraws are history (`withdrawn`
    /// stays — spent funds are not moved back).
    ///
    /// Orthogonal to [`PaymentStream::stream_cancel`] (terminal:
    /// earned routes to the recipient, the unearned remainder to the
    /// initializer): this is a *continuing* transfer, not a
    /// termination.
    ///
    /// Check order is authority → state → config: a zero
    /// `new_recipient` is [`EscrowError::InvalidStream`] (code 304).
    /// Transferring to the current recipient is an idempotent no-op
    /// (`Ok(())`, no state change).
    ///
    /// The program / indexer records the transfer with
    /// [`PaymentStream::transfer_audit_json`].
    pub fn transfer_recipient(
        &mut self,
        caller: [u8; 32],
        new_recipient: [u8; 32],
    ) -> Result<(), EscrowError> {
        if caller != self.recipient {
            return Err(EscrowError::StreamUnauthorized);
        }
        self.require_active()?;
        if new_recipient == [0u8; 32] {
            return Err(EscrowError::InvalidStream);
        }
        if new_recipient == self.recipient {
            return Ok(());
        }
        self.recipient = new_recipient;
        Ok(())
    }

    /// Audit-event JSON for a recipient transfer (hand-written, no
    /// serde — same convention as the auction modules):
    /// `{"event":"stream_recipient_transferred","old_recipient":
    /// "<64hex>","new_recipient":"<64hex>"}`. Standalone (no `&self`):
    /// the old key is only known to the caller at call time — by the
    /// time `transfer_recipient` returns, the stream already carries
    /// the new recipient.
    pub fn transfer_audit_json(old_recipient: [u8; 32], new_recipient: [u8; 32]) -> String {
        let mut s = String::from("{\"event\":\"stream_recipient_transferred\",\"old_recipient\":\"");
        s.push_str(&hex64(&old_recipient));
        s.push_str("\",\"new_recipient\":\"");
        s.push_str(&hex64(&new_recipient));
        s.push_str("\"}");
        s
    }

    /// Renegotiates the rate mid-flight — dual-signed: *both* the
    /// initializer and the recipient must present, so neither side can
    /// reprice the stream alone. Either party absent, or a stranger in
    /// either slot, is [`EscrowError::StreamUnauthorized`] (code 305).
    ///
    /// Only *future* accrual changes: the amount earned under the old
    /// rate is checkpointed at `now` (ungated — see [`Self::earned`])
    /// and never repriced, so `earned(now)` is identical immediately
    /// before and after the change. `total_funded` (set at creation)
    /// still caps everything: a rate increase cannot pay out more than
    /// was funded, it only reaches the cap sooner.
    ///
    /// Check order is authority → state → config: a zero `new_rate`
    /// is [`EscrowError::InvalidStream`] (code 304), as is a rate whose
    /// `new_rate × duration_secs` product does not fit `u64` (the same
    /// fail-closed bound [`Self::create_stream`] enforces). A change
    /// to the current rate is an idempotent no-op (no checkpoint
    /// churn). Allowed while paused — accrual is frozen then, so the
    /// checkpoint is exact and the new rate applies from resume.
    pub fn update_stream_rate(
        &mut self,
        initializer: [u8; 32],
        recipient: [u8; 32],
        new_rate: u64,
        now: u64,
    ) -> Result<(), EscrowError> {
        // Authority first: dual signature — both parties must present.
        if initializer != self.initializer || recipient != self.recipient {
            return Err(EscrowError::StreamUnauthorized);
        }
        self.require_active()?;
        if new_rate == 0 {
            return Err(EscrowError::InvalidStream);
        }
        // Same u64-fit bound as create_stream, on the full duration.
        if (new_rate as u128).saturating_mul(self.duration_secs as u128) > u64::MAX as u128 {
            return Err(EscrowError::InvalidStream);
        }
        if new_rate == self.rate_per_sec {
            return Ok(());
        }
        let acc = self.accruing_seconds(now);
        // Chain from the previous checkpoint: only the seconds since
        // the last change accrue at the old rate. (Using
        // `old_rate × acc` here would reprice the pre-change seconds
        // on every change after the first.)
        let ungated = (self.checkpoint_earned as u128)
            .saturating_add(
                (self.rate_per_sec as u128)
                    .saturating_mul(acc.saturating_sub(self.checkpoint_seconds) as u128),
            )
            .min(self.total_funded as u128) as u64;
        self.checkpoint_earned = ungated;
        self.checkpoint_seconds = acc;
        self.rate_per_sec = new_rate;
        Ok(())
    }

    /// Audit-event JSON for a rate change (hand-written, no serde —
    /// same convention as [`Self::transfer_audit_json`]):
    /// `{"event":"stream_rate_updated","old_rate":10,"new_rate":20,"at":25}`.
    pub fn rate_update_audit_json(old_rate: u64, new_rate: u64, at: u64) -> String {
        let mut s = String::from("{\"event\":\"stream_rate_updated\",\"old_rate\":");
        s.push_str(&old_rate.to_string());
        s.push_str(",\"new_rate\":");
        s.push_str(&new_rate.to_string());
        s.push_str(",\"at\":");
        s.push_str(&at.to_string());
        s.push('}');
        s
    }

    /// Renegotiates the payout cliff mid-flight — dual-signed: *both*
    /// the initializer and the recipient must present, so neither side
    /// can move the first-payout gate alone. Either party absent, or a
    /// stranger in either slot, is [`EscrowError::StreamUnauthorized`]
    /// (code 305).
    ///
    /// Only *future* payouts change: the cliff gates payout, not
    /// accrual, so moving it never reprices anything — the amount
    /// already earned (and any amount already withdrawn) is untouched,
    /// and `earned(now)` simply starts reporting the ungated accrual
    /// from the new `start_ts + cliff_secs` onward. Raising the cliff
    /// past `now` re-gates the stream (a withdraw then returns `0`
    /// until the new cliff elapses, never a negative or a clawback of
    /// what was already withdrawn); lowering it releases the gated
    /// accrual at once. No checkpoint is needed — the checkpoint
    /// stores the *ungated* accrued amount, so a cliff change cannot
    /// erase pre-change accrual the way a rate change could.
    ///
    /// Check order is authority → state → config: the new cliff
    /// reuses the [`Self::create_stream`] gate
    /// (`new_cliff_secs <= duration_secs`, else
    /// [`EscrowError::InvalidStream`] (code 304), the original cliff
    /// untouched). A change to the current cliff is an idempotent
    /// no-op. Allowed while paused — the cliff is a payout gate, not
    /// an accrual input, so the change applies from resume exactly as
    /// [`Self::update_stream_rate`] does.
    pub fn amend_stream_cliff_secs(
        &mut self,
        initializer: [u8; 32],
        recipient: [u8; 32],
        new_cliff_secs: u64,
    ) -> Result<(), EscrowError> {
        // Authority first: dual signature — both parties must present.
        if initializer != self.initializer || recipient != self.recipient {
            return Err(EscrowError::StreamUnauthorized);
        }
        self.require_active()?;
        // Same cliff-vs-duration bound as create_stream.
        if new_cliff_secs > self.duration_secs {
            return Err(EscrowError::InvalidStream);
        }
        if new_cliff_secs == self.cliff_secs {
            return Ok(());
        }
        self.cliff_secs = new_cliff_secs;
        Ok(())
    }

    /// Audit-event JSON for a cliff change (hand-written, no serde —
    /// same convention as [`Self::rate_update_audit_json`]):
    /// `{"event":"stream_cliff_updated","old_cliff_secs":0,"new_cliff_secs":50,"at":25}`.
    pub fn cliff_update_audit_json(old_cliff_secs: u64, new_cliff_secs: u64, at: u64) -> String {
        let mut s = String::from("{\"event\":\"stream_cliff_updated\",\"old_cliff_secs\":");
        s.push_str(&old_cliff_secs.to_string());
        s.push_str(",\"new_cliff_secs\":");
        s.push_str(&new_cliff_secs.to_string());
        s.push_str(",\"at\":");
        s.push_str(&at.to_string());
        s.push('}');
        s
    }

    /// Renegotiates the stream length mid-flight — dual-signed: *both*
    /// the initializer and the recipient must present, so neither side
    /// can move the accrual window alone. Either party absent, or a
    /// stranger in either slot, is [`EscrowError::StreamUnauthorized`]
    /// (code 305).
    ///
    /// Only the window's end moves (`end_ts = start_ts +
    /// duration_secs`): lengthening lets accrual run longer, shortening
    /// caps it earlier. The amount already earned is checkpointed at
    /// `now` (ungated — see [`Self::earned`]) and never repriced or
    /// reduced, so `earned(now)` is identical immediately before and
    /// after the change; shortening the window below the seconds
    /// already accrued freezes the earned amount — it never falls
    /// back, and nothing already withdrawn is clawed back. `earned`
    /// after the change is `checkpoint_earned + rate × max(0,
    /// accruing_seconds(now) − checkpoint_seconds)`, with
    /// `accruing_seconds` capped at the *new* `end_ts`.
    /// `total_funded` (set at creation) still caps everything:
    /// lengthening creates no new funding obligation, shortening
    /// refunds nothing already funded — any on-chain funding
    /// difference is the caller's to settle, the state machine moves
    /// no funds. Rate, start, cliff, withdrawn, and the checkpoint
    /// pair are untouched apart from the freeze above.
    ///
    /// Check order is authority → state → config: a zero
    /// `new_duration_secs` is [`EscrowError::InvalidStream`] (code
    /// 304), as is a new duration shorter than the live `cliff_secs`
    /// (the same bound [`Self::create_stream`] enforces — the cliff
    /// must fit inside the window). A change to the current duration
    /// is an idempotent no-op (no checkpoint churn). Allowed while
    /// paused — accrual is frozen then, so the checkpoint is exact
    /// and the new window applies from resume.
    pub fn amend_stream_duration_secs(
        &mut self,
        initializer: [u8; 32],
        recipient: [u8; 32],
        new_duration_secs: u64,
        now: u64,
    ) -> Result<(), EscrowError> {
        // Authority first: dual signature — both parties must present.
        if initializer != self.initializer || recipient != self.recipient {
            return Err(EscrowError::StreamUnauthorized);
        }
        self.require_active()?;
        if new_duration_secs == 0 || self.cliff_secs > new_duration_secs {
            return Err(EscrowError::InvalidStream);
        }
        if new_duration_secs == self.duration_secs {
            return Ok(());
        }
        // Checkpoint first, exactly like update_stream_rate: freeze
        // the earned amount under the old window so shortening the
        // window can never reduce it. Chain from the previous
        // checkpoint — only the seconds since the last change accrue
        // at the current rate.
        let acc = self.accruing_seconds(now);
        let ungated = (self.checkpoint_earned as u128)
            .saturating_add(
                (self.rate_per_sec as u128)
                    .saturating_mul(acc.saturating_sub(self.checkpoint_seconds) as u128),
            )
            .min(self.total_funded as u128) as u64;
        self.checkpoint_earned = ungated;
        self.checkpoint_seconds = acc;
        self.duration_secs = new_duration_secs;
        Ok(())
    }

    /// Audit-event JSON for a duration change (hand-written, no serde —
    /// same convention as [`Self::cliff_update_audit_json`]):
    /// `{"event":"stream_duration_updated","old_duration_secs":100,"new_duration_secs":200,"at":25}`.
    pub fn duration_update_audit_json(
        old_duration_secs: u64,
        new_duration_secs: u64,
        at: u64,
    ) -> String {
        let mut s = String::from("{\"event\":\"stream_duration_updated\",\"old_duration_secs\":");
        s.push_str(&old_duration_secs.to_string());
        s.push_str(",\"new_duration_secs\":");
        s.push_str(&new_duration_secs.to_string());
        s.push_str(",\"at\":");
        s.push_str(&at.to_string());
        s.push('}');
        s
    }

    /// Renegotiates the stream start time mid-flight — dual-signed:
    /// *both* the initializer and the recipient must present, so
    /// neither side can move the accrual window alone. Either party
    /// absent, or a stranger in either slot, is
    /// [`EscrowError::StreamUnauthorized`] (code 305).
    ///
    /// Only the window's start moves (`end_ts = start_ts +
    /// duration_secs` shifts with it): the window slides, it does
    /// not stretch — `duration_secs` and `total_funded` (`rate ×
    /// duration`, independent of start) never move. Only a stream
    /// that has not started yet may move its start: `now` must be
    /// before the live `start_ts`, and the new start must be after
    /// `now` — a revision only moves a future start moment, it must
    /// not retroactively open the stream by backdating. Changing
    /// the start after accrual began would rewrite accrued history
    /// (`accruing_seconds` / `earned` are both computed from
    /// `start_ts`), so a stream with any accrual or withdrawal
    /// history — a non-`(0, 0)` checkpoint pair or a non-zero
    /// `withdrawn` — is refused outright, fail-closed: that blocks
    /// bypassing the `now < start_ts` gate by pre-setting a
    /// checkpoint with a future `now` and then amending with an
    /// earlier one. No checkpoint is needed for the change itself:
    /// with no history the checkpoint is `(0, 0)` and `earned` /
    /// `stream_withdraw` read the live `start_ts` on every call, so
    /// the new start takes effect from the next evaluation. Rate,
    /// duration, cliff, `total_funded`, `withdrawn`, and the
    /// checkpoint pair are untouched.
    ///
    /// Check order is authority → state → config: `now >= start_ts`
    /// or `new_start_ts <= now` is [`EscrowError::InvalidStream`]
    /// (code 304), the original start untouched, as is any
    /// accrual/withdrawal history. A change to the current start is
    /// an idempotent no-op. Allowed while paused — accrual has not
    /// begun, so the new start applies from resume exactly as
    /// [`Self::amend_stream_duration_secs`] does.
    pub fn amend_stream_start_ts(
        &mut self,
        initializer: [u8; 32],
        recipient: [u8; 32],
        new_start_ts: u64,
        now: u64,
    ) -> Result<(), EscrowError> {
        // Authority first: dual signature — both parties must present.
        if initializer != self.initializer || recipient != self.recipient {
            return Err(EscrowError::StreamUnauthorized);
        }
        self.require_active()?;
        // The stream must not have started yet: `now` before the
        // live start, and the new start after `now` — a revision
        // only moves a future start moment, never backdates it open.
        if now >= self.start_ts || new_start_ts <= now {
            return Err(EscrowError::InvalidStream);
        }
        // Defense gate, fail-closed: any accrual or withdrawal
        // history (a checkpoint set with a future `now`, or funds
        // already withdrawn) means the start is already written
        // into earned history and cannot move.
        if self.checkpoint_earned != 0 || self.checkpoint_seconds != 0 || self.withdrawn != 0 {
            return Err(EscrowError::InvalidStream);
        }
        if new_start_ts == self.start_ts {
            return Ok(());
        }
        self.start_ts = new_start_ts;
        Ok(())
    }

    /// Audit-event JSON for a start change (hand-written, no serde —
    /// same convention as [`Self::duration_update_audit_json`]):
    /// `{"event":"stream_start_updated","old_start_ts":100,"new_start_ts":200,"at":50}`.
    pub fn start_update_audit_json(old_start_ts: u64, new_start_ts: u64, at: u64) -> String {
        let mut s = String::from("{\"event\":\"stream_start_updated\",\"old_start_ts\":");
        s.push_str(&old_start_ts.to_string());
        s.push_str(",\"new_start_ts\":");
        s.push_str(&new_start_ts.to_string());
        s.push_str(",\"at\":");
        s.push_str(&at.to_string());
        s.push('}');
        s
    }

    /// Freezes accrual at `now`. Initializer-only; `pause` on a
    /// paused stream is [`EscrowError::StreamAlreadyPaused`] (307),
    /// `pause` on a terminal stream is
    /// [`EscrowError::StreamNotActive`] (306).
    pub fn pause(&mut self, caller: [u8; 32], now: u64) -> Result<(), EscrowError> {
        if caller != self.initializer {
            return Err(EscrowError::StreamUnauthorized);
        }
        self.require_active()?;
        if self.paused_at.is_some() {
            return Err(EscrowError::StreamAlreadyPaused);
        }
        self.paused_at = Some(now);
        Ok(())
    }

    /// Resumes accrual at `now`: the elapsed pause interval is added
    /// to `paused_total` so it is permanently excluded from accrual.
    /// Initializer-only; `resume` on a stream that is not paused is
    /// [`EscrowError::StreamNotPaused`] (308).
    pub fn resume(&mut self, caller: [u8; 32], now: u64) -> Result<(), EscrowError> {
        if caller != self.initializer {
            return Err(EscrowError::StreamUnauthorized);
        }
        self.require_active()?;
        let paused_at = match self.paused_at {
            Some(ts) => ts,
            None => return Err(EscrowError::StreamNotPaused),
        };
        self.paused_total = self.paused_total.saturating_add(now.saturating_sub(paused_at));
        self.paused_at = None;
        Ok(())
    }

    /// Whether the stream is currently paused.
    pub fn is_paused(&self) -> bool {
        self.paused_at.is_some()
    }

    /// Funder key.
    pub fn initializer(&self) -> [u8; 32] {
        self.initializer
    }

    /// Payee key.
    pub fn recipient(&self) -> [u8; 32] {
        self.recipient
    }

    /// Per-second rate.
    pub fn rate_per_sec(&self) -> u64 {
        self.rate_per_sec
    }

    /// Accrual start timestamp.
    pub fn start_ts(&self) -> u64 {
        self.start_ts
    }

    /// Stream length in seconds.
    pub fn duration_secs(&self) -> u64 {
        self.duration_secs
    }

    /// Payout gate in seconds from `start_ts`.
    pub fn cliff_secs(&self) -> u64 {
        self.cliff_secs
    }

    /// Total funded by the initializer.
    pub fn total_funded(&self) -> u64 {
        self.total_funded
    }

    /// Amount already withdrawn.
    pub fn withdrawn(&self) -> u64 {
        self.withdrawn
    }

    /// Seconds spent paused across completed intervals.
    pub fn paused_total(&self) -> u64 {
        self.paused_total
    }

    /// Lifecycle state.
    pub fn state(&self) -> StreamState {
        self.state
    }
}

/// 32-byte key to lowercase hex (64 chars) — private helper for the
/// hand-written audit JSON above, same shape as the other modules.
fn hex64(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}
