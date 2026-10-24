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
//! Orthogonal to AV-13 vesting (one lump sum that unlocks whole at
//! expiry — the release is a single gate) and to AV-197 bidirectional
//! channels (both parties co-sign off-chain state): here the release is
//! *continuous* per-second and unilateral. Orthogonal to AV-190 rental
//! escrow (day-granularity rent tranches): the stream accrues at
//! second granularity and has no tranches. `Copy`, heap-free,
//! `no_std`-friendly.

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

    /// Amount earned as of `now`: `rate_per_sec × accruing_seconds`,
    /// computed in `u128` (cannot overflow) and capped at
    /// `total_funded`.
    ///
    /// Reports `0` before `start_ts + cliff_secs` — the cliff gates
    /// payout, it does not consume the stream: accrual itself runs
    /// from `start_ts`.
    pub fn earned(&self, now: u64) -> u64 {
        if now < self.start_ts.saturating_add(self.cliff_secs) {
            return 0;
        }
        let elapsed = self.accruing_seconds(now) as u128;
        let earned = (self.rate_per_sec as u128).saturating_mul(elapsed);
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
