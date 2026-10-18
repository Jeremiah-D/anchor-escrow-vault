//! AV-101: keeper report signatures — the signing envelope.
//!
//! Keeper reports ([`KeeperReport`], [`CloseReport`],
//! [`MilestoneReport`], [`StaleVaultReport`], [`BatchReport`],
//! [`ExecutionBundle`], [`EscrowAggregateView`]) are consumed by
//! offline signers (multisig CLIs, keeper operators). A report that
//! was tampered with after the scan must not verify.
//!
//! Every report type already serializes to canonical deterministic
//! JSON via its `to_json()` (hand-rolled, fixed field order — the
//! crate is dependency-free). This module signs exactly those bytes:
//!
//! - [`sign_report_json`] / [`verify_report_json`]: the raw
//!   primitive over canonical report JSON.
//! - [`signed_report_json`] / [`verify_signed_report_json`]: the
//!   self-contained envelope
//!   `{"report":<canonical>,"signature":{"public_key":"…","signature":"…"}}`
//!   a keeper hands to the signer, and the offline check the signer
//!   runs before submitting.
//! - [`SignableReport`]: the uniform opt-in surface —
//!   `report.to_signed_json(&key)` — implemented for all seven keeper
//!   report types.
//!
//! Opt-in by construction: without a [`SigningKey`] the reports
//! serialize exactly as before (unsigned `to_json()` output is
//! byte-identical); signing only ever *wraps* the canonical bytes.
//! The signature covers the canonical JSON, never the envelope, so a
//! verifier needs no JSON parser — [`verify_signed_report_json`]
//! splits the envelope by its fixed layout (see the constants below).

use super::ed25519::{verify as ed25519_verify, SigningKey};
use super::{
    aggregate::EscrowAggregateView, batch::BatchReport, execution_bundle::ExecutionBundle,
    keeper::CloseReport, keeper::KeeperReport, keeper::MilestoneReport, keeper::StaleVaultReport,
};

// ---------------------------------------------------------------------------
// Envelope layout.
// ---------------------------------------------------------------------------

/// `{"report":` — the envelope prefix.
const ENVELOPE_PREFIX: &str = "{\"report\":";
/// `,"signature":{"public_key":"` — between the canonical report and
/// the hex public key.
const ENVELOPE_MID1: &str = ",\"signature\":{\"public_key\":\"";
/// `","signature":"` — between the hex public key and the hex signature.
const ENVELOPE_MID2: &str = "\",\"signature\":\"";
/// `}}` — closes the signature object and the envelope.
const ENVELOPE_SUFFIX: &str = "}}";

/// A detached Ed25519 signature over a report's canonical JSON.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportSignature {
    /// The keeper's 32-byte public key (so verifiers can pin it).
    pub public_key: [u8; 32],
    /// The 64-byte Ed25519 signature over the canonical report JSON.
    pub signature: [u8; 64],
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

fn hex_decode_32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

fn hex_decode_64(s: &str) -> Option<[u8; 64]> {
    if s.len() != 128 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 64];
    for i in 0..64 {
        out[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

/// Sign a report's canonical JSON (`to_json()` output) with the
/// keeper's key. The signature covers exactly these bytes.
pub fn sign_report_json(canonical_json: &str, key: &SigningKey) -> ReportSignature {
    ReportSignature {
        public_key: key.public_key(),
        signature: key.sign(canonical_json.as_bytes()),
    }
}

/// Verify a detached [`ReportSignature`] against canonical report JSON.
/// `false` on any mismatch — including a tampered report.
pub fn verify_report_json(canonical_json: &str, sig: &ReportSignature) -> bool {
    ed25519_verify(
        &sig.public_key,
        canonical_json.as_bytes(),
        &sig.signature,
    )
}

/// Wrap canonical report JSON in the signed envelope:
/// `{"report":<canonical>,"signature":{"public_key":"…","signature":"…"}}`.
/// The canonical bytes are embedded verbatim — the unsigned
/// `to_json()` output is a substring of the signed envelope.
pub fn signed_report_json(canonical_json: &str, key: &SigningKey) -> String {
    let sig = sign_report_json(canonical_json, key);
    let mut s = String::with_capacity(
        ENVELOPE_PREFIX.len()
            + canonical_json.len()
            + ENVELOPE_MID1.len()
            + 64
            + ENVELOPE_MID2.len()
            + 128
            + ENVELOPE_SUFFIX.len(),
    );
    s.push_str(ENVELOPE_PREFIX);
    s.push_str(canonical_json);
    s.push_str(ENVELOPE_MID1);
    s.push_str(&hex_encode(&sig.public_key));
    s.push_str(ENVELOPE_MID2);
    s.push_str(&hex_encode(&sig.signature));
    s.push_str(ENVELOPE_SUFFIX);
    s
}

/// Split a signed envelope into `(canonical_report_json, signature)`.
/// Strict: the envelope must start with [`ENVELOPE_PREFIX`], end with
/// [`ENVELOPE_SUFFIX`], and carry both literal mid markers at their
/// exact offsets; anything else is `None` (never panics).
pub fn split_signed_report_json(envelope: &str) -> Option<(&str, ReportSignature)> {
    let tail_len = ENVELOPE_MID1.len() + 64 + ENVELOPE_MID2.len() + 128 + ENVELOPE_SUFFIX.len();
    if !envelope.starts_with(ENVELOPE_PREFIX)
        || !envelope.ends_with(ENVELOPE_SUFFIX)
        || envelope.len() < ENVELOPE_PREFIX.len() + tail_len
    {
        return None;
    }
    let body_start = ENVELOPE_PREFIX.len();
    let body_end = envelope.len() - tail_len;
    let mid1_at = body_end;
    let pk_at = mid1_at + ENVELOPE_MID1.len();
    let mid2_at = pk_at + 64;
    let sig_at = mid2_at + ENVELOPE_MID2.len();
    if &envelope[mid1_at..pk_at] != ENVELOPE_MID1
        || &envelope[mid2_at..sig_at] != ENVELOPE_MID2
    {
        return None;
    }
    let public_key = hex_decode_32(&envelope[pk_at..mid2_at])?;
    let signature = hex_decode_64(&envelope[sig_at..sig_at + 128])?;
    Some((
        &envelope[body_start..body_end],
        ReportSignature {
            public_key,
            signature,
        },
    ))
}

/// Verify a signed envelope end-to-end: split it, then verify the
/// signature over the embedded canonical report JSON. `false` on any
/// malformed envelope or any tampering.
pub fn verify_signed_report_json(envelope: &str) -> bool {
    match split_signed_report_json(envelope) {
        Some((canonical, sig)) => verify_report_json(canonical, &sig),
        None => false,
    }
}

// ---------------------------------------------------------------------------
// The uniform opt-in surface for all keeper report types.
// ---------------------------------------------------------------------------

/// Uniform opt-in signing for every keeper report type:
/// `report.to_signed_json(&key)` wraps the type's canonical
/// `to_json()` in the signed envelope. Without a key, `to_json()`
/// stays byte-identical (unsigned, backward compatible).
pub trait SignableReport {
    /// The canonical JSON this signature covers (the unsigned
    /// `to_json()` output, verbatim).
    fn canonical_json(&self) -> String;

    /// The signed envelope (see [`signed_report_json`]).
    fn to_signed_json(&self, key: &SigningKey) -> String {
        signed_report_json(&self.canonical_json(), key)
    }
}

impl SignableReport for KeeperReport {
    fn canonical_json(&self) -> String {
        self.to_json()
    }
}

impl SignableReport for CloseReport {
    fn canonical_json(&self) -> String {
        self.to_json()
    }
}

impl SignableReport for MilestoneReport {
    fn canonical_json(&self) -> String {
        self.to_json()
    }
}

impl SignableReport for StaleVaultReport {
    fn canonical_json(&self) -> String {
        self.to_json()
    }
}

impl SignableReport for BatchReport {
    fn canonical_json(&self) -> String {
        self.to_json()
    }
}

impl SignableReport for ExecutionBundle {
    fn canonical_json(&self) -> String {
        self.to_json()
    }
}

impl SignableReport for EscrowAggregateView {
    fn canonical_json(&self) -> String {
        self.to_json()
    }
}

#[cfg(test)]
mod report_signing_tests {
    use super::*;
    use crate::{
        batch::{BatchInitializeParams, BatchWatchItem},
        keeper::WatchedEscrow,
        Escrow, EscrowState,
    };

    fn test_key() -> SigningKey {
        // Fixed test seed — never a real key.
        SigningKey::from_seed([0x42; 32])
    }

    fn watch(id: u8, escrow: Escrow) -> WatchedEscrow {
        WatchedEscrow {
            escrow_id: [id; 32],
            escrow,
            reference: None,
            vault_derivation: None,
            pending_intent: None,
        }
    }
    fn funded_escrow() -> Escrow {
        let mut e = Escrow::initialize([0x11; 32], [0x22; 32], 1_000_000, u64::MAX).unwrap();
        e.fund([0x11; 32], 1_000).unwrap();
        e
    }

    #[test]
    fn envelope_layout_is_verbatim_canonical_plus_signature() {
        let key = test_key();
        let report = crate::keeper::scan_keeper_actions(&[], 1_000);
        let canonical = report.to_json();
        let envelope = report.to_signed_json(&key);
        // The canonical bytes are embedded verbatim.
        assert!(envelope.starts_with("{\"report\":"));
        assert!(envelope.contains(&canonical));
        assert!(envelope.ends_with("}}"));
        // Unsigned output is untouched by the signing feature.
        // AV-120: the stamped report sequence rides the canonical
        // bytes (`null` when the operator stamped nothing).
        // AV-123: the gasless-intent annotations ride the canonical
        // bytes (`[]` when no watched escrow carries an intent).
        // AV-133: the pending auto-unpause vaults ride the canonical
        // bytes (`[]` when none are armed).
        assert_eq!(canonical, "{\"at\":1000,\"scanned\":0,\"total_estimated_cu\":0,\"jito_tip\":null,\"intent_releases\":[],\"pool_balance\":0,\"pool_inflow\":0,\"pool_outflow\":0,\"actions\":[],\"report_seq\":null,\"pending_auto_unpause\":[]}");
    }

    #[test]
    fn split_round_trips_and_verifies() {
        let key = test_key();
        let report = crate::keeper::scan_keeper_actions(&[], 1_000);
        let envelope = report.to_signed_json(&key);
        let (canonical, sig) = split_signed_report_json(&envelope).expect("splits");
        assert_eq!(canonical, report.to_json());
        assert_eq!(sig.public_key, key.public_key());
        assert!(verify_report_json(canonical, &sig));
        assert!(verify_signed_report_json(&envelope));
    }

    #[test]
    fn tampered_report_fails_verification() {
        let key = test_key();
        let watched = vec![watch(0x01, funded_escrow())];
        let report = crate::keeper::scan_keeper_actions(&watched, 1_000);
        let envelope = report.to_signed_json(&key);
        assert!(verify_signed_report_json(&envelope));
        // Flip one byte inside the canonical report region.
        let mut tampered = envelope.clone();
        let pos = tampered.find("\"scanned\"").unwrap() + 10;
        let b = tampered.as_bytes()[pos];
        tampered.replace_range(pos..pos + 1, if b == b'1' { "2" } else { "1" });
        assert!(!verify_signed_report_json(&tampered));
        // The split still works (layout intact) but the signature fails.
        let (canonical, sig) = split_signed_report_json(&tampered).unwrap();
        assert!(!verify_report_json(canonical, &sig));
    }

    #[test]
    fn tampered_signature_fails_verification() {
        let key = test_key();
        let report = crate::keeper::scan_keeper_actions(&[], 1_000);
        let mut envelope = report.to_signed_json(&key);
        // Flip a hex digit inside the signature (not the report).
        let sig_pos = envelope.rfind("\"signature\":\"").unwrap() + 13;
        let b = envelope.as_bytes()[sig_pos];
        envelope.replace_range(
            sig_pos..sig_pos + 1,
            if b == b'0' { "1" } else { "0" },
        );
        assert!(!verify_signed_report_json(&envelope));
    }

    #[test]
    fn wrong_key_fails_verification() {
        let key = test_key();
        let other = SigningKey::from_seed([0x99; 32]);
        let report = crate::keeper::scan_keeper_actions(&[], 1_000);
        let envelope = report.to_signed_json(&key);
        let (canonical, sig) = split_signed_report_json(&envelope).unwrap();
        assert!(verify_report_json(canonical, &sig));
        // Same canonical bytes, signature made by another key.
        let forged = ReportSignature {
            public_key: other.public_key(),
            signature: sig.signature,
        };
        assert!(!verify_report_json(canonical, &forged));
    }

    #[test]
    fn malformed_envelopes_are_rejected_without_panic() {
        assert!(!verify_signed_report_json(""));
        assert!(!verify_signed_report_json("{\"report\":{}}"));
        assert!(!verify_signed_report_json("{\"report\":{},\"signature\":{}}"));
        // Truncated signature hex.
        let key = test_key();
        let report = crate::keeper::scan_keeper_actions(&[], 1_000);
        let envelope = report.to_signed_json(&key);
        assert!(!verify_signed_report_json(&envelope[..envelope.len() - 10]));
        // Non-hex public key.
        let mut bad = envelope.clone();
        let pk_pos = bad.find("\"public_key\":\"").unwrap() + 14;
        bad.replace_range(pk_pos..pk_pos + 2, "zz");
        assert!(!verify_signed_report_json(&bad));
    }

    #[test]
    fn all_report_types_sign_and_verify() {
        let key = test_key();
        let watched = vec![watch(0x01, funded_escrow())];

        let r1 = crate::keeper::scan_keeper_actions(&watched, 1_000);
        assert!(verify_signed_report_json(&r1.to_signed_json(&key)));

        let r2 = crate::keeper::scan_closeable(&watched);
        assert!(verify_signed_report_json(&r2.to_signed_json(&key)));

        let r3 = crate::keeper::scan_milestones(&watched, 1_000);
        assert!(verify_signed_report_json(&r3.to_signed_json(&key)));

        // StaleVaultReport needs WatchedEscrowWithBalance; an empty
        // scan still produces a well-formed (empty) report.
        let r4 = crate::keeper::scan_stale_vaults(&[]);
        assert!(verify_signed_report_json(&r4.to_signed_json(&key)));

        let batch_items = vec![BatchWatchItem {
            escrow_id: [0x05; 32],
            escrow: None,
            initialize: BatchInitializeParams {
                initializer: [0x11; 32],
                taker: [0x22; 32],
                amount: 1_000_000,
                expires_at: u64::MAX,
            },
            vault_derivation: None,
        }];
        let r5 = crate::batch::scan_batch_lifecycle(&batch_items, 1_000);
        assert!(verify_signed_report_json(&r5.to_signed_json(&key)));

        let bundles = crate::execution_bundle::bundle_execution(&r5);
        assert!(!bundles.is_empty());
        assert!(verify_signed_report_json(&bundles[0].to_signed_json(&key)));

        let r7 = crate::keeper::scan_aggregate_view(&watched, 1_000);
        assert!(verify_signed_report_json(&r7.to_signed_json(&key)));
    }

    #[test]
    fn detached_sign_verify_primitive() {
        let key = test_key();
        let json = "{\"hello\":\"world\"}";
        let sig = sign_report_json(json, &key);
        assert!(verify_report_json(json, &sig));
        assert!(!verify_report_json("{\"hello\":\"mars\"}", &sig));
        assert_eq!(sig.public_key, key.public_key());
    }

    #[test]
    fn signing_is_deterministic_per_report() {
        let key = test_key();
        let report = crate::keeper::scan_keeper_actions(&[], 1_000);
        assert_eq!(
            report.to_signed_json(&key),
            report.to_signed_json(&key)
        );
    }

    #[test]
    fn escrow_state_link_check() {
        // Keeps the EscrowState import used if refactors drop it.
        assert_eq!(format!("{:?}", EscrowState::Funded), "Funded");
    }
}
