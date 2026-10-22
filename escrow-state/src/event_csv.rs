//! Deterministic indexer-event CSV export (AV-74).
//!
//! [`events_to_csv`] renders a slice of [`EscrowEvent`] as RFC 4180
//! CSV — the data-analysis / audit-ingest complement to the AV-26
//! snapshot JSON export ([`crate::EscrowSnapshot::to_json`]): one row
//! per event, fixed column order, a header row, LF line endings, and a
//! hand-written escaper (the crate stays dependency-free).
//!
//! # Columns
//!
//! ```text
//! kind,seq,at,actor,payout,fee,refund,penalty,rent_reclaimed,arbiter_fee
//! ```
//!
//! - `kind` — the canonical snake_case [`EscrowEventKind::name`].
//! - `seq`, `at` — decimal `u64`.
//! - `actor` — see "Actor provenance" below.
//! - `payout`, `fee`, `refund`, `penalty`, `rent_reclaimed`,
//!   `arbiter_fee` — [`EventAmounts`] expanded, decimal `u64`
//!   (AV-135: the arbiter adjudication fee column; 0 on every kind
//!   but the dispute settlements).
//!
//! # Actor provenance
//!
//! [`EscrowEvent`] carries no dedicated actor field, and the log never
//! invents one: the only per-escrow identity every event carries is
//! [`EscrowEvent::escrow_id`] (32 bytes; on-chain, the vault PDA public
//! key). The `actor` column is that identity rendered as 64 lowercase
//! hex characters (the same convention as the snapshot serializer), so
//! the column answers "which escrow did this event come from", not
//! "who signed this transition".
//!
//! # A projection, not a full serialization
//!
//! The CSV carries only the nine columns above. `from` / `to`,
//! `evidence_hash`, `rationale_hash`, `cpi`, `caller`, `reference`,
//! `template_params_hash`, `evidence_defaulted`,
//! `bounty_pool_remaining` and `slash_ladder_index` are *not* exported.
//! [`csv_to_events`] reconstructs the carried fields exactly and fills
//! the rest with documented zero-values: `from == to == Uninitialized`
//! (the explicit "not carried by this projection" marker — the event's
//! real states are available from the typed log), `None` for every
//! optional field, `false` for `evidence_defaulted`.
//!
//! # Round-trip contract
//!
//! `events_to_csv(csv_to_events(csv))` is byte-identical to `csv` for
//! any `csv` this module emitted, and `csv_to_events` re-emits to the
//! same bytes: the parse is canonical. The parser is line-oriented and
//! never panics — every malformed input maps to a precise
//! [`CsvError`]. CRLF line endings are tolerated on import (one `\r`
//! stripped per line); export always writes LF.
//!
//! The escaper quotes any field containing `,`, `"`, `\n` or `\r` and
//! doubles inner quotes (RFC 4180 §2.7). Today's fields never need it
//! (snake_case kinds, decimal integers, lowercase hex), but the format
//! layer implements it so the exporter stays correct if a field
//! alphabet ever widens.

use crate::{EscrowEvent, EscrowEventKind, EscrowState, EventAmounts};

/// The exact header row [`events_to_csv`] writes and
/// [`csv_to_events`] requires.
const HEADER: &str =
    "kind,seq,at,actor,payout,fee,refund,penalty,rent_reclaimed,arbiter_fee";

/// Expected column count per record row.
// AV-135: the arbiter_fee column joined the export.
const COLUMN_COUNT: usize = 10;

/// Errors [`csv_to_events`] can return. Line numbers are 1-based; the
/// header is line 1, the first record line 2. The parser never panics —
/// every malformed input maps to one of these variants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CsvError {
    /// The input has no lines at all (empty string) — there is nothing
    /// to check the header against.
    MissingHeader,
    /// Line 1 is not the exact [`HEADER`] row.
    UnexpectedHeader {
        /// The offending first line, verbatim.
        got: String,
    },
    /// A record row does not carry exactly [`COLUMN_COUNT`] fields.
    BadFieldCount {
        line: usize,
        expected: usize,
        got: usize,
    },
    /// The `kind` column is not a known [`EscrowEventKind::name`].
    UnknownKind { line: usize, value: String },
    /// A `seq` / `at` / amount column is not a decimal `u64`.
    InvalidInt {
        line: usize,
        column: &'static str,
        value: String,
    },
    /// The `actor` column is not 64 hex characters.
    InvalidActorHex { line: usize, value: String },
    /// A quoted field never closes on its line.
    UnterminatedQuote { line: usize },
    /// Characters other than `,` follow a quoted field's closing quote.
    TrailingCharsAfterQuote { line: usize },
}

/// Render `events` as deterministic CSV: the [`HEADER`] row, then one
/// record row per event in slice order, LF-terminated lines. The same
/// input always produces byte-identical output.
pub fn events_to_csv(events: &[EscrowEvent]) -> String {
    let mut out = String::new();
    out.push_str(HEADER);
    out.push('\n');
    for event in events {
        let a = &event.amounts;
        push_field(&mut out, event.kind.name());
        out.push(',');
        push_u64(&mut out, event.seq);
        out.push(',');
        push_u64(&mut out, event.at);
        out.push(',');
        push_field(&mut out, &hex32(&event.escrow_id));
        out.push(',');
        push_u64(&mut out, a.payout);
        out.push(',');
        push_u64(&mut out, a.fee);
        out.push(',');
        push_u64(&mut out, a.refund);
        out.push(',');
        push_u64(&mut out, a.penalty);
        out.push(',');
        push_u64(&mut out, a.rent_reclaimed);
        out.push(',');
        // AV-135: the arbiter adjudication fee leg of the settlement
        // (0 on every other kind).
        push_u64(&mut out, a.arbiter_fee);
        out.push('\n');
    }
    out
}

/// Parse CSV previously written by [`events_to_csv`] back into events.
///
/// The carried fields (`kind`, `seq`, `at`, `actor` → `escrow_id`,
/// the five amounts) round-trip exactly; see the module docs for what
/// the projection does not carry and the zero-values those fields get.
pub fn csv_to_events(csv: &str) -> Result<Vec<EscrowEvent>, CsvError> {
    // Split into lines, dropping the single empty piece a trailing
    // newline leaves behind; every other line must be a real record.
    let raw: Vec<&str> = csv.split('\n').collect();
    let mut end = raw.len();
    if end > 0 && raw[end - 1].is_empty() {
        end -= 1;
    }
    let lines = &raw[..end];
    if lines.is_empty() {
        return Err(CsvError::MissingHeader);
    }
    let header = strip_cr(lines[0]);
    if header != HEADER {
        return Err(CsvError::UnexpectedHeader {
            got: header.to_string(),
        });
    }
    let mut events = Vec::with_capacity(lines.len().saturating_sub(1));
    for (i, raw_line) in lines.iter().enumerate().skip(1) {
        // 1-based line number; the header is line 1.
        let line_no = i + 1;
        let fields = parse_line(strip_cr(raw_line), line_no)?;
        if fields.len() != COLUMN_COUNT {
            return Err(CsvError::BadFieldCount {
                line: line_no,
                expected: COLUMN_COUNT,
                got: fields.len(),
            });
        }
        let kind = EscrowEventKind::from_name(&fields[0]).ok_or_else(|| CsvError::UnknownKind {
            line: line_no,
            value: fields[0].clone(),
        })?;
        let seq = parse_u64(&fields[1], line_no, "seq")?;
        let at = parse_u64(&fields[2], line_no, "at")?;
        let escrow_id = dehex32(&fields[3]).ok_or_else(|| CsvError::InvalidActorHex {
            line: line_no,
            value: fields[3].clone(),
        })?;
        let payout = parse_u64(&fields[4], line_no, "payout")?;
        let fee = parse_u64(&fields[5], line_no, "fee")?;
        let refund = parse_u64(&fields[6], line_no, "refund")?;
        let penalty = parse_u64(&fields[7], line_no, "penalty")?;
        let rent_reclaimed = parse_u64(&fields[8], line_no, "rent_reclaimed")?;
        // AV-135: the arbiter-fee column — appended, so older readers
        // stop at rent_reclaimed.
        let arbiter_fee = parse_u64(&fields[9], line_no, "arbiter_fee")?;
        // The CSV is a projection: only the ten columns round-trip.
        // Non-carried fields take documented zero-values — `from`/`to`
        // are the explicit "not carried" marker, never inferred.
        events.push(EscrowEvent {
            kind,
            escrow_id,
            seq,
            from: EscrowState::Uninitialized,
            to: EscrowState::Uninitialized,
            amounts: EventAmounts {
                payout,
                fee,
                refund,
                penalty,
                rent_reclaimed,
                arbiter_fee,
            },
            at,
            evidence_hash: None,
            evidence_defaulted: false,
            rationale_hash: None,
            cpi: None,
            caller: None,
            reference: None,
            template_params_hash: None,
            // AV-81: the split roster is not carried by the CSV
            // projection — like the other non-carried fields it takes
            // its documented zero-value on import.
            split_children: None,
            // AV-85: the migration step's versions are not carried by
            // the CSV projection either — `None` on import, like the
            // other kind-specific extras.
            schema_versions: None,
            // AV-86: the appeal verdict is not carried by the CSV
            // projection either — `None` on import, like the other
            // kind-specific extras.
            appeal_outcome: None,
            // AV-91: the evidence Merkle root and disclosure progress
            // are not carried by the CSV projection either — `None`
            // on import, like the other kind-specific extras.
            evidence_root: None,
            evidence_disclosure: None,
            // AV-93: the split legs are not carried by the CSV
            // projection either — `None` on import, like the other
            // kind-specific extras.
            release_split: None,
            // AV-124: the post-debit bounty pool is not carried by
            // the CSV projection either — `None` on import, like the
            // other kind-specific extras.
            bounty_pool_remaining: None,
            // AV-126: the consumed slash-ladder rung is not carried by
            // the CSV projection either — `None` on import, like the
            // other kind-specific extras.
            slash_ladder_index: None,
            auto_unpause: false,
            // AV-182: the memo note is not carried by the CSV
            // projection either — `None` on import, like the other
            // kind-specific extras.
            memo: None,
        });
    }
    Ok(events)
}

/// Strip the one trailing `\r` a CRLF line ending leaves behind.
/// Export always writes LF; import tolerates CRLF.
fn strip_cr(line: &str) -> &str {
    line.strip_suffix('\r').unwrap_or(line)
}

/// Append one CSV field with RFC 4180 §2.7 escaping: a field
/// containing `,`, `"`, `\n` or `\r` is wrapped in quotes and every
/// inner quote is doubled. Pure function of the input — deterministic.
fn push_field(out: &mut String, field: &str) {
    let needs_quote = field
        .chars()
        .any(|c| matches!(c, ',' | '"' | '\n' | '\r'));
    if !needs_quote {
        out.push_str(field);
        return;
    }
    out.push('"');
    for c in field.chars() {
        if c == '"' {
            out.push('"');
        }
        out.push(c);
    }
    out.push('"');
}

/// Append a `u64` as canonical decimal (no padding, no separators).
fn push_u64(out: &mut String, n: u64) {
    // `u64::to_string` is allocation-light here via the `String`
    // buffer: one canonical form, so equal numbers render equal bytes.
    out.push_str(&n.to_string());
}

/// Render 32 bytes as 64 lowercase hex characters — the same
/// convention as the snapshot serializer.
fn hex32(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// Decode 64 hex characters (either case) into 32 bytes. `None` on a
/// wrong length or a non-hex character.
fn dehex32(s: &str) -> Option<[u8; 32]> {
    fn nibble(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }
    let bytes = s.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = nibble(bytes[2 * i])? << 4 | nibble(bytes[2 * i + 1])?;
    }
    Some(out)
}

/// Parse one decimal `u64` column, tagging parse failures with the
/// line and the column name.
fn parse_u64(s: &str, line: usize, column: &'static str) -> Result<u64, CsvError> {
    s.parse::<u64>().map_err(|_| CsvError::InvalidInt {
        line,
        column,
        value: s.to_string(),
    })
}

/// Split one record line into fields, honoring RFC 4180 quoted
/// fields (doubled quotes unescape to one). The parser is
/// line-oriented: it never crosses a `\n`, and never panics.
fn parse_line(line: &str, line_no: usize) -> Result<Vec<String>, CsvError> {
    #[derive(PartialEq)]
    enum State {
        /// At the start of a field (or the line): `"` opens quoting,
        /// `,` ends an empty field.
        FieldStart,
        /// Inside an unquoted field.
        InBare,
        /// Inside a `"…"` quoted field.
        InQuoted,
        /// Just after a quoted field's closing quote: only `,` or
        /// end-of-line may follow.
        AfterQuoted,
    }

    let mut fields = Vec::new();
    let mut field = String::new();
    let mut state = State::FieldStart;
    let mut chars = line.chars().peekable();

    while let Some(c) = chars.next() {
        match state {
            State::FieldStart => match c {
                '"' => state = State::InQuoted,
                ',' => fields.push(std::mem::take(&mut field)),
                _ => {
                    field.push(c);
                    state = State::InBare;
                }
            },
            State::InBare => match c {
                ',' => {
                    fields.push(std::mem::take(&mut field));
                    state = State::FieldStart;
                }
                '"' => return Err(CsvError::TrailingCharsAfterQuote { line: line_no }),
                _ => field.push(c),
            },
            State::InQuoted => {
                if c == '"' {
                    if chars.peek() == Some(&'"') {
                        // Doubled quote: one literal quote.
                        field.push('"');
                        chars.next();
                    } else {
                        state = State::AfterQuoted;
                    }
                } else {
                    field.push(c);
                }
            }
            State::AfterQuoted => match c {
                ',' => {
                    fields.push(std::mem::take(&mut field));
                    state = State::FieldStart;
                }
                _ => return Err(CsvError::TrailingCharsAfterQuote { line: line_no }),
            },
        }
    }

    match state {
        State::InQuoted => Err(CsvError::UnterminatedQuote { line: line_no }),
        _ => {
            fields.push(field);
            Ok(fields)
        }
    }
}

#[cfg(test)]
mod event_csv_tests {
    use super::*;
    use crate::IndexedEscrow;

    const ALICE: [u8; 32] = [0xAA; 32];
    const BOB: [u8; 32] = [0xBB; 32];
    const ESCROW_ID: [u8; 32] = [0x1D; 32];
    const EXPIRES_AT: u64 = 1_800_000_000;
    const T0: u64 = 1_700_000_000;
    const ACTOR_HEX: &str = "1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d";

    fn initialized_events() -> Vec<EscrowEvent> {
        IndexedEscrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT, ESCROW_ID, T0)
            .unwrap()
            .drain_events()
    }

    /// `Initialized` → `Funded` → partial `Released` (4_000 lamport
    /// fee on the 400_000 gross at 100 bps): a multi-kind,
    /// multi-amount stream for the round-trip tests.
    fn flow_events() -> Vec<EscrowEvent> {        let mut e = IndexedEscrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT, ESCROW_ID, T0)
            .unwrap()
            .with_protocol_fee(100)
            .unwrap();
        e.fund(ALICE, T0 + 1).unwrap();
        e.release(ALICE, 400_000, None, BOB, T0 + 2).unwrap();
        e.drain_events()
    }

    #[test]
    fn header_and_single_event_are_byte_pinned() {
        let csv = events_to_csv(&initialized_events());
        let expected = format!(
            "kind,seq,at,actor,payout,fee,refund,penalty,rent_reclaimed,arbiter_fee\n\
             initialized,0,{T0},{ACTOR_HEX},0,0,0,0,0,0\n"
        );
        assert_eq!(csv, expected);
    }

    #[test]
    fn empty_slice_exports_header_only() {
        assert_eq!(
            events_to_csv(&[]),
            "kind,seq,at,actor,payout,fee,refund,penalty,rent_reclaimed,arbiter_fee\n"
        );
        assert_eq!(csv_to_events("kind,seq,at,actor,payout,fee,refund,penalty,rent_reclaimed,arbiter_fee\n").unwrap(), vec![]);
    }

    #[test]
    fn escape_field_boundaries() {
        // Plain fields pass through untouched.
        let mut out = String::new();
        push_field(&mut out, "released");
        assert_eq!(out, "released");
        // Comma, quote, newline, carriage return each force quoting;
        // inner quotes double.
        let mut out = String::new();
        push_field(&mut out, "a,b");
        assert_eq!(out, "\"a,b\"");
        let mut out = String::new();
        push_field(&mut out, "say \"hi\"");
        assert_eq!(out, "\"say \"\"hi\"\"\"");
        let mut out = String::new();
        push_field(&mut out, "line1\nline2");
        assert_eq!(out, "\"line1\nline2\"");
        let mut out = String::new();
        push_field(&mut out, "cr\rlf");
        assert_eq!(out, "\"cr\rlf\"");
        // The empty field stays empty and unquoted.
        let mut out = String::new();
        push_field(&mut out, "");
        assert_eq!(out, "");
    }

    #[test]
    fn parse_line_handles_quoted_fields() {
        let fields = parse_line("a,\"b,c\",\"d\"\"e\",\"f\",", 2).unwrap();
        assert_eq!(fields, vec!["a", "b,c", "d\"e", "f", ""]);
        let fields = parse_line("\"\",x", 2).unwrap();
        assert_eq!(fields, vec!["", "x"]);
    }

    #[test]
    fn parse_line_rejects_malformed_quoting() {
        assert_eq!(
            parse_line("\"abc", 3),
            Err(CsvError::UnterminatedQuote { line: 3 })
        );
        assert_eq!(
            parse_line("\"a\"x,b", 3),
            Err(CsvError::TrailingCharsAfterQuote { line: 3 })
        );
        assert_eq!(
            parse_line("a\"b,c", 3),
            Err(CsvError::TrailingCharsAfterQuote { line: 3 })
        );
    }

    #[test]
    fn multi_event_round_trip_is_byte_identical() {
        let events = flow_events();
        assert_eq!(events.len(), 3);
        let csv = events_to_csv(&events);
        let parsed = csv_to_events(&csv).unwrap();
        // Carried fields come back exactly.
        assert_eq!(parsed.len(), 3);
        for (original, back) in events.iter().zip(parsed.iter()) {
            assert_eq!(back.kind, original.kind);
            assert_eq!(back.seq, original.seq);
            assert_eq!(back.at, original.at);
            assert_eq!(back.escrow_id, original.escrow_id);
            assert_eq!(back.escrow_id, ESCROW_ID);
            assert_eq!(back.amounts, original.amounts);
        }
        // The release row carries the fee split.
        let released = &parsed[2];
        assert_eq!(released.kind, EscrowEventKind::Released);
        assert_eq!(released.seq, 2);
        assert_eq!(released.at, T0 + 2);
        assert_eq!(
            released.amounts,
            EventAmounts {
                payout: 400_000,
                fee: 4_000,
                refund: 0,
                penalty: 0,
                rent_reclaimed: 0,
                arbiter_fee: 0,
            }
        );
        // The projection does not carry states: the documented
        // zero-value marker rides the reconstruction instead.
        assert_eq!(released.from, EscrowState::Uninitialized);
        assert_eq!(released.to, EscrowState::Uninitialized);
        assert!(released.evidence_hash.is_none());
        assert!(released.caller.is_none());
        assert!(!released.evidence_defaulted);
        // Re-emission is byte-identical: the parse is canonical.
        assert_eq!(events_to_csv(&parsed), csv);
    }

    #[test]
    fn export_is_deterministic() {
        let events = flow_events();
        assert_eq!(events_to_csv(&events), events_to_csv(&events));
    }

    #[test]
    fn actor_hex_accepts_uppercase_on_import() {
        let csv = format!(
            "kind,seq,at,actor,payout,fee,refund,penalty,rent_reclaimed,arbiter_fee\n\
             initialized,0,{T0},{},0,0,0,0,0,0\n",
            ACTOR_HEX.to_uppercase()
        );
        let parsed = csv_to_events(&csv).unwrap();
        assert_eq!(parsed[0].escrow_id, ESCROW_ID);
        // …but export stays canonical lowercase.
        assert!(events_to_csv(&parsed).contains(ACTOR_HEX));
    }

    #[test]
    fn crlf_input_is_tolerated() {
        let csv = events_to_csv(&initialized_events()).replace('\n', "\r\n");
        let parsed = csv_to_events(&csv).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].kind, EscrowEventKind::Initialized);
    }

    #[test]
    fn missing_header_is_an_error() {
        assert_eq!(csv_to_events(""), Err(CsvError::MissingHeader));
    }

    #[test]
    fn wrong_header_is_an_error() {
        let err = csv_to_events("kind,seq,at\ninitialized,0,1\n").unwrap_err();
        assert_eq!(
            err,
            CsvError::UnexpectedHeader {
                got: "kind,seq,at".to_string()
            }
        );
    }

    #[test]
    fn bad_field_count_is_an_error() {
        let csv = format!("{HEADER}\ninitialized,0,{T0}\n");
        assert_eq!(
            csv_to_events(&csv).unwrap_err(),
            CsvError::BadFieldCount {
                line: 2,
                expected: 10,
                got: 3
            }
        );
        // A blank record line is a zero-field record, not a skip.
        let csv = format!("{HEADER}\n\n");
        assert_eq!(
            csv_to_events(&csv).unwrap_err(),
            CsvError::BadFieldCount {
                line: 2,
                expected: 10,
                got: 1
            }
        );
    }

    #[test]
    fn unknown_kind_is_an_error() {
        let csv = format!("{HEADER}\nlaunched,0,{T0},{ACTOR_HEX},0,0,0,0,0,0\n");
        assert_eq!(
            csv_to_events(&csv).unwrap_err(),
            CsvError::UnknownKind {
                line: 2,
                value: "launched".to_string()
            }
        );
    }

    #[test]
    fn invalid_integers_are_errors() {
        let bad_seq = format!("{HEADER}\nreleased,x,{T0},{ACTOR_HEX},1,2,3,4,5,0\n");
        assert_eq!(
            csv_to_events(&bad_seq).unwrap_err(),
            CsvError::InvalidInt {
                line: 2,
                column: "seq",
                value: "x".to_string()
            }
        );
        let negative = format!("{HEADER}\nreleased,0,{T0},{ACTOR_HEX},-1,0,0,0,0,0\n");
        assert_eq!(
            csv_to_events(&negative).unwrap_err(),
            CsvError::InvalidInt {
                line: 2,
                column: "payout",
                value: "-1".to_string()
            }
        );
        let overflow = format!("{HEADER}\nreleased,0,{T0},{ACTOR_HEX},18446744073709551616,0,0,0,0,0\n");
        assert_eq!(
            csv_to_events(&overflow).unwrap_err(),
            CsvError::InvalidInt {
                line: 2,
                column: "payout",
                value: "18446744073709551616".to_string()
            }
        );
    }

    #[test]
    fn invalid_actor_hex_is_an_error() {
        // Too short.
        let short = format!("{HEADER}\nreleased,0,{T0},1d1d,1,2,3,4,5,0\n");
        assert_eq!(
            csv_to_events(&short).unwrap_err(),
            CsvError::InvalidActorHex {
                line: 2,
                value: "1d1d".to_string()
            }
        );
        // Right length, non-hex character.
        let actor = "zz".to_string() + &"1d".repeat(31);
        let bad_char = format!("{HEADER}\nreleased,0,{T0},{actor},1,2,3,4,5,0\n");
        assert_eq!(
            csv_to_events(&bad_char).unwrap_err(),
            CsvError::InvalidActorHex {
                line: 2,
                value: actor
            }
        );
    }

    #[test]
    fn unterminated_quote_in_record_is_an_error() {
        let csv = format!("{HEADER}\n\"released,0,{T0},{ACTOR_HEX},1,2,3,4,5\n");
        assert_eq!(
            csv_to_events(&csv).unwrap_err(),
            CsvError::UnterminatedQuote { line: 2 }
        );
    }
}
