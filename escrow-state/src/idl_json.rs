//! AV-29: Anchor IDL JSON generation pipeline (test-only).
//!
//! `anchor build` would emit `target/idl/escrow_vault.json` from the
//! `#[program]` module in `programs/escrow-vault/src/program.rs`, but the
//! Anchor/Solana BPF toolchain is unavailable in this environment (and in
//! CI), so the checked-in `programs/escrow-vault/idl/escrow_vault.json` is
//! generated from the single sources of truth the pure-logic crate
//! already maintains:
//!
//! - the `Vault` account layout (name / type / byte offset) from
//!   [`VAULT_FIELDS`];
//! - the instruction name / args from the `INSTRUCTIONS` spec table in
//!   `anchor_idl_tests`;
//! - the error code / name table from [`EscrowError`].
//!
//! Regenerate with:
//!
//! ```bash
//! UPDATE_IDL=1 cargo test -p escrow-state idl_json
//! ```
//!
//! Without the variable, `idl_json_matches_checked_in` fails on any
//! byte-level drift between the generator and the checked-in file, so CI
//! pins the artifact. When the Anchor toolchain is available, `anchor
//! build` output should replace the checked-in file (the pinning tests
//! then guard the real artifact instead).
//!
//! The `"offset"` on each account field is a pipeline extension, not
//! part of the Anchor IDL schema: the byte offset of the field inside
//! the account data *including* the 8-byte Anchor discriminator,
//! computed from Borsh layout rules (sequential fields, no padding).
//! Anchor tooling ignores unknown JSON fields; the offsets exist so
//! indexers and the tests below can pin the IDL against the on-chain
//! bytes without re-deriving the layout.

use super::account_space_tests::encode_escrow;
use super::anchor_idl_tests::INSTRUCTIONS;
use super::*;

// SHA-256 and the Anchor discriminator constructors live at the crate
// root (`crate::sha256`) and in `crate::discriminator` so this
// test-only pipeline and production code (AV-32/AV-33) share one
// implementation. `sha256` arrives via `use super::*;` above.
use super::discriminator::instruction_discriminator;

// ---------------------------------------------------------------------------
// IDL type model.
// ---------------------------------------------------------------------------

/// Element type of a fixed-size IDL array.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ArrayElem {
    U8,
    U64,
    PublicKey,
}

impl ArrayElem {
    fn borsh_len(self) -> usize {
        match self {
            ArrayElem::U8 => 1,
            ArrayElem::U64 => 8,
            ArrayElem::PublicKey => 32,
        }
    }

    fn render(self, w: &mut Writer) {
        w.str_lit(match self {
            ArrayElem::U8 => "u8",
            ArrayElem::U64 => "u64",
            ArrayElem::PublicKey => "publicKey",
        });
    }
}

/// An Anchor IDL type expression. Covers every type that appears in
/// `VAULT_FIELDS`, the named account subtypes, and the instruction args.
#[derive(Clone, Debug, PartialEq, Eq)]
enum IdlType {
    U8,
    U16,
    U64,
    PublicKey,
    Str,
    Array(ArrayElem, usize),
    Vec(Box<IdlType>),
    Option(Box<IdlType>),
    Named(&'static str),
}

impl IdlType {
    /// Borsh serialized length. Panics on variable-length types, which
    /// never appear in account layout (offsets would be meaningless).
    fn borsh_len(&self) -> usize {
        match self {
            IdlType::U8 => 1,
            IdlType::U16 => 2,
            IdlType::U64 => 8,
            IdlType::PublicKey => 32,
            IdlType::Str => panic!("idl_json: variable-length type has no account offset"),
            IdlType::Array(elem, n) => elem.borsh_len() * n,
            IdlType::Vec(_) => panic!("idl_json: variable-length type has no account offset"),
            IdlType::Option(inner) => 1 + inner.borsh_len(),
            IdlType::Named(name) => named_type_fields(name)
                .iter()
                .map(|(_, t)| t.borsh_len())
                .sum(),
        }
    }

    fn render(&self, w: &mut Writer) {
        match self {
            IdlType::U8 => w.str_lit("u8"),
            IdlType::U16 => w.str_lit("u16"),
            IdlType::U64 => w.str_lit("u64"),
            IdlType::PublicKey => w.str_lit("publicKey"),
            IdlType::Str => w.str_lit("string"),
            IdlType::Array(elem, n) => {
                w.buf.push_str("{\"array\": [");
                elem.render(w);
                w.buf.push_str(&format!(", {n}]}}"));
            }
            IdlType::Vec(inner) => {
                w.buf.push_str("{\"vec\": ");
                inner.render(w);
                w.buf.push('}');
            }
            IdlType::Option(inner) => {
                w.buf.push_str("{\"option\": ");
                inner.render(w);
                w.buf.push('}');
            }
            IdlType::Named(name) => {
                w.buf.push_str("{\"defined\": ");
                w.str_lit(name);
                w.buf.push('}');
            }
        }
    }
}

/// Map a `VAULT_FIELDS` type string onto the IDL type model. Panics on
/// an unmapped string: adding a field with a new type spelling must
/// update this pipeline, not silently drift.
fn idl_type_of(vault_ty: &str) -> IdlType {
    match vault_ty {
        "Pubkey" => IdlType::PublicKey,
        "u64" => IdlType::U64,
        "u16" => IdlType::U16,
        "u8" => IdlType::U8,
        "u8 (enum discriminant)" => IdlType::U8,
        "u8 (bitmask)" => IdlType::U8,
        "u64 (bitmask)" => IdlType::U64,
        "Option<QuorumPolicy>" => IdlType::Option(Box::new(IdlType::Named("QuorumPolicy"))),
        "Option<VestingSchedule>" => IdlType::Option(Box::new(IdlType::Named("VestingSchedule"))),
        "Option<Pubkey>" => IdlType::Option(Box::new(IdlType::PublicKey)),
        "Option<MilestonePlan>" => IdlType::Option(Box::new(IdlType::Named("MilestonePlan"))),
        "Option<[u8; 32]>" => IdlType::Option(Box::new(IdlType::Array(ArrayElem::U8, 32))),
        other => panic!("idl_json: unmapped VAULT_FIELDS type string: {other}"),
    }
}

/// Map an `INSTRUCTIONS` spec arg type string onto the IDL type model.
fn arg_idl_type(spec_ty: &str) -> IdlType {
    match spec_ty {
        "u64" => IdlType::U64,
        "u8" => IdlType::U8,
        "u16" => IdlType::U16,
        "Pubkey" => IdlType::PublicKey,
        "String" => IdlType::Str,
        "Vec<Pubkey>" => IdlType::Vec(Box::new(IdlType::PublicKey)),
        "Vec<u64>" => IdlType::Vec(Box::new(IdlType::U64)),
        "Vec<u8>" => IdlType::Vec(Box::new(IdlType::U8)),
        "Option<[u8; 32]>" => IdlType::Option(Box::new(IdlType::Array(ArrayElem::U8, 32))),
        other => panic!("idl_json: unmapped instruction arg type string: {other}"),
    }
}

/// Fields of the named account subtypes, in Borsh order. Mirrors the
/// Rust structs field-for-field; `named_type_sizes_pin_constants` and
/// the byte-level offset test below nail any drift.
fn named_type_fields(name: &str) -> &'static [(&'static str, IdlType)] {
    match name {
        // QuorumPolicy { attestors: [[u8; 32]; 8], registered: u8,
        //                threshold: u8, approvals: u64 }.
        "QuorumPolicy" => &[
            ("attestors", IdlType::Array(ArrayElem::PublicKey, 8)),
            ("registered", IdlType::U8),
            ("threshold", IdlType::U8),
            ("approvals", IdlType::U64),
        ],
        // VestingSchedule { start: u64, end: u64 }.
        "VestingSchedule" => &[("start", IdlType::U64), ("end", IdlType::U64)],
        // MilestonePlan { amounts: [u64; 8], count: u8 }.
        "MilestonePlan" => &[
            ("amounts", IdlType::Array(ArrayElem::U64, 8)),
            ("count", IdlType::U8),
        ],
        other => panic!("idl_json: unknown named type: {other}"),
    }
}

/// The `Vault` account fields as (name, IDL type), in Borsh order,
/// derived from [`VAULT_FIELDS`].
fn vault_idl_fields() -> Vec<(&'static str, IdlType)> {
    VAULT_FIELDS
        .iter()
        .map(|(name, ty, _)| (*name, idl_type_of(ty)))
        .collect()
}

/// (name, account-data byte offset, serialized length) for every `Vault`
/// field. Offsets include the 8-byte Anchor discriminator.
fn vault_field_offsets() -> Vec<(&'static str, usize, usize)> {
    let mut out = Vec::with_capacity(VAULT_FIELDS.len());
    let mut offset = ANCHOR_DISCRIMINATOR_LEN;
    for (name, ty) in vault_idl_fields() {
        let len = ty.borsh_len();
        out.push((name, offset, len));
        offset += len;
    }
    out
}

// ---------------------------------------------------------------------------
// Deterministic JSON rendering.
// ---------------------------------------------------------------------------

struct Writer {
    buf: String,
    indent: usize,
}

impl Writer {
    fn new() -> Self {
        Self {
            buf: String::new(),
            indent: 0,
        }
    }

    fn line(&mut self, s: &str) {
        for _ in 0..self.indent {
            self.buf.push_str("  ");
        }
        self.buf.push_str(s);
        self.buf.push('\n');
    }

    fn str_lit(&mut self, s: &str) {
        self.buf.push('"');
        for c in s.chars() {
            match c {
                '"' => self.buf.push_str("\\\""),
                '\\' => self.buf.push_str("\\\\"),
                '\n' => self.buf.push_str("\\n"),
                '\r' => self.buf.push_str("\\r"),
                '\t' => self.buf.push_str("\\t"),
                c if (c as u32) < 0x20 => {
                    self.buf.push_str(&format!("\\u{:04x}", c as u32));
                }
                c => self.buf.push(c),
            }
        }
        self.buf.push('"');
    }

    fn key(&mut self, name: &str) {
        self.str_lit(name);
        self.buf.push_str(": ");
    }
}

/// One rendered IDL instruction: the unit the spec table pins against.
struct RenderedInstruction {
    name: &'static str,
    discriminator: [u8; 8],
    args: Vec<(&'static str, IdlType)>,
}

fn rendered_instructions() -> Vec<RenderedInstruction> {
    INSTRUCTIONS
        .iter()
        .map(|spec| RenderedInstruction {
            name: spec.name,
            discriminator: instruction_discriminator(spec.name),
            args: spec
                .params
                .iter()
                .map(|(name, ty, _)| (*name, arg_idl_type(ty)))
                .collect(),
        })
        .collect()
}

fn render_idl_json() -> String {
    let version = program_crate_version();
    let mut w = Writer::new();
    w.line("{");
    w.indent += 1;

    w.line(&format!("\"version\": \"{version}\","));
    w.line("\"name\": \"escrow_vault\",");

    // ---- instructions ----
    w.line("\"instructions\": [");
    w.indent += 1;
    let instructions = rendered_instructions();
    for (i, ix) in instructions.iter().enumerate() {
        w.line("{");
        w.indent += 1;
        w.buf.push_str(&"  ".repeat(w.indent));
        w.key("name");
        w.str_lit(ix.name);
        w.buf.push_str(",\n");
        w.buf.push_str(&"  ".repeat(w.indent));
        w.key("discriminator");
        w.buf.push('[');
        for (j, b) in ix.discriminator.iter().enumerate() {
            if j > 0 {
                w.buf.push_str(", ");
            }
            w.buf.push_str(&b.to_string());
        }
        w.buf.push_str("],\n");
        // Per-instruction account constraints live in
        // programs/escrow-vault/src/program.rs and are pinned by the
        // anchor_idl_tests spec (input_mapping), not by this pipeline:
        // the byte-layout surface this file guards is name/args.
        w.buf.push_str(&"  ".repeat(w.indent));
        w.buf.push_str("\"accounts\": [],\n");
        w.buf.push_str(&"  ".repeat(w.indent));
        w.buf.push_str("\"args\": [");
        if ix.args.is_empty() {
            w.buf.push_str("]");
        } else {
            w.buf.push('\n');
            w.indent += 1;
            for (k, (name, ty)) in ix.args.iter().enumerate() {
                w.buf.push_str(&"  ".repeat(w.indent));
                w.buf.push_str("{\"name\": ");
                w.str_lit(name);
                w.buf.push_str(", \"type\": ");
                ty.render(&mut w);
                w.buf.push('}');
                if k + 1 < ix.args.len() {
                    w.buf.push(',');
                }
                w.buf.push('\n');
            }
            w.indent -= 1;
            w.buf.push_str(&"  ".repeat(w.indent));
            w.buf.push(']');
        }
        w.buf.push('\n');
        w.indent -= 1;
        w.buf.push_str(&"  ".repeat(w.indent));
        w.buf.push('}');
        if i + 1 < instructions.len() {
            w.buf.push(',');
        }
        w.buf.push('\n');
    }
    w.indent -= 1;
    w.line("],");

    // ---- accounts ----
    w.line("\"accounts\": [");
    w.indent += 1;
    w.line("{");
    w.indent += 1;
    w.line("\"name\": \"Vault\",");
    w.line("\"type\": {");
    w.indent += 1;
    w.line("\"kind\": \"struct\",");
    w.line("\"fields\": [");
    w.indent += 1;
    let offsets = vault_field_offsets();
    for (i, (name, offset, _)) in offsets.iter().enumerate() {
        let ty = &vault_idl_fields()[i].1;
        w.buf.push_str(&"  ".repeat(w.indent));
        w.buf.push_str("{\"name\": ");
        w.str_lit(name);
        w.buf.push_str(", \"type\": ");
        ty.render(&mut w);
        w.buf.push_str(&format!(", \"offset\": {offset}}}"));
        if i + 1 < offsets.len() {
            w.buf.push(',');
        }
        w.buf.push('\n');
    }
    w.indent -= 1;
    w.line("]");
    w.indent -= 1;
    w.line("}");
    w.indent -= 1;
    w.line("}");
    w.indent -= 1;
    w.line("],");

    // ---- types ----
    w.line("\"types\": [");
    w.indent += 1;
    for (ti, type_name) in ["QuorumPolicy", "VestingSchedule", "MilestonePlan"]
        .iter()
        .enumerate()
    {
        w.line("{");
        w.indent += 1;
        w.buf.push_str(&"  ".repeat(w.indent));
        w.key("name");
        w.str_lit(type_name);
        w.buf.push_str(",\n");
        w.line("\"type\": {");
        w.indent += 1;
        w.line("\"kind\": \"struct\",");
        w.line("\"fields\": [");
        w.indent += 1;
        let fields = named_type_fields(type_name);
        let mut offset = 0usize;
        for (i, (name, ty)) in fields.iter().enumerate() {
            w.buf.push_str(&"  ".repeat(w.indent));
            w.buf.push_str("{\"name\": ");
            w.str_lit(name);
            w.buf.push_str(", \"type\": ");
            ty.render(&mut w);
            w.buf.push_str(&format!(", \"offset\": {offset}}}"));
            if i + 1 < fields.len() {
                w.buf.push(',');
            }
            w.buf.push('\n');
            offset += ty.borsh_len();
        }
        w.indent -= 1;
        w.line("]");
        w.indent -= 1;
        w.line("}");
        w.indent -= 1;
        w.buf.push_str(&"  ".repeat(w.indent));
        w.buf.push('}');
        if ti + 1 < 3 {
            w.buf.push(',');
        }
        w.buf.push('\n');
    }
    w.indent -= 1;
    w.line("],");

    // ---- errors ----
    w.line("\"errors\": [");
    w.indent += 1;
    let errors = EscrowError::all();
    for (i, e) in errors.iter().enumerate() {
        w.buf.push_str(&"  ".repeat(w.indent));
        w.buf.push_str(&format!(
            "{{\"code\": {}, \"name\": ",
            e.code()
        ));
        w.str_lit(&format!("{e:?}"));
        w.buf.push('}');
        if i + 1 < errors.len() {
            w.buf.push(',');
        }
        w.buf.push('\n');
    }
    w.indent -= 1;
    w.line("],");

    // ---- metadata ----
    w.line("\"metadata\": {");
    w.indent += 1;
    w.buf.push_str(&"  ".repeat(w.indent));
    w.key("generator");
    w.str_lit("escrow-state idl_json pipeline (AV-29)");
    w.buf.push_str(",\n");
    w.buf.push_str(&"  ".repeat(w.indent));
    w.key("provenance");
    w.str_lit("generated from VAULT_FIELDS + INSTRUCTIONS spec + EscrowError; the Anchor toolchain is unavailable in this environment, so this file stands in for `anchor build` output until the toolchain can regenerate it");
    w.buf.push_str(",\n");
    w.buf.push_str(&"  ".repeat(w.indent));
    w.key("borsh_offsets");
    w.str_lit("field \"offset\" values are a pipeline extension: byte offsets into the account data INCLUDING the 8-byte Anchor discriminator, computed from Borsh layout (sequential fields, no padding); named-type offsets are relative to the start of the type");
    w.buf.push('\n');
    w.indent -= 1;
    w.line("}");

    w.indent -= 1;
    w.line("}");
    w.buf
}

/// Read the `version` from `programs/escrow-vault/Cargo.toml` so the
/// IDL version tracks the program crate. Panics when unparseable: a
/// silent fallback version would be worse than a loud failure.
fn program_crate_version() -> String {
    let manifest =
        std::fs::read_to_string("../programs/escrow-vault/Cargo.toml").expect("read program Cargo.toml");
    for line in manifest.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("version") {
            let rest = rest.trim().strip_prefix('=').expect("version assignment").trim();
            let version = rest.trim_matches('"');
            assert!(
                !version.is_empty() && version != "version",
                "unparseable version line: {line}"
            );
            return version.to_string();
        }
    }
    panic!("idl_json: no version found in programs/escrow-vault/Cargo.toml");
}

/// Path of the checked-in IDL, relative to the `escrow-state` crate dir
/// (cargo runs tests with the package root as cwd).
fn idl_json_path() -> std::path::PathBuf {
    std::path::PathBuf::from("../programs/escrow-vault/idl/escrow_vault.json")
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

#[test]
fn sha256_known_vectors() {
    // FIPS 180-4 test vectors pin the hand-rolled implementation, which
    // in turn pins every instruction discriminator below.
    let hex = |d: [u8; 32]| d.iter().map(|b| format!("{b:02x}")).collect::<String>();
    assert_eq!(
        hex(sha256(b"")),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        hex(sha256(b"abc")),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        hex(sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    );
}

#[test]
fn named_type_sizes_pin_constants() {
    // The named-type field tables above must serialize to exactly the
    // lengths the account-space math reserves.
    let size = |name: &str| {
        named_type_fields(name)
            .iter()
            .map(|(_, t)| t.borsh_len())
            .sum::<usize>()
    };
    assert_eq!(size("QuorumPolicy"), QUORUM_POLICY_LEN);
    assert_eq!(size("VestingSchedule"), 16);
    assert_eq!(size("MilestonePlan"), MILESTONE_PLAN_LEN);
}

#[test]
fn vault_offsets_cover_account_space() {
    let offsets = vault_field_offsets();
    assert_eq!(offsets.len(), VAULT_FIELDS.len());
    for (i, (name, offset, len)) in offsets.iter().enumerate() {
        assert_eq!(*name, VAULT_FIELDS[i].0, "field order drift");
        assert_eq!(*len, VAULT_FIELDS[i].2, "field length drift for {name}");
        let _ = offset;
    }
    let total: usize = offsets.iter().map(|(_, _, len)| len).sum();
    assert_eq!(total, ESCROW_BODY_LEN);
    assert_eq!(ANCHOR_DISCRIMINATOR_LEN + total, VAULT_SPACE);
}

#[test]
fn idl_instructions_pin_spec() {
    // Bidirectional: every INSTRUCTIONS spec entry appears in the
    // rendered IDL with identical name/args, and the IDL carries no
    // instruction the spec table does not know about.
    let rendered = rendered_instructions();
    assert_eq!(
        rendered.len(),
        INSTRUCTIONS.len(),
        "instruction count drift between INSTRUCTIONS spec and IDL"
    );
    for spec in INSTRUCTIONS {
        let r = rendered
            .iter()
            .find(|r| r.name == spec.name)
            .unwrap_or_else(|| panic!("IDL missing instruction {}", spec.name));
        let expected_args: Vec<(&str, IdlType)> = spec
            .params
            .iter()
            .map(|(name, ty, _)| (*name, arg_idl_type(ty)))
            .collect();
        assert_eq!(r.args, expected_args, "arg drift for instruction {}", spec.name);
        // The discriminator is recomputed from the Anchor rule here, so
        // a change to the hashing helper breaks this test loudly.
        assert_eq!(
            r.discriminator,
            instruction_discriminator(spec.name),
            "discriminator drift for instruction {}",
            spec.name
        );
        assert_eq!(
            &r.discriminator[..],
            &sha256(format!("global:{}", spec.name).as_bytes())[..8]
        );
    }
}

#[test]
fn idl_errors_pin_enum() {
    // Every EscrowError variant appears exactly once, with its stable code.
    let errors = EscrowError::all();
    let mut seen = std::collections::HashSet::new();
    for e in errors {
        let name = format!("{e:?}");
        assert!(seen.insert(name.clone()), "duplicate error variant {name}");
        assert!(
            (100..200).contains(&e.code()),
            "error code out of pinned range: {name} = {}",
            e.code()
        );
    }
    assert_eq!(errors.len(), 23, "error variant count drift");
    // Spot-pin the code table ends so a renumber breaks loudly.
    assert_eq!(EscrowError::Unauthorized.code(), 100);
    assert_eq!(EscrowError::CpiExecutionFailed.code(), 121);
    assert_eq!(EscrowError::ReentrantCall.code(), 122);
}

#[test]
fn idl_json_matches_checked_in() {
    let rendered = render_idl_json();
    let path = idl_json_path();
    if std::env::var("UPDATE_IDL").is_ok() {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create idl dir");
        }
        std::fs::write(&path, &rendered).expect("write IDL JSON");
        return;
    }
    let checked_in = std::fs::read_to_string(&path).unwrap_or_else(|_| {
        panic!(
            "checked-in IDL not found at {}; regenerate with UPDATE_IDL=1 cargo test -p escrow-state idl_json",
            path.display()
        )
    });
    assert_eq!(
        checked_in, rendered,
        "checked-in escrow_vault.json drifted from the generator; regenerate with UPDATE_IDL=1"
    );
}

// Byte-level pinning: the IDL field offsets must land on the exact bytes
// the hand-written Borsh encoder (`encode_escrow`) produces for a
// fully-configured escrow. This is the anti-drift nail AV-29 exists for:
// IDL name/type/offset on one side, real serialized bytes on the other.

const ALICE: [u8; 32] = [0xAA; 32];
const BOB: [u8; 32] = [0xBB; 32];
const ATTESTOR_1: [u8; 32] = [0xA1; 32];
const ATTESTOR_2: [u8; 32] = [0xA2; 32];
const ARB: [u8; 32] = [0xA9; 32];
const MINT: [u8; 32] = [0xA5; 32];
const REFUND: [u8; 32] = [0xB0; 32];
const EVIDENCE: [u8; 32] = [0xE8; 32];
const EXPIRES_AT: u64 = 1_800_000_000;
const VEST_START: u64 = 1_700_000_000;
const VEST_END: u64 = 1_900_000_000;

/// Slice of the encoded body for `name`, using the IDL-computed offset.
/// `encode_escrow` emits the body without the discriminator, so the
/// account-data offset is shifted back by 8.
fn body_field<'a>(bytes: &'a [u8], offsets: &[(&str, usize, usize)], name: &str) -> &'a [u8] {
    let (_, offset, len) = offsets
        .iter()
        .find(|(n, _, _)| *n == name)
        .copied()
        .unwrap_or_else(|| panic!("unknown field {name}"));
    &bytes[offset - ANCHOR_DISCRIMINATOR_LEN..offset - ANCHOR_DISCRIMINATOR_LEN + len]
}

fn u64_at(b: &[u8]) -> u64 {
    u64::from_le_bytes(b.try_into().expect("u64 slice"))
}

fn max_config_funded_escrow() -> Escrow {
    let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT).unwrap();
    e = e.with_dual_sig().unwrap();
    e = e
        .with_quorum(QuorumPolicy::new(&[ATTESTOR_1, ATTESTOR_2], 2).unwrap())
        .unwrap();
    e = e
        .with_vesting(VestingSchedule::new(VEST_START, VEST_END).unwrap())
        .unwrap();
    e = e.with_mint(MINT).unwrap();
    e = e.with_protocol_fee(250).unwrap();
    e = e.with_grace_period(3600).unwrap();
    e = e.with_refund_address(REFUND).unwrap();
    e = e.with_penalty_bps(100).unwrap();
    e = e.with_timelock(VEST_START + 1).unwrap();
    e = e.with_decimals(6).unwrap();
    e = e.with_arbiter(ARB).unwrap();
    e = e
        .with_milestones(MilestonePlan::new(&[400_000, 600_000]).unwrap())
        .unwrap();
    e.activate(ALICE).unwrap();
    e.activate(BOB).unwrap();
    e.fund(ALICE).unwrap();
    e.attest(ATTESTOR_1).unwrap();
    e.attest(ATTESTOR_2).unwrap();
    // Milestone 0: dual-confirm then release. Tranche 400_000 at 250 bps
    // => fee 10_000, taker payout 390_000, gross released 400_000.
    e.confirm_milestone(ALICE, 0).unwrap();
    e.confirm_milestone(BOB, 0).unwrap();
    let (payout, fee) = e
        .release_milestone(ALICE, EXPIRES_AT, 0, Some(MINT))
        .unwrap();
    assert_eq!((payout, fee), (390_000, 10_000));
    // Milestone 1: dual-skip => 600_000 joins the refundable remainder.
    e.skip_milestone(ALICE, 1).unwrap();
    e.skip_milestone(BOB, 1).unwrap();
    e
}

#[test]
fn idl_field_offsets_pin_borsh_encoder() {
    let e = max_config_funded_escrow();
    let enc = encode_escrow(&e);
    assert_eq!(enc.len(), ESCROW_BODY_LEN);
    let offsets = vault_field_offsets();

    assert_eq!(body_field(&enc, &offsets, "initializer"), &ALICE);
    assert_eq!(body_field(&enc, &offsets, "taker"), &BOB);
    assert_eq!(u64_at(body_field(&enc, &offsets, "amount")), 1_000_000);
    assert_eq!(u64_at(body_field(&enc, &offsets, "released")), 400_000);
    assert_eq!(u64_at(body_field(&enc, &offsets, "expires_at")), EXPIRES_AT);
    assert_eq!(body_field(&enc, &offsets, "state"), &[1u8]); // Funded

    // quorum: Some { attestors[8], registered, threshold, approvals }.
    let q = body_field(&enc, &offsets, "quorum");
    assert_eq!(q[0], 1, "quorum discriminant");
    assert_eq!(&q[1..33], &ATTESTOR_1);
    assert_eq!(&q[33..65], &ATTESTOR_2);
    assert_eq!(&q[65..257], &[0u8; 192], "unused attestor slots zeroed");
    assert_eq!(q[257], 2, "registered");
    assert_eq!(q[258], 2, "threshold");
    assert_eq!(u64_at(&q[259..267]), 0b11, "approvals bitmask");

    // activation: bit 0 initializer, bit 1 taker, bit 2 dual-sig required
    // (set by with_dual_sig) => 0b111.
    assert_eq!(body_field(&enc, &offsets, "activation"), &[0b111]);

    let v = body_field(&enc, &offsets, "vesting");
    assert_eq!(v[0], 1, "vesting discriminant");
    assert_eq!(u64_at(&v[1..9]), VEST_START);
    assert_eq!(u64_at(&v[9..17]), VEST_END);

    let a = body_field(&enc, &offsets, "arbiter");
    assert_eq!(a[0], 1, "arbiter discriminant");
    assert_eq!(&a[1..33], &ARB);

    let m = body_field(&enc, &offsets, "milestones");
    assert_eq!(m[0], 1, "milestones discriminant");
    assert_eq!(u64_at(&m[1..9]), 400_000);
    assert_eq!(u64_at(&m[9..17]), 600_000);
    assert_eq!(&m[17..65], &[0u8; 48], "unused tranche slots zeroed");
    assert_eq!(m[65], 2, "tranche count");

    // milestone_flags: bits index*6+{0,1,2} (init/taker confirm + released
    // of milestone 0) and index*6+{3,4,5} (init/taker skip approvals +
    // skipped of milestone 1) => bits 0,1,2 and 9,10,11.
    assert_eq!(
        u64_at(body_field(&enc, &offsets, "milestone_flags")),
        0b111_000000_111
    );
    assert_eq!(u64_at(body_field(&enc, &offsets, "skipped")), 600_000);

    let mint = body_field(&enc, &offsets, "mint");
    assert_eq!(mint[0], 1, "mint discriminant");
    assert_eq!(&mint[1..33], &MINT);

    assert_eq!(
        u16::from_le_bytes(
            body_field(&enc, &offsets, "fee_bps")
                .try_into()
                .expect("u16 slice")
        ),
        250
    );
    assert_eq!(u64_at(body_field(&enc, &offsets, "fees_paid")), 10_000);
    assert_eq!(u64_at(body_field(&enc, &offsets, "grace_period")), 3600);

    let ev = body_field(&enc, &offsets, "evidence_hash");
    assert_eq!(ev[0], 0, "no evidence attached");
    assert_eq!(&ev[1..33], &[0u8; 32]);

    let r = body_field(&enc, &offsets, "refund_to");
    assert_eq!(r[0], 1, "refund_to discriminant");
    assert_eq!(&r[1..33], &REFUND);

    assert_eq!(
        u16::from_le_bytes(
            body_field(&enc, &offsets, "penalty_bps")
                .try_into()
                .expect("u16 slice")
        ),
        100
    );
    assert_eq!(u64_at(body_field(&enc, &offsets, "timelock")), VEST_START + 1);
    assert_eq!(body_field(&enc, &offsets, "decimals"), &[6u8]);
}

#[test]
fn idl_field_offsets_pin_dispute_path() {
    // The dispute path exercises the tail fields the funded path leaves
    // zeroed: evidence_hash persisted on escalate, Disputed/Settled
    // discriminants through resolve.
    let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT).unwrap();
    e = e.with_arbiter(ARB).unwrap();
    e.fund(ALICE).unwrap();
    e.escalate(BOB, EXPIRES_AT - 100, Some(EVIDENCE)).unwrap();

    let enc = encode_escrow(&e);
    let offsets = vault_field_offsets();
    assert_eq!(body_field(&enc, &offsets, "state"), &[5u8]); // Disputed
    let ev = body_field(&enc, &offsets, "evidence_hash");
    assert_eq!(ev[0], 1, "evidence discriminant");
    assert_eq!(&ev[1..33], &EVIDENCE);

    let (payout, fee, refund) = e.resolve(ARB, 300_000, None).unwrap();
    assert_eq!((payout, fee, refund), (300_000, 0, 700_000));
    let enc = encode_escrow(&e);
    assert_eq!(body_field(&enc, &offsets, "state"), &[6u8]); // Settled
    // Evidence survives settlement: the audit trail is never cleared.
    let ev = body_field(&enc, &offsets, "evidence_hash");
    assert_eq!(&ev[1..33], &EVIDENCE);
    assert_eq!(u64_at(body_field(&enc, &offsets, "released")), 300_000);
}
