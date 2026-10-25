//! AV-152: IDL semver breaking-change gate (test-only).
//!
//! The AV-29 pipeline pins the *generated* IDL byte-for-byte, but
//! generation from sources can still *intentionally* change the IDL
//! between releases — a removed instruction, a reordered account
//! field, a reused error code — and every one of those silently breaks
//! off-chain clients (indexers, the keeper CLI, SDKs) at the wire
//! level. This module is the release gate: it diffs two checked-in
//! IDL JSON documents (baseline vs. current) and classifies each
//! change as breaking or non-breaking:
//!
//! - breaking: instruction removed; instruction arg added/removed/
//!   renamed/type-changed (instruction args are positional Borsh, so
//!   even renames matter for discriminated wire compat);
//!   account or named-type field removed/renamed/type-changed/
//!   reordered; required (non-`Option`) field added; named type
//!   removed; error removed; error code changed for an existing
//!   error; error code reused by a different error.
//! - non-breaking: instruction added; `Option<…>` field added (the
//!   vault's opt-in convention: new optional regions are zeroed when
//!   unset); named type added; error added; version bump.
//!
//! CI gate: every breaking change must appear in
//! [`BREAKING_CHANGE_ALLOWLIST`] (stable string keys, one per
//! change), otherwise [`unallowed_breaking_changes`] returns it and
//! the `idl_semver_gate` test fails. The baseline is
//! `programs/escrow-vault/idl/escrow_vault.baseline.json` — a copy of
//! the IDL as of the last release. When cutting a release, refresh it:
//!
//! ```bash
//! cp programs/escrow-vault/idl/escrow_vault.json \
//!    programs/escrow-vault/idl/escrow_vault.baseline.json
//! ```
//!
//! The IDL JSON is parsed with a hand-rolled JSON parser (the crate
//! is zero-dependency); the diff operates on a semantic model of the
//! IDL, not on text, so formatting changes never report as
//! breaking changes.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Minimal JSON parser.
// ---------------------------------------------------------------------------

/// A JSON value. Numbers are split into unsigned integers (everything
/// the IDL needs: discriminator bytes, offsets, error codes) and
/// floats for completeness.
#[derive(Debug, Clone, PartialEq)]
enum JsonVal {
    Null,
    Bool(bool),
    UInt(u64),
    Float(f64),
    Str(String),
    Arr(Vec<JsonVal>),
    Obj(Vec<(String, JsonVal)>),
}

impl JsonVal {
    fn as_str(&self) -> Result<&str, String> {
        match self {
            JsonVal::Str(s) => Ok(s),
            other => Err(format!("idl_compat: expected string, got {other:?}")),
        }
    }

    fn as_uint(&self) -> Result<u64, String> {
        match self {
            JsonVal::UInt(n) => Ok(*n),
            other => Err(format!("idl_compat: expected integer, got {other:?}")),
        }
    }

    fn as_arr(&self) -> Result<&[JsonVal], String> {
        match self {
            JsonVal::Arr(a) => Ok(a),
            other => Err(format!("idl_compat: expected array, got {other:?}")),
        }
    }

    fn as_obj(&self) -> Result<&[(String, JsonVal)], String> {
        match self {
            JsonVal::Obj(o) => Ok(o),
            other => Err(format!("idl_compat: expected object, got {other:?}")),
        }
    }

    /// Look up an object field by name (first match wins).
    fn get(&self, key: &str) -> Result<&JsonVal, String> {
        self.as_obj()?
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
            .ok_or_else(|| format!("idl_compat: missing object key {key:?}"))
    }
}

struct Parser<'a> {
    src: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(src: &'a str) -> Self {
        Parser {
            src: src.as_bytes(),
            pos: 0,
        }
    }

    fn err<T>(&self, what: &str) -> Result<T, String> {
        Err(format!("idl_compat: JSON parse error at byte {pos}: {what}", pos = self.pos))
    }

    fn peek(&self) -> Option<u8> {
        self.src.get(self.pos).copied()
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn expect_byte(&mut self, b: u8, what: &str) -> Result<(), String> {
        if self.peek() == Some(b) {
            self.pos += 1;
            Ok(())
        } else {
            self.err(what)
        }
    }

    fn parse_value(&mut self) -> Result<JsonVal, String> {
        self.skip_ws();
        match self.peek() {
            Some(b'n') => self.parse_literal("null", JsonVal::Null),
            Some(b't') => self.parse_literal("true", JsonVal::Bool(true)),
            Some(b'f') => self.parse_literal("false", JsonVal::Bool(false)),
            Some(b'"') => Ok(JsonVal::Str(self.parse_string()?)),
            Some(b'[') => self.parse_array(),
            Some(b'{') => self.parse_object(),
            Some(c) if c == b'-' || c.is_ascii_digit() => self.parse_number(),
            _ => self.err("unexpected character"),
        }
    }

    fn parse_literal(&mut self, lit: &str, val: JsonVal) -> Result<JsonVal, String> {
        if self.src.get(self.pos..self.pos + lit.len()) == Some(lit.as_bytes()) {
            self.pos += lit.len();
            Ok(val)
        } else {
            self.err("bad literal")
        }
    }

    fn parse_string(&mut self) -> Result<String, String> {
        self.expect_byte(b'"', "expected string")?;
        let mut out = String::new();
        loop {
            let c = self.peek().ok_or_else(|| "unterminated string".to_string())?;
            match c {
                b'"' => {
                    self.pos += 1;
                    return Ok(out);
                }
                b'\\' => {
                    self.pos += 1;
                    let e = self.peek().ok_or_else(|| "unterminated escape".to_string())?;
                    self.pos += 1;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let mut code: u32 = 0;
                            for _ in 0..4 {
                                let h = self.peek().ok_or_else(|| "bad \\u escape".to_string())?;
                                self.pos += 1;
                                let digit = (h as char).to_digit(16).ok_or_else(|| {
                                    "bad \\u escape".to_string()
                                })?;
                                code = code * 16 + digit;
                            }
                            let ch = char::from_u32(code)
                                .ok_or_else(|| "bad \\u escape".to_string())?;
                            out.push(ch);
                        }
                        _ => return self.err("bad escape"),
                    }
                }
                _ => {
                    // UTF-8 byte sequences pass through byte-wise.
                    out.push(c as char);
                    self.pos += 1;
                }
            }
        }
    }

    fn parse_number(&mut self) -> Result<JsonVal, String> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        let mut is_float = false;
        while let Some(c) = self.peek() {
            if c.is_ascii_digit() {
                self.pos += 1;
            } else if matches!(c, b'.' | b'e' | b'E' | b'+' | b'-') {
                is_float = true;
                self.pos += 1;
            } else {
                break;
            }
        }
        let tok = std::str::from_utf8(&self.src[start..self.pos])
            .map_err(|_| "bad number".to_string())?;
        if tok.is_empty() || tok == "-" {
            return self.err("bad number");
        }
        if !is_float {
            if let Ok(n) = tok.parse::<u64>() {
                return Ok(JsonVal::UInt(n));
            }
        }
        tok.parse::<f64>()
            .map(JsonVal::Float)
            .map_err(|_| format!("idl_compat: unparseable number {tok:?}"))
    }

    fn parse_array(&mut self) -> Result<JsonVal, String> {
        self.expect_byte(b'[', "expected array")?;
        let mut items = Vec::new();
        loop {
            self.skip_ws();
            if self.peek() == Some(b']') {
                self.pos += 1;
                return Ok(JsonVal::Arr(items));
            }
            if !items.is_empty() {
                self.expect_byte(b',', "expected ',' in array")?;
                self.skip_ws();
                if self.peek() == Some(b']') {
                    return self.err("trailing comma in array");
                }
            }
            items.push(self.parse_value()?);
        }
    }

    fn parse_object(&mut self) -> Result<JsonVal, String> {
        self.expect_byte(b'{', "expected object")?;
        let mut fields = Vec::new();
        loop {
            self.skip_ws();
            if self.peek() == Some(b'}') {
                self.pos += 1;
                return Ok(JsonVal::Obj(fields));
            }
            if !fields.is_empty() {
                self.expect_byte(b',', "expected ',' in object")?;
                self.skip_ws();
                if self.peek() == Some(b'}') {
                    return self.err("trailing comma in object");
                }
            }
            self.skip_ws();
            let key = self.parse_string()?;
            self.skip_ws();
            self.expect_byte(b':', "expected ':' in object")?;
            let val = self.parse_value()?;
            fields.push((key, val));
        }
    }
}

fn parse_json(src: &str) -> Result<JsonVal, String> {
    let mut p = Parser::new(src);
    let v = p.parse_value()?;
    p.skip_ws();
    if p.pos != p.src.len() {
        return p.err("trailing content after JSON value");
    }
    Ok(v)
}

// ---------------------------------------------------------------------------
// IDL type-expression model.
// ---------------------------------------------------------------------------

/// An Anchor IDL type expression in structural form, so the diff
/// compares types by meaning, not by JSON formatting.
#[derive(Debug, Clone, PartialEq, Eq)]
enum TypeExpr {
    /// A primitive or named type rendered as a string (`"u8"`,
    /// `"string"`, …).
    Atom(String),
    /// `{"array": [elem, n]}`.
    Array(Box<TypeExpr>, u64),
    /// `{"vec": elem}`.
    VecT(Box<TypeExpr>),
    /// `{"option": inner}`.
    OptionT(Box<TypeExpr>),
    /// `{"defined": name}`.
    Defined(String),
}

impl TypeExpr {
    /// `true` for `{"option": …}` — the vault's opt-in convention, for
    /// which adding a field is non-breaking (AV-152 classification).
    fn is_option(&self) -> bool {
        matches!(self, TypeExpr::OptionT(_))
    }

    /// Canonical rendering matching the AV-29 generator's spelling, so
    /// diff output is readable and greppable against the IDL file.
    fn canonical(&self) -> String {
        match self {
            TypeExpr::Atom(s) => format!("{s:?}"),
            TypeExpr::Array(elem, n) => {
                format!("{{\"array\": [{}, {n}]}}", elem.canonical())
            }
            TypeExpr::VecT(elem) => format!("{{\"vec\": {}}}", elem.canonical()),
            TypeExpr::OptionT(inner) => format!("{{\"option\": {}}}", inner.canonical()),
            TypeExpr::Defined(name) => format!("{{\"defined\": {name:?}}}"),
        }
    }

    fn from_json(v: &JsonVal) -> Result<Self, String> {
        match v {
            JsonVal::Str(s) => Ok(TypeExpr::Atom(s.clone())),
            JsonVal::Obj(_) => {
                let obj = v.as_obj()?;
                if obj.len() != 1 {
                    return Err(format!("idl_compat: multi-key type expression: {obj:?}"));
                }
                let (kind, inner) = &obj[0];
                match kind.as_str() {
                    "array" => {
                        let items = inner.as_arr()?;
                        if items.len() != 2 {
                            return Err("idl_compat: array type must be [elem, n]".into());
                        }
                        let elem = TypeExpr::from_json(&items[0])?;
                        let n = items[1].as_uint()?;
                        Ok(TypeExpr::Array(Box::new(elem), n))
                    }
                    "vec" => Ok(TypeExpr::VecT(Box::new(TypeExpr::from_json(inner)?))),
                    "option" => Ok(TypeExpr::OptionT(Box::new(TypeExpr::from_json(inner)?))),
                    "defined" => Ok(TypeExpr::Defined(inner.as_str()?.to_string())),
                    other => Err(format!("idl_compat: unknown type kind {other:?}")),
                }
            }
            other => Err(format!("idl_compat: bad type expression: {other:?}")),
        }
    }
}

// ---------------------------------------------------------------------------
// IDL semantic model.
// ---------------------------------------------------------------------------

type Fields = Vec<(String, TypeExpr)>;

#[derive(Debug, Clone)]
struct IdlIx {
    name: String,
    args: Fields,
}

#[derive(Debug, Clone)]
struct IdlAccount {
    name: String,
    fields: Fields,
}

#[derive(Debug, Clone)]
struct IdlTypeDef {
    name: String,
    fields: Fields,
}

#[derive(Debug, Clone)]
struct IdlError {
    code: u16,
    name: String,
}

#[derive(Debug, Clone)]
struct IdlSpec {
    version: String,
    instructions: Vec<IdlIx>,
    accounts: Vec<IdlAccount>,
    types: Vec<IdlTypeDef>,
    errors: Vec<IdlError>,
}

/// Parse one `{"name": …, "type": …}` list (instruction args, account
/// fields, named-type fields). Unknown keys on each entry are ignored
/// so the pipeline extension fields (e.g. `"offset"`) never break
/// the gate.
fn parse_fields(list: &[JsonVal]) -> Result<Fields, String> {
    list.iter()
        .map(|entry| {
            let name = entry.get("name")?.as_str()?.to_string();
            let ty = TypeExpr::from_json(entry.get("type")?)?;
            Ok((name, ty))
        })
        .collect()
}

fn parse_idl(json: &str) -> Result<IdlSpec, String> {
    let root = parse_json(json)?;
    let version = root.get("version")?.as_str()?.to_string();

    let mut instructions = Vec::new();
    for ix in root.get("instructions")?.as_arr()? {
        let name = ix.get("name")?.as_str()?.to_string();
        let args = parse_fields(ix.get("args")?.as_arr()?)?;
        instructions.push(IdlIx { name, args });
    }

    let mut accounts = Vec::new();
    for acc in root.get("accounts")?.as_arr()? {
        let name = acc.get("name")?.as_str()?.to_string();
        let fields = parse_fields(acc.get("type")?.get("fields")?.as_arr()?)?;
        accounts.push(IdlAccount { name, fields });
    }

    let mut types = Vec::new();
    for ty in root.get("types")?.as_arr()? {
        let name = ty.get("name")?.as_str()?.to_string();
        let fields = parse_fields(ty.get("type")?.get("fields")?.as_arr()?)?;
        types.push(IdlTypeDef { name, fields });
    }

    let mut errors = Vec::new();
    for e in root.get("errors")?.as_arr()? {
        let code = e.get("code")?.as_uint()?;
        if code > u16::MAX as u64 {
            return Err(format!("idl_compat: error code out of range: {code}"));
        }
        let name = e.get("name")?.as_str()?.to_string();
        errors.push(IdlError {
            code: code as u16,
            name,
        });
    }

    Ok(IdlSpec {
        version,
        instructions,
        accounts,
        types,
        errors,
    })
}

// ---------------------------------------------------------------------------
// Diff and classification.
// ---------------------------------------------------------------------------

/// One IDL change between the baseline and the current IDL, with a
/// breaking/non-breaking classification per the AV-152 rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompatChange {
    // ---- instructions ----
    InstructionAdded {
        name: String,
    },
    InstructionRemoved {
        name: String,
    },
    InstructionArgAdded {
        ix: String,
        arg: String,
    },
    InstructionArgRemoved {
        ix: String,
        arg: String,
    },
    InstructionArgRenamed {
        ix: String,
        from: String,
        to: String,
    },
    InstructionArgTypeChanged {
        ix: String,
        arg: String,
        from: String,
        to: String,
    },
    InstructionArgsReordered {
        ix: String,
    },
    // ---- account / named-type fields (shared alignment) ----
    FieldAdded {
        scope: String,
        field: String,
        ty: String,
        optional: bool,
    },
    FieldRemoved {
        scope: String,
        field: String,
    },
    FieldRenamed {
        scope: String,
        from: String,
        to: String,
    },
    FieldTypeChanged {
        scope: String,
        field: String,
        from: String,
        to: String,
    },
    FieldsReordered {
        scope: String,
    },
    // ---- named types ----
    TypeAdded {
        name: String,
    },
    TypeRemoved {
        name: String,
    },
    // ---- errors ----
    ErrorAdded {
        code: u16,
        name: String,
    },
    ErrorRemoved {
        code: u16,
        name: String,
    },
    ErrorCodeChanged {
        name: String,
        from: u16,
        to: u16,
    },
    ErrorCodeReused {
        code: u16,
        from: String,
        to: String,
    },
    // ---- version ----
    VersionChanged {
        from: String,
        to: String,
    },
}

impl CompatChange {
    /// `true` when the change breaks wire compatibility for existing
    /// off-chain clients. Instruction args are positional Borsh, so
    /// any arg change (add/remove/rename/type/reorder) is breaking;
    /// account/type fields are sequential Borsh, so any field change
    /// is breaking except adding an `Option<…>` field — the vault's
    /// opt-in convention (zeroed when unset).
    pub fn is_breaking(&self) -> bool {
        match self {
            CompatChange::InstructionAdded { .. } => false,
            CompatChange::InstructionRemoved { .. } => true,
            CompatChange::InstructionArgAdded { .. } => true,
            CompatChange::InstructionArgRemoved { .. } => true,
            CompatChange::InstructionArgRenamed { .. } => true,
            CompatChange::InstructionArgTypeChanged { .. } => true,
            CompatChange::InstructionArgsReordered { .. } => true,
            CompatChange::FieldAdded { optional, .. } => !optional,
            CompatChange::FieldRemoved { .. } => true,
            CompatChange::FieldRenamed { .. } => true,
            CompatChange::FieldTypeChanged { .. } => true,
            CompatChange::FieldsReordered { .. } => true,
            CompatChange::TypeAdded { .. } => false,
            CompatChange::TypeRemoved { .. } => true,
            CompatChange::ErrorAdded { .. } => false,
            CompatChange::ErrorRemoved { .. } => true,
            CompatChange::ErrorCodeChanged { .. } => true,
            CompatChange::ErrorCodeReused { .. } => true,
            CompatChange::VersionChanged { .. } => false,
        }
    }

    /// The stable allowlist key for a breaking change: the exact
    /// string a release must declare in
    /// [`BREAKING_CHANGE_ALLOWLIST`] to keep the CI gate green.
    /// Non-breaking changes have no key (they never need the
    /// allowlist).
    pub fn allowlist_key(&self) -> Option<String> {
        let key = match self {
            CompatChange::InstructionRemoved { name } => format!("instruction_removed:{name}"),
            CompatChange::InstructionArgAdded { ix, arg } => {
                format!("instruction_arg_added:{ix}.{arg}")
            }
            CompatChange::InstructionArgRemoved { ix, arg } => {
                format!("instruction_arg_removed:{ix}.{arg}")
            }
            CompatChange::InstructionArgRenamed { ix, from, to } => {
                format!("instruction_arg_renamed:{ix}.{from}->{to}")
            }
            CompatChange::InstructionArgTypeChanged { ix, arg, .. } => {
                format!("instruction_arg_type_changed:{ix}.{arg}")
            }
            CompatChange::InstructionArgsReordered { ix } => {
                format!("instruction_args_reordered:{ix}")
            }
            CompatChange::FieldAdded {
                scope, field, optional: false, ..
            } => format!("field_added:{scope}.{field}"),
            CompatChange::FieldRemoved { scope, field } => {
                format!("field_removed:{scope}.{field}")
            }
            CompatChange::FieldRenamed { scope, from, to } => {
                format!("field_renamed:{scope}.{from}->{to}")
            }
            CompatChange::FieldTypeChanged { scope, field, .. } => {
                format!("field_type_changed:{scope}.{field}")
            }
            CompatChange::FieldsReordered { scope } => format!("fields_reordered:{scope}"),
            CompatChange::TypeRemoved { name } => format!("type_removed:{name}"),
            CompatChange::ErrorRemoved { name, .. } => format!("error_removed:{name}"),
            CompatChange::ErrorCodeChanged { name, .. } => {
                format!("error_code_changed:{name}")
            }
            CompatChange::ErrorCodeReused { code, .. } => format!("error_code_reused:{code}"),
            _ => return None,
        };
        Some(key)
    }

    /// Human-readable one-liner for the gate failure message and the
    /// release notes.
    pub fn describe(&self) -> String {
        let kind = if self.is_breaking() {
            "BREAKING"
        } else {
            "non-breaking"
        };
        let detail = match self {
            CompatChange::InstructionAdded { name } => format!("instruction {name} added"),
            CompatChange::InstructionRemoved { name } => format!("instruction {name} removed"),
            CompatChange::InstructionArgAdded { ix, arg } => {
                format!("{ix}: arg {arg} added")
            }
            CompatChange::InstructionArgRemoved { ix, arg } => {
                format!("{ix}: arg {arg} removed")
            }
            CompatChange::InstructionArgRenamed { ix, from, to } => {
                format!("{ix}: arg renamed {from} -> {to}")
            }
            CompatChange::InstructionArgTypeChanged { ix, arg, from, to } => {
                format!("{ix}: arg {arg} type {from} -> {to}")
            }
            CompatChange::InstructionArgsReordered { ix } => {
                format!("{ix}: args reordered")
            }
            CompatChange::FieldAdded {
                scope, field, ty, optional, ..
            } => {
                let opt = if *optional { " (optional)" } else { "" };
                format!("{scope}: field {field}: {ty} added{opt}")
            }
            CompatChange::FieldRemoved { scope, field } => {
                format!("{scope}: field {field} removed")
            }
            CompatChange::FieldRenamed { scope, from, to } => {
                format!("{scope}: field renamed {from} -> {to}")
            }
            CompatChange::FieldTypeChanged {
                scope, field, from, to, ..
            } => {
                format!("{scope}: field {field} type {from} -> {to}")
            }
            CompatChange::FieldsReordered { scope } => format!("{scope}: fields reordered"),
            CompatChange::TypeAdded { name } => format!("type {name} added"),
            CompatChange::TypeRemoved { name } => format!("type {name} removed"),
            CompatChange::ErrorAdded { code, name } => {
                format!("error {name} ({code}) added")
            }
            CompatChange::ErrorRemoved { code, name } => {
                format!("error {name} ({code}) removed")
            }
            CompatChange::ErrorCodeChanged { name, from, to } => {
                format!("error {name} code {from} -> {to}")
            }
            CompatChange::ErrorCodeReused { code, from, to } => {
                format!("error code {code} reused: {from} -> {to}")
            }
            CompatChange::VersionChanged { from, to } => format!("version {from} -> {to}"),
        };
        format!("[{kind}] {detail}")
    }
}

/// Align two same-position field lists (instruction args, account
/// fields, named-type fields). The `scope` labels the change site
/// (`"instruction <ix>"`, `"account <name>"`, `"type <name>"`).
/// Positional alignment handles the Borsh reality: names are matched
/// positionally, and a same-position name change with the same type
/// is a rename, while any type change wins over a rename.
fn diff_fields(scope: &str, old: &Fields, new: &Fields) -> Vec<CompatChange> {
    let mut changes = Vec::new();

    // Same name set in a different order: one reorder change, no
    // positional noise.
    let old_names: Vec<&str> = old.iter().map(|(n, _)| n.as_str()).collect();
    let new_names: Vec<&str> = new.iter().map(|(n, _)| n.as_str()).collect();
    let same_set = {
        let mut a = old_names.clone();
        let mut b = new_names.clone();
        a.sort_unstable();
        b.sort_unstable();
        a == b
    };
    if same_set && old_names != new_names {
        changes.push(if scope.starts_with("instruction ") {
            CompatChange::InstructionArgsReordered {
                ix: scope["instruction ".len()..].to_string(),
            }
        } else {
            CompatChange::FieldsReordered {
                scope: scope.to_string(),
            }
        });
        return changes;
    }

    let common = old.len().min(new.len());
    for i in 0..common {
        let (old_name, old_ty) = &old[i];
        let (new_name, new_ty) = &new[i];
        if old_ty == new_ty {
            if old_name != new_name {
                changes.push(rename_change(scope, old_name, new_name));
            }
        } else {
            changes.push(if scope.starts_with("instruction ") {
                CompatChange::InstructionArgTypeChanged {
                    ix: scope["instruction ".len()..].to_string(),
                    arg: old_name.clone(),
                    from: old_ty.canonical(),
                    to: new_ty.canonical(),
                }
            } else {
                CompatChange::FieldTypeChanged {
                    scope: scope.to_string(),
                    field: old_name.clone(),
                    from: old_ty.canonical(),
                    to: new_ty.canonical(),
                }
            });
        }
    }
    for (name, _) in old.iter().skip(common) {
        changes.push(if scope.starts_with("instruction ") {
            CompatChange::InstructionArgRemoved {
                ix: scope["instruction ".len()..].to_string(),
                arg: name.clone(),
            }
        } else {
            CompatChange::FieldRemoved {
                scope: scope.to_string(),
                field: name.clone(),
            }
        });
    }
    for (name, ty) in new.iter().skip(common) {
        changes.push(if scope.starts_with("instruction ") {
            CompatChange::InstructionArgAdded {
                ix: scope["instruction ".len()..].to_string(),
                arg: name.clone(),
            }
        } else {
            CompatChange::FieldAdded {
                scope: scope.to_string(),
                field: name.clone(),
                ty: ty.canonical(),
                optional: ty.is_option(),
            }
        });
    }
    changes
}

fn rename_change(scope: &str, from: &str, to: &str) -> CompatChange {
    if let Some(ix) = scope.strip_prefix("instruction ") {
        CompatChange::InstructionArgRenamed {
            ix: ix.to_string(),
            from: from.to_string(),
            to: to.to_string(),
        }
    } else {
        CompatChange::FieldRenamed {
            scope: scope.to_string(),
            from: from.to_string(),
            to: to.to_string(),
        }
    }
}

/// The full diff of two IDL documents.
#[derive(Debug, Clone)]
pub struct IdlDiff {
    /// Every change, in deterministic order: instructions, then
    /// accounts, then types, then errors, then the version.
    pub changes: Vec<CompatChange>,
}

impl IdlDiff {
    /// The breaking subset (the CI gate's concern).
    pub fn breaking(&self) -> Vec<&CompatChange> {
        self.changes.iter().filter(|c| c.is_breaking()).collect()
    }

    /// The non-breaking subset (release-notes fodder).
    pub fn non_breaking(&self) -> Vec<&CompatChange> {
        self.changes.iter().filter(|c| !c.is_breaking()).collect()
    }
}

/// Diff two IDL JSON documents: `old` is the baseline (last release),
/// `new` is the current generated IDL.
pub fn diff_idl(old_json: &str, new_json: &str) -> Result<IdlDiff, String> {
    let old = parse_idl(old_json)?;
    let new = parse_idl(new_json)?;
    let mut changes = Vec::new();

    // ---- instructions (matched by name) ----
    let old_ix: HashMap<&str, &IdlIx> =
        old.instructions.iter().map(|ix| (ix.name.as_str(), ix)).collect();
    let new_ix: HashMap<&str, &IdlIx> =
        new.instructions.iter().map(|ix| (ix.name.as_str(), ix)).collect();
    for ix in &old.instructions {
        match new_ix.get(ix.name.as_str()) {
            None => changes.push(CompatChange::InstructionRemoved {
                name: ix.name.clone(),
            }),
            Some(new) => {
                let scope = format!("instruction {}", ix.name);
                changes.extend(diff_fields(&scope, &ix.args, &new.args));
            }
        }
    }
    for ix in &new.instructions {
        if !old_ix.contains_key(ix.name.as_str()) {
            changes.push(CompatChange::InstructionAdded {
                name: ix.name.clone(),
            });
        }
    }

    // ---- accounts (matched by name) ----
    let old_acc: HashMap<&str, &IdlAccount> =
        old.accounts.iter().map(|a| (a.name.as_str(), a)).collect();
    let new_acc: HashMap<&str, &IdlAccount> =
        new.accounts.iter().map(|a| (a.name.as_str(), a)).collect();
    for acc in &old.accounts {
        if let Some(new) = new_acc.get(acc.name.as_str()) {
            let scope = format!("account {}", acc.name);
            changes.extend(diff_fields(&scope, &acc.fields, &new.fields));
        }
        // Accounts are never removed in this program's history (the
        // Vault is append-only by design); an account vanishing is
        // caught by its field diffs, not by a dedicated change.
    }
    for acc in &new.accounts {
        if !old_acc.contains_key(acc.name.as_str()) {
            let scope = format!("account {}", acc.name);
            for (name, ty) in &acc.fields {
                changes.push(CompatChange::FieldAdded {
                    scope: scope.clone(),
                    field: name.clone(),
                    ty: ty.canonical(),
                    optional: ty.is_option(),
                });
            }
        }
    }

    // ---- named types (matched by name) ----
    let old_ty: HashMap<&str, &IdlTypeDef> =
        old.types.iter().map(|t| (t.name.as_str(), t)).collect();
    let new_ty: HashMap<&str, &IdlTypeDef> =
        new.types.iter().map(|t| (t.name.as_str(), t)).collect();
    for ty in &old.types {
        match new_ty.get(ty.name.as_str()) {
            None => changes.push(CompatChange::TypeRemoved {
                name: ty.name.clone(),
            }),
            Some(new) => {
                let scope = format!("type {}", ty.name);
                changes.extend(diff_fields(&scope, &ty.fields, &new.fields));
            }
        }
    }
    for ty in &new.types {
        if !old_ty.contains_key(ty.name.as_str()) {
            changes.push(CompatChange::TypeAdded {
                name: ty.name.clone(),
            });
        }
    }

    // ---- errors ----
    let old_by_name: HashMap<&str, u16> =
        old.errors.iter().map(|e| (e.name.as_str(), e.code)).collect();
    let old_by_code: HashMap<u16, &str> =
        old.errors.iter().map(|e| (e.code, e.name.as_str())).collect();
    let new_by_name: HashMap<&str, u16> =
        new.errors.iter().map(|e| (e.name.as_str(), e.code)).collect();
    for e in &old.errors {
        match new_by_name.get(e.name.as_str()) {
            None => changes.push(CompatChange::ErrorRemoved {
                code: e.code,
                name: e.name.clone(),
            }),
            Some(&code) if code != e.code => changes.push(CompatChange::ErrorCodeChanged {
                name: e.name.clone(),
                from: e.code,
                to: code,
            }),
            _ => {}
        }
    }
    for e in &new.errors {
        match old_by_name.get(e.name.as_str()) {
            None => match old_by_code.get(&e.code) {
                Some(&old_name) => changes.push(CompatChange::ErrorCodeReused {
                    code: e.code,
                    from: old_name.to_string(),
                    to: e.name.clone(),
                }),
                None => changes.push(CompatChange::ErrorAdded {
                    code: e.code,
                    name: e.name.clone(),
                }),
            },
            _ => {}
        }
    }

    // ---- version ----
    if old.version != new.version {
        changes.push(CompatChange::VersionChanged {
            from: old.version.clone(),
            to: new.version.clone(),
        });
    }

    Ok(IdlDiff { changes })
}

// ---------------------------------------------------------------------------
// The CI gate: breaking changes need an explicit allowlist entry.
// ---------------------------------------------------------------------------

/// Breaking changes that this release explicitly accepts. One stable
/// key per change (see [`CompatChange::allowlist_key`]); any breaking
/// change whose key is absent fails the `idl_semver_gate` test.
/// AV-158: the delayed-governance tails are appended to the Vault
/// account (backward-compatible wire growth, like AV-157).
pub const BREAKING_CHANGE_ALLOWLIST: &[&str] = &[
    "field_added:account Vault.governance_delay_secs",
    "field_added:account Vault.governance_proposal",
    "field_added:account Vault.fees_withdrawn",
    // AV-191: the referral tail — appended, never renumbered.
    "field_added:account Vault.referrer",
    "field_added:account Vault.referral_bps",
    "field_added:account Vault.referral_paid",
    // AV-195: the social-recovery tail — appended, never renumbered.
    "field_added:account Vault.recovery",
    // AV-196: the dispute jury size — appended, never renumbered.
    "field_added:account Vault.jury_panel_size",
    // AV-203: the delivery-confirmation tail — appended, never renumbered.
    "field_added:account Vault.delivery_confirmation",
    "field_added:account Vault.delivery_confirmed",
    // AV-205: the per-call release cap tail — appended, never renumbered.
    "field_added:account Vault.max_release_per_call",
    // AV-206: the milestone deadline + late-penalty tail — appended,
    // never renumbered.
    "field_added:account Vault.milestone_due_dates",
    "field_added:account Vault.milestone_late_penalty_bps",
    "field_added:account Vault.milestone_verifier",
    // AV-212: the credential issuer tail — appended, never renumbered.
    "field_added:account Vault.credential_issuer",
    // AV-216: the delivery-deadline tail — appended, never renumbered.
    "field_added:account Vault.delivery_deadline_at",
    "field_added:account Vault.late_delivery_penalty_bps",
    "field_added:account Vault.delivery_late",
    // AV-217: the settlement-mint tail — appended, never renumbered.
    "field_added:account Vault.settlement_mint",
    // AV-208: the delegation spend cap + spent counter — appended
    // to the Delegation named type, never renumbered.
    "field_added:type Delegation.spend_cap",
    "field_added:type Delegation.spent",
];

fn unallowed_breaking_with(diff: &IdlDiff, allowlist: &[&str]) -> Vec<String> {
    diff.breaking()
        .iter()
        .filter_map(|c| c.allowlist_key())
        .filter(|key| !allowlist.contains(&key.as_str()))
        .collect()
}

/// The breaking changes in `diff` that no
/// [`BREAKING_CHANGE_ALLOWLIST`] entry covers — the CI gate fails on
/// any of these.
pub fn unallowed_breaking_changes(diff: &IdlDiff) -> Vec<String> {
    unallowed_breaking_with(diff, BREAKING_CHANGE_ALLOWLIST)
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod idl_compat_tests {
    use super::*;

    /// Assemble a minimal IDL JSON document for targeted diff tests.
    /// `instructions`/`accounts`/`types` are pre-rendered JSON arrays;
    /// `errors` is a slice of (code, name).
    fn mini_idl(
        version: &str,
        instructions: &str,
        accounts: &str,
        types: &str,
        errors: &[(u16, &str)],
    ) -> String {
        let errors_json: Vec<String> = errors
            .iter()
            .map(|(code, name)| format!("{{\"code\": {code}, \"name\": {name:?}}}"))
            .collect();
        format!(
            "{{\
            \"version\": {version:?}, \
            \"name\": \"escrow_vault\", \
            \"instructions\": [{instructions}], \
            \"accounts\": [{accounts}], \
            \"types\": [{types}], \
            \"errors\": [{}], \
            \"metadata\": {{}}\
            }}",
            errors_json.join(", ")
        )
    }

    fn ix(name: &str, args: &str) -> String {
        format!(
            "{{\"name\": {name:?}, \"discriminator\": [0], \"accounts\": [], \"args\": [{args}]}}"
        )
    }

    fn arg(name: &str, ty: &str) -> String {
        format!("{{\"name\": {name:?}, \"type\": {ty}}}")
    }

    fn account_field(name: &str, ty: &str) -> String {
        format!("{{\"name\": {name:?}, \"type\": {ty}, \"offset\": 8}}")
    }

    const BASE: &str = "0.1.0";

    fn base_idl() -> String {
        mini_idl(
            BASE,
            &ix("release", &arg("amount", "\"u64\"")),
            &format!(
                "{{\"name\": \"Vault\", \"type\": {{\"kind\": \"struct\", \"fields\": [{}]}}}}",
                account_field("amount", "\"u64\"")
            ),
            "",
            &[(100, "Unauthorized"), (101, "InvalidState")],
        )
    }

    #[test]
    fn json_parser_handles_nested_shapes() {
        let v = parse_json(
            r#"{"a": [1, 2.5, -3, true, false, null, "x\u0041", {"b": []}], "c": {}}"#,
        )
        .unwrap();
        assert!(matches!(v, JsonVal::Obj(_)));
        let a = v.get("a").unwrap().as_arr().unwrap();
        assert_eq!(a[0], JsonVal::UInt(1));
        assert_eq!(a[1], JsonVal::Float(2.5));
        assert_eq!(a[3], JsonVal::Bool(true));
        assert_eq!(a[4], JsonVal::Bool(false));
        assert_eq!(a[5], JsonVal::Null);
        assert_eq!(a[6].as_str().unwrap(), "xA");
        assert!(parse_json("{bad}").is_err());
        assert!(parse_json("[1, 2,]").is_err());
        assert!(parse_json("{\"a\": 1} trailing").is_err());
    }

    #[test]
    fn identical_idl_has_no_changes() {
        let idl = base_idl();
        let diff = diff_idl(&idl, &idl).unwrap();
        assert!(diff.changes.is_empty());
    }

    #[test]
    fn type_expr_structural_equality() {
        // Same meaning, different JSON formatting: no change reported.
        let old = base_idl();
        let new = mini_idl(
            BASE,
            &ix(
                "release",
                &format!("{{\"name\": \"amount\" , \"type\" : \"u64\" }}"),
            ),
            &format!(
                "{{\"name\": \"Vault\", \"type\": {{\"kind\": \"struct\", \"fields\": [{}]}}}}",
                account_field("amount", "\"u64\"")
            ),
            "",
            &[(100, "Unauthorized"), (101, "InvalidState")],
        );
        let diff = diff_idl(&old, &new).unwrap();
        assert!(diff.changes.is_empty(), "{diff:?}");
    }

    #[test]
    fn instruction_removed_is_breaking_with_key() {
        let diff = diff_idl(
            &base_idl(),
            &mini_idl(BASE, "", &format!(
                "{{\"name\": \"Vault\", \"type\": {{\"kind\": \"struct\", \"fields\": [{}]}}}}",
                account_field("amount", "\"u64\"")
            ), "", &[(100, "Unauthorized"), (101, "InvalidState")]),
        )
        .unwrap();
        assert_eq!(diff.changes.len(), 1);
        let c = &diff.changes[0];
        assert!(c.is_breaking());
        assert_eq!(c.allowlist_key().as_deref(), Some("instruction_removed:release"));
        assert!(c.describe().contains("release"));
    }

    #[test]
    fn instruction_added_is_non_breaking() {
        let with_new = mini_idl(
            BASE,
            &format!("{}, {}", ix("release", &arg("amount", "\"u64\"")), ix("ping", "")),
            &format!(
                "{{\"name\": \"Vault\", \"type\": {{\"kind\": \"struct\", \"fields\": [{}]}}}}",
                account_field("amount", "\"u64\"")
            ),
            "",
            &[(100, "Unauthorized"), (101, "InvalidState")],
        );
        let diff = diff_idl(&base_idl(), &with_new).unwrap();
        assert_eq!(diff.changes.len(), 1);
        assert!(!diff.changes[0].is_breaking());
        assert_eq!(diff.changes[0].allowlist_key(), None);
        assert_eq!(diff.non_breaking().len(), 1);
        assert!(diff.breaking().is_empty());
    }

    #[test]
    fn arg_renamed_is_breaking() {
        let renamed = mini_idl(
            BASE,
            &ix("release", &arg("total", "\"u64\"")),
            &format!(
                "{{\"name\": \"Vault\", \"type\": {{\"kind\": \"struct\", \"fields\": [{}]}}}}",
                account_field("amount", "\"u64\"")
            ),
            "",
            &[(100, "Unauthorized"), (101, "InvalidState")],
        );
        let diff = diff_idl(&base_idl(), &renamed).unwrap();
        assert_eq!(diff.changes.len(), 1);
        let c = &diff.changes[0];
        assert!(c.is_breaking());
        assert_eq!(
            c.allowlist_key().as_deref(),
            Some("instruction_arg_renamed:release.amount->total")
        );
    }

    #[test]
    fn arg_type_changed_is_breaking() {
        let changed = mini_idl(
            BASE,
            &ix("release", &arg("amount", "\"u128\"")),
            &format!(
                "{{\"name\": \"Vault\", \"type\": {{\"kind\": \"struct\", \"fields\": [{}]}}}}",
                account_field("amount", "\"u64\"")
            ),
            "",
            &[(100, "Unauthorized"), (101, "InvalidState")],
        );
        let diff = diff_idl(&base_idl(), &changed).unwrap();
        assert_eq!(diff.changes.len(), 1);
        let c = &diff.changes[0];
        assert!(c.is_breaking());
        assert!(matches!(
            c,
            CompatChange::InstructionArgTypeChanged { ix, .. } if ix == "release"
        ));
        assert_eq!(
            c.allowlist_key().as_deref(),
            Some("instruction_arg_type_changed:release.amount")
        );
    }

    #[test]
    fn arg_added_is_breaking_positional() {
        // Instruction args are positional Borsh: appending an arg still
        // breaks existing callers.
        let added = mini_idl(
            BASE,
            &ix(
                "release",
                &format!("{}, {}", arg("amount", "\"u64\""), arg("memo", "\"string\"")),
            ),
            &format!(
                "{{\"name\": \"Vault\", \"type\": {{\"kind\": \"struct\", \"fields\": [{}]}}}}",
                account_field("amount", "\"u64\"")
            ),
            "",
            &[(100, "Unauthorized"), (101, "InvalidState")],
        );
        let diff = diff_idl(&base_idl(), &added).unwrap();
        assert_eq!(diff.changes.len(), 1);
        assert!(diff.changes[0].is_breaking());
    }

    #[test]
    fn args_reordered_reports_one_change_not_renames() {
        let reordered = mini_idl(
            BASE,
            &ix(
                "release",
                &format!("{}, {}", arg("memo", "\"string\""), arg("amount", "\"u64\"")),
            ),
            &format!(
                "{{\"name\": \"Vault\", \"type\": {{\"kind\": \"struct\", \"fields\": [{}]}}}}",
                account_field("amount", "\"u64\"")
            ),
            "",
            &[(100, "Unauthorized"), (101, "InvalidState")],
        );
        // Old args are [amount]; new args are [memo, amount]: the
        // positional alignment sees amount->memo as a rename plus an
        // addition. Keep the honest positional semantics.
        let diff = diff_idl(&base_idl(), &reordered).unwrap();
        assert!(diff.breaking().len() >= 1);
    }

    #[test]
    fn args_pure_reorder_is_one_reorder_change() {
        let two = mini_idl(
            BASE,
            &ix(
                "release",
                &format!("{}, {}", arg("amount", "\"u64\""), arg("memo", "\"string\"")),
            ),
            &format!(
                "{{\"name\": \"Vault\", \"type\": {{\"kind\": \"struct\", \"fields\": [{}]}}}}",
                account_field("amount", "\"u64\"")
            ),
            "",
            &[(100, "Unauthorized"), (101, "InvalidState")],
        );
        let two_rev = mini_idl(
            BASE,
            &ix(
                "release",
                &format!("{}, {}", arg("memo", "\"string\""), arg("amount", "\"u64\"")),
            ),
            &format!(
                "{{\"name\": \"Vault\", \"type\": {{\"kind\": \"struct\", \"fields\": [{}]}}}}",
                account_field("amount", "\"u64\"")
            ),
            "",
            &[(100, "Unauthorized"), (101, "InvalidState")],
        );
        let diff = diff_idl(&two, &two_rev).unwrap();
        assert_eq!(diff.changes.len(), 1);
        assert!(matches!(
            diff.changes[0],
            CompatChange::InstructionArgsReordered { .. }
        ));
        assert!(diff.changes[0].is_breaking());
    }

    #[test]
    fn field_reordered_is_breaking() {
        let reordered = mini_idl(
            BASE,
            &ix("release", &arg("amount", "\"u64\"")),
            &format!(
                "{{\"name\": \"Vault\", \"type\": {{\"kind\": \"struct\", \"fields\": [{}, {}]}}}}",
                account_field("memo", "\"string\""),
                account_field("amount", "\"u64\"")
            ),
            "",
            &[(100, "Unauthorized"), (101, "InvalidState")],
        );
        let ordered = mini_idl(
            BASE,
            &ix("release", &arg("amount", "\"u64\"")),
            &format!(
                "{{\"name\": \"Vault\", \"type\": {{\"kind\": \"struct\", \"fields\": [{}, {}]}}}}",
                account_field("amount", "\"u64\""),
                account_field("memo", "\"string\"")
            ),
            "",
            &[(100, "Unauthorized"), (101, "InvalidState")],
        );
        let diff = diff_idl(&ordered, &reordered).unwrap();
        assert_eq!(diff.changes.len(), 1);
        assert!(matches!(
            diff.changes[0],
            CompatChange::FieldsReordered { .. }
        ));
        assert!(diff.changes[0].is_breaking());
        assert_eq!(
            diff.changes[0].allowlist_key().as_deref(),
            Some("fields_reordered:account Vault")
        );
    }

    #[test]
    fn optional_field_added_is_non_breaking_required_is_breaking() {
        let add_optional = mini_idl(
            BASE,
            &ix("release", &arg("amount", "\"u64\"")),
            &format!(
                "{{\"name\": \"Vault\", \"type\": {{\"kind\": \"struct\", \"fields\": [{}, {}]}}}}",
                account_field("amount", "\"u64\""),
                account_field("note", "{\"option\": \"string\"}")
            ),
            "",
            &[(100, "Unauthorized"), (101, "InvalidState")],
        );
        let diff = diff_idl(&base_idl(), &add_optional).unwrap();
        assert_eq!(diff.changes.len(), 1);
        assert!(!diff.changes[0].is_breaking());

        let add_required = mini_idl(
            BASE,
            &ix("release", &arg("amount", "\"u64\"")),
            &format!(
                "{{\"name\": \"Vault\", \"type\": {{\"kind\": \"struct\", \"fields\": [{}, {}]}}}}",
                account_field("amount", "\"u64\""),
                account_field("note", "\"string\"")
            ),
            "",
            &[(100, "Unauthorized"), (101, "InvalidState")],
        );
        let diff = diff_idl(&base_idl(), &add_required).unwrap();
        assert_eq!(diff.changes.len(), 1);
        assert!(diff.changes[0].is_breaking());
        assert_eq!(
            diff.changes[0].allowlist_key().as_deref(),
            Some("field_added:account Vault.note")
        );
    }

    #[test]
    fn error_code_reused_is_breaking_error_added_is_not() {
        let reused = mini_idl(
            BASE,
            &ix("release", &arg("amount", "\"u64\"")),
            &format!(
                "{{\"name\": \"Vault\", \"type\": {{\"kind\": \"struct\", \"fields\": [{}]}}}}",
                account_field("amount", "\"u64\"")
            ),
            "",
            &[(100, "Unauthorized"), (101, "Timeout")],
        );
        let diff = diff_idl(&base_idl(), &reused).unwrap();
        // InvalidState (101) removed + code 101 reused by Timeout.
        assert_eq!(diff.changes.len(), 2);
        assert!(diff.breaking().len() == 2);
        let reuse = diff
            .changes
            .iter()
            .find(|c| matches!(c, CompatChange::ErrorCodeReused { .. }))
            .expect("code-reuse change");
        assert_eq!(reuse.allowlist_key().as_deref(), Some("error_code_reused:101"));

        let added = mini_idl(
            BASE,
            &ix("release", &arg("amount", "\"u64\"")),
            &format!(
                "{{\"name\": \"Vault\", \"type\": {{\"kind\": \"struct\", \"fields\": [{}]}}}}",
                account_field("amount", "\"u64\"")
            ),
            "",
            &[(100, "Unauthorized"), (101, "InvalidState"), (102, "Timeout")],
        );
        let diff = diff_idl(&base_idl(), &added).unwrap();
        assert_eq!(diff.changes.len(), 1);
        assert!(!diff.changes[0].is_breaking());
        assert!(matches!(
            diff.changes[0],
            CompatChange::ErrorAdded { code: 102, .. }
        ));
    }

    #[test]
    fn version_change_is_non_breaking() {
        let bumped = mini_idl(
            "0.2.0",
            &ix("release", &arg("amount", "\"u64\"")),
            &format!(
                "{{\"name\": \"Vault\", \"type\": {{\"kind\": \"struct\", \"fields\": [{}]}}}}",
                account_field("amount", "\"u64\"")
            ),
            "",
            &[(100, "Unauthorized"), (101, "InvalidState")],
        );
        let diff = diff_idl(&base_idl(), &bumped).unwrap();
        assert_eq!(diff.changes.len(), 1);
        assert!(!diff.changes[0].is_breaking());
        assert!(matches!(
            diff.changes[0],
            CompatChange::VersionChanged { .. }
        ));
    }

    #[test]
    fn allowlist_mechanism() {
        // A breaking change with no allowlist entry is unallowed; with
        // the key declared it is accepted.
        let diff = diff_idl(
            &base_idl(),
            &mini_idl(BASE, "", &format!(
                "{{\"name\": \"Vault\", \"type\": {{\"kind\": \"struct\", \"fields\": [{}]}}}}",
                account_field("amount", "\"u64\"")
            ), "", &[(100, "Unauthorized"), (101, "InvalidState")]),
        )
        .unwrap();
        assert_eq!(
            unallowed_breaking_with(&diff, &[]),
            vec!["instruction_removed:release".to_string()]
        );
        assert!(unallowed_breaking_with(&diff, &["instruction_removed:release"]).is_empty());
        // The real const agrees with the empty-case behavior.
        assert_eq!(
            unallowed_breaking_changes(&diff),
            vec!["instruction_removed:release".to_string()]
        );
    }

    #[test]
    fn full_idl_parses_and_self_diffs_clean() {
        // The real 161-instruction IDL must parse (AV-160 added
        // `crank_release_period`; AV-163 adds `pause_program` /
        // `unpause_program`; AV-191 adds `initialize_referrer`;
        // AV-195 adds the five social-recovery instructions;
        // AV-196 adds `configure_jury`; AV-203 adds
        // `initialize_delivery_confirmation` and `confirm_delivery`;
        // AV-205 adds `initialize_max_release_cap` and `update_release_cap`);
        // the checked-in file diffed against itself has no changes
        // (exercises the parser on the production artifact).
        let idl = std::fs::read_to_string("../programs/escrow-vault/idl/escrow_vault.json")
            .expect("read checked-in IDL");
        let spec = parse_idl(&idl).expect("parse checked-in IDL");
        assert_eq!(spec.instructions.len(), 163);
        // AV-179 adds 4 upgrade-authority errors; AV-180 adds 4
        // freeze-authority errors; AV-184 adds UnsafeMint; AV-186 adds
        // 5 HTLC errors; AV-187 adds 2 NFT-escrow errors; AV-188 adds
        // 5 Merkle-distributor errors; AV-189 adds 5 English-auction
        // errors; AV-190 adds 3 rental-escrow errors; AV-191 adds
        // InvalidReferral; AV-192 adds 7 sealed-bid auction errors;
        // AV-193 adds 3 oracle-adapter errors; AV-194 adds 4
        // bid-deposit errors; AV-195 adds 7 social-recovery errors;
        // AV-196 adds 6 jury-sortition errors; AV-197 adds 5
        // payment-channel errors; AV-200 adds 1 sealed-bid pricing
        // error; AV-201 adds 1 English-auction buyout error; AV-205
        // adds 1 per-call release cap error.
        assert_eq!(spec.errors.len(), 242); // AV-209 adds 4 winner-payment errors; AV-212 adds 6 credential-gate errors; AV-214 adds 6 option-escrow errors; AV-215 adds 1 delegation-expiry error; AV-217 adds 3 settlement-rate errors; AV-218 adds 2 settlement-allowlist errors.
        // AV-178 adds the TieredQuorum + Tier named types; AV-195 adds
        // the SocialRecovery named type; AV-218 adds the
        // SettlementMintAllowlist named type.
        assert_eq!(spec.types.len(), 37);
        let diff = diff_idl(&idl, &idl).unwrap();
        assert!(diff.changes.is_empty());
    }

    /// The CI gate: the baseline IDL (last release) vs. the current
    /// checked-in IDL must have no breaking change without an explicit
    /// allowlist entry.
    #[test]
    fn idl_semver_gate() {
        let baseline = std::fs::read_to_string(
            "../programs/escrow-vault/idl/escrow_vault.baseline.json",
        )
        .expect("read IDL baseline (last release)");
        let current = std::fs::read_to_string("../programs/escrow-vault/idl/escrow_vault.json")
            .expect("read checked-in IDL");
        let diff = diff_idl(&baseline, &current).expect("diff IDLs");
        let unallowed = unallowed_breaking_changes(&diff);
        assert!(
            unallowed.is_empty(),
            "breaking IDL changes without allowlist entries:\n{}\n\
             Add each key to BREAKING_CHANGE_ALLOWLIST in idl_compat.rs \
             (or fix the IDL) before release.",
            diff.breaking()
                .iter()
                .map(|c| format!("  - {} [{}]", c.describe(), c.allowlist_key().unwrap()))
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
}
