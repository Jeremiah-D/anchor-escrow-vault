//! AV-92: deterministic vault PDA derivation (off-chain, zero dependencies).
//!
//! Solana derives program addresses as
//! `sha256(seeds.. ++ [bump] ++ program_id ++ "ProgramDerivedAddress")`
//! and treats the result as a PDA only when it is *off* the ed25519
//! curve. This module hand-rolls both halves — the hash layout over
//! the crate's [`crate::sha256`] and the off-curve check over
//! hand-written ed25519 field arithmetic — so keeper/batch/close
//! tooling can derive the exact vault address a given seed set would
//! create on-chain, with no dependency beyond this crate.
//!
//! Design notes:
//!
//! - Real Solana PDAs never store their seeds on-chain, and this
//!   crate's vault layout is rent-critical (`VAULT_FIELDS` is the
//!   single source of truth — AV-10/11/12/13/14/15 each recomputed it
//!   precisely). Seeds therefore live **off-chain**: [`VaultSeeds`]
//!   is recorded on the watch structs ([`crate::WatchedEscrow`],
//!   [`crate::BatchWatchItem`], …) via `with_vault_seeds`, and the
//!   scans attach the derived [`VaultDerivation::address`] to their
//!   reports. The on-chain [`crate::Escrow`] layout is untouched.
//! - [`find_program_address`] is the unified derivation tool. The old
//!   multisig convention ("the caller runs its own
//!   `find_program_address`", AV-84) now resolves to this function —
//!   see [`crate::multisig`].
//! - [`is_on_ed25519_curve`] mirrors Solana's `Pubkey::is_on_curve`
//!   (Edwards decompression against the curve equation). One subtlety
//!   it preserves: the all-zero 32 bytes *are* on the curve — they
//!   decode to the 2-torsion point `(±√−1, 0)` (`x² = −1` is solvable
//!   because `p ≡ 1 (mod 4)`). A PDA candidate hashing to all-zero
//!   would be rejected by Solana too, so the bump search treats it as
//!   on-curve.

use super::EscrowError;

/// Maximum number of seeds in one PDA derivation (Solana `MAX_SEEDS`).
pub const MAX_PDA_SEEDS: usize = 16;

/// Maximum length of a single seed in bytes (Solana `MAX_SEED_LENGTH`).
pub const MAX_PDA_SEED_LEN: usize = 32;

/// Domain separator Solana mixes into every PDA derivation hash.
pub const PDA_DOMAIN: &[u8] = b"ProgramDerivedAddress";

/// Validate a PDA seed list against the Solana `create_program_address`
/// limits: at most [`MAX_PDA_SEEDS`] seeds, each at most
/// [`MAX_PDA_SEED_LEN`] bytes. Violations are
/// [`EscrowError::InvalidVaultSeeds`] (code 149) — the derivation is
/// never attempted with invalid seeds.
pub fn validate_pda_seeds(seeds: &[&[u8]]) -> Result<(), EscrowError> {
    if seeds.len() > MAX_PDA_SEEDS {
        return Err(EscrowError::InvalidVaultSeeds);
    }
    for seed in seeds {
        if seed.len() > MAX_PDA_SEED_LEN {
            return Err(EscrowError::InvalidVaultSeeds);
        }
    }
    Ok(())
}

/// A validated PDA seed list. Fixed-size so the watch structs that
/// record it stay `Copy` (16 seeds × 32 bytes + lengths).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultSeeds {
    seeds: [[u8; 32]; MAX_PDA_SEEDS],
    lens: [u8; MAX_PDA_SEEDS],
    count: u8,
}

impl VaultSeeds {
    /// Validate and store the seed list. An empty list is allowed
    /// (Solana permits it; the bump seed makes `find` non-empty in
    /// practice).
    pub fn new(seeds: &[&[u8]]) -> Result<Self, EscrowError> {
        validate_pda_seeds(seeds)?;
        let mut out = Self {
            seeds: [[0u8; 32]; MAX_PDA_SEEDS],
            lens: [0u8; MAX_PDA_SEEDS],
            count: seeds.len() as u8,
        };
        for (i, seed) in seeds.iter().enumerate() {
            out.seeds[i][..seed.len()].copy_from_slice(seed);
            out.lens[i] = seed.len() as u8;
        }
        Ok(out)
    }

    /// Number of recorded seeds.
    pub fn seed_count(&self) -> usize {
        self.count as usize
    }

    /// The `i`-th seed (`i < seed_count()`).
    pub fn seed(&self, i: usize) -> &[u8] {
        &self.seeds[i][..self.lens[i] as usize]
    }

    /// Iterate the recorded seeds in order.
    pub fn iter(&self) -> impl Iterator<Item = &[u8]> + '_ {
        (0..self.seed_count()).map(|i| self.seed(i))
    }
}

/// Validated PDA derivation inputs recorded off-chain for one watched
/// vault: the seed list plus the program id they derive under. The
/// derivation is meaningless without the program id, so the two travel
/// together; the scans that attach `vault_address` to their reports
/// need no new parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultDerivation {
    /// The validated seed list.
    pub seeds: VaultSeeds,
    /// The program id the vault PDA derives under.
    pub program_id: [u8; 32],
}

impl VaultDerivation {
    /// Record derivation inputs, validating the seeds.
    pub fn new(seeds: &[&[u8]], program_id: &[u8; 32]) -> Result<Self, EscrowError> {
        Ok(Self {
            seeds: VaultSeeds::new(seeds)?,
            program_id: *program_id,
        })
    }

    /// The canonical vault address: bump search then hash. `None`
    /// only when no bump in `0..=255` yields an off-curve address
    /// (does not happen in practice — roughly half the candidates are
    /// off-curve).
    pub fn address(&self) -> Option<[u8; 32]> {
        let mut buf: [&[u8]; MAX_PDA_SEEDS] = [&[]; MAX_PDA_SEEDS];
        let n = self.seeds.seed_count();
        for (i, slot) in buf.iter_mut().enumerate().take(n) {
            *slot = self.seeds.seed(i);
        }
        find_program_address(&buf[..n], &self.program_id).map(|(addr, _)| addr)
    }

    /// The bump [`VaultDerivation::address`] was derived with.
    pub fn bump(&self) -> Option<u8> {
        let mut buf: [&[u8]; MAX_PDA_SEEDS] = [&[]; MAX_PDA_SEEDS];
        let n = self.seeds.seed_count();
        for (i, slot) in buf.iter_mut().enumerate().take(n) {
            *slot = self.seeds.seed(i);
        }
        find_vault_bump(&buf[..n], &self.program_id)
    }
}

/// Derive the vault PDA for explicit seeds, program id and bump:
/// `sha256(seeds.. ++ [bump] ++ program_id ++ "ProgramDerivedAddress")`.
///
/// This is Solana's `create_program_address` byte layout exactly — the
/// bump travels as the last seed, then the program id, then the domain
/// separator. Seeds are validated first ([`EscrowError::InvalidVaultSeeds`]
/// on violation); the hash itself cannot fail.
pub fn derive_vault_address(
    seeds: &[&[u8]],
    program_id: &[u8; 32],
    bump: u8,
) -> Result<[u8; 32], EscrowError> {
    validate_pda_seeds(seeds)?;
    Ok(derive_unchecked(seeds, program_id, bump))
}

/// The same hash without seed validation — callers have validated already.
fn derive_unchecked(seeds: &[&[u8]], program_id: &[u8; 32], bump: u8) -> [u8; 32] {
    let mut msg = Vec::with_capacity(
        seeds.iter().map(|s| s.len()).sum::<usize>() + 1 + 32 + PDA_DOMAIN.len(),
    );
    for seed in seeds {
        msg.extend_from_slice(seed);
    }
    msg.push(bump);
    msg.extend_from_slice(program_id);
    msg.extend_from_slice(PDA_DOMAIN);
    super::sha256(&msg)
}

/// Whether the 32 bytes decode to a point on the ed25519 curve —
/// Solana's `Pubkey::is_on_curve` (Edwards decompression).
///
/// Decompresses `y` from the low 255 bits (rejecting `y >= p`), then
/// checks the curve equation `-x² + y² = 1 + d·x²·y²` via
/// `x² = (y²−1) / (d·y²+1)`: for `p ≡ 5 (mod 8)` the square root is
/// `v^((p+3)/8)` with a `√−1` fix-up when needed, and the equation is
/// re-verified on the recovered `x`, so a wrong candidate can never
/// pass. The sign bit is irrelevant to membership — `(x, y)` and
/// `(-x, y)` are both curve points.
///
/// Field arithmetic is hand-rolled over 4×u64 limbs (`p = 2^255−19`,
/// `2^256 ≡ 38`); see the `Fe` internals below. Inversion and square
/// roots go through Fermat exponentiation — no lookup tables, no
/// branches on secret data (this is off-chain tooling, but the code
/// stays constant-shape anyway).
pub fn is_on_ed25519_curve(bytes: &[u8; 32]) -> bool {
    let mut y_bytes = *bytes;
    y_bytes[31] &= 0x7F;
    // The y < p gate runs on the raw bytes: `fe_from_bytes` reduces
    // mod p, which would map y = p to 0 (a valid point) and hide the
    // gate.
    if raw_bytes_ge_p(&y_bytes) {
        return false;
    }
    let y = Fe::from_bytes(&y_bytes);
    let y2 = y.mul(y);
    // den = d·y²+1; den = 0 has no affine solution (u ≠ 0 then, since
    // d ≠ −1), so it is off-curve by construction.
    let den = ED25519_D.mul(y2).add(Fe::ONE);
    if den == Fe::ZERO {
        return false;
    }
    let num = y2.sub(Fe::ONE);
    let v = num.mul(den.pow(P_MINUS_2));
    // sqrt for p ≡ 5 (mod 8): x = v^((p+3)/8); when that squares to −v
    // instead of v, multiply by √−1 = 2^((p−1)/4). The final equation
    // check decides — a non-residue fails both attempts.
    let mut x = v.pow(EXP_SQRT);
    if x.mul(x) != v {
        x = x.mul(SQRT_M1);
        if x.mul(x) != v {
            return false;
        }
    }
    true
}

/// Scan bumps from 255 down to 0 and return the first bump whose
/// derived address is off the ed25519 curve — Solana's
/// `find_program_address` bump search. `None` when the seeds are
/// invalid or (practically impossible) no bump qualifies.
pub fn find_vault_bump(seeds: &[&[u8]], program_id: &[u8; 32]) -> Option<u8> {
    if validate_pda_seeds(seeds).is_err() {
        return None;
    }
    let mut bump = 255u8;
    loop {
        if !is_on_ed25519_curve(&derive_unchecked(seeds, program_id, bump)) {
            return Some(bump);
        }
        if bump == 0 {
            return None;
        }
        bump -= 1;
    }
}

/// Solana-shaped PDA derivation: the canonical vault address plus the
/// bump it was derived with. This is the unified tool the old
/// "caller runs its own `find_program_address`" convention (AV-84,
/// [`crate::multisig`]) now resolves to.
pub fn find_program_address(
    seeds: &[&[u8]],
    program_id: &[u8; 32],
) -> Option<([u8; 32], u8)> {
    find_vault_bump(seeds, program_id).map(|bump| {
        // Seeds were validated by `find_vault_bump`.
        (derive_unchecked(seeds, program_id, bump), bump)
    })
}

// ---------------------------------------------------------------------------
// ed25519 field arithmetic: p = 2^255 − 19, 4 little-endian u64 limbs.
// ---------------------------------------------------------------------------

/// Field prime `p = 2^255 − 19` as 4 LE u64 limbs.
const FIELD_P: [u64; 4] = [
    0xFFFF_FFFF_FFFF_FFED,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFF,
    0x7FFF_FFFF_FFFF_FFFF,
];

/// `p − 2`, the Fermat inversion exponent.
const P_MINUS_2: [u64; 4] = [
    0xFFFF_FFFF_FFFF_FFEB,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFF,
    0x7FFF_FFFF_FFFF_FFFF,
];

/// `(p+3)/8 = 2^252 − 2`, the square-root exponent for `p ≡ 5 (mod 8)`.
const EXP_SQRT: [u64; 4] = [
    0xFFFF_FFFF_FFFF_FFFE,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFF,
    0x0FFF_FFFF_FFFF_FFFF,
];

/// √−1 mod p, i.e. `2^((p−1)/4)` (2 is a quadratic non-residue mod p
/// because `p ≡ 5 (mod 8)`). Verified by
/// `pda_tests::sqrt_m1_squares_to_minus_one`.
const SQRT_M1: Fe = Fe([
    0xC4EE1B274A0EA0B0,
    0x2F431806AD2FE478,
    0x2B4D00993DFBD7A7,
    0x2B8324804FC1DF0B,
]);

/// Edwards `d = −121665 · inv(121666) mod p`. Hardcoded (crate style:
/// cf. `SQUADS_V4_PROGRAM_ID`) and verified by
/// `pda_tests::ed25519_d_matches_definition`.
const ED25519_D: Fe = Fe([
    0x75EB4DCA135978A3,
    0x00700A4D4141D8AB,
    0x8CC740797779E898,
    0x52036CEE2B6FFE73,
]);

/// Compare raw little-endian bytes against `p` (before any modular
/// reduction).
fn raw_bytes_ge_p(yb: &[u8; 32]) -> bool {
    // p = 2^255 − 19 little-endian: 0xED, 0xFF×30, 0x7F.
    let mut p_bytes = [0xFFu8; 32];
    p_bytes[0] = 0xED;
    p_bytes[31] = 0x7F;
    for i in (0..32).rev() {
        if yb[i] != p_bytes[i] {
            return yb[i] > p_bytes[i];
        }
    }
    true
}

/// Field element mod `p`, 4 little-endian u64 limbs, always reduced
/// (`< p`) after each operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Fe([u64; 4]);

impl Fe {
    const ZERO: Fe = Fe([0, 0, 0, 0]);
    const ONE: Fe = Fe([1, 0, 0, 0]);

    fn from_bytes(b: &[u8; 32]) -> Fe {
        let mut t = [0u64; 16];
        for i in 0..4 {
            let mut c = [0u8; 8];
            c.copy_from_slice(&b[8 * i..8 * i + 8]);
            t[i] = u64::from_le_bytes(c);
        }
        // Input < 2^256: the reduce is just the conditional subtract.
        Self::reduce(&t)
    }

    /// Add `val` (< 2^128) at base-2^64 limb `k`, propagating carries.
    /// Keeps every limb `< 2^64` — the accumulator can never overflow.
    fn acc_add(t: &mut [u64; 16], mut val: u128, mut k: usize) {
        const M64: u128 = 0xFFFF_FFFF_FFFF_FFFF;
        while val != 0 {
            let s = t[k] as u128 + (val & M64);
            t[k] = s as u64;
            val = (val >> 64) + (s >> 64);
            k += 1;
            debug_assert!(k < t.len());
        }
    }

    /// Reduce the base-2^64 accumulator mod p. `2^256 ≡ 38`,
    /// `2^512 ≡ 38² = 1444`; products stay `< 2^510` so limbs past 8
    /// are zero.
    fn reduce(t: &[u64; 16]) -> Fe {
        debug_assert!(t[9..].iter().all(|&x| x == 0));
        let mut acc = [0u128; 5];
        for i in 0..4 {
            acc[i] = t[i] as u128;
        }
        for i in 0..4 {
            acc[i] += t[4 + i] as u128 * 38;
        }
        acc[0] += t[8] as u128 * 1444;
        for i in 0..4 {
            let c = acc[i] >> 64;
            acc[i] &= 0xFFFF_FFFF_FFFF_FFFF;
            acc[i + 1] += c;
        }
        // Fold the leftover high limb (`2^256 ≡ 38`) until stable —
        // at most two passes: the carry out of the low four limbs is
        // ≤ 1 each time.
        loop {
            let hi = acc[4];
            if hi == 0 {
                break;
            }
            acc[4] = 0;
            let mut c = hi * 38;
            for i in 0..4 {
                let chunk = c & 0xFFFF_FFFF_FFFF_FFFF;
                c >>= 64;
                let s = acc[i] + chunk;
                acc[i] = s & 0xFFFF_FFFF_FFFF_FFFF;
                c += s >> 64;
            }
            acc[4] += c;
        }
        let mut r = [acc[0] as u64, acc[1] as u64, acc[2] as u64, acc[3] as u64];
        // Value < 2^256 here, so at most two subtractions of p.
        for _ in 0..2 {
            if Self::ge_limbs(&r, &FIELD_P) {
                r = Self::sub_limbs(&r, &FIELD_P);
            }
        }
        Fe(r)
    }

    fn ge_limbs(a: &[u64; 4], b: &[u64; 4]) -> bool {
        for i in (0..4).rev() {
            if a[i] != b[i] {
                return a[i] > b[i];
            }
        }
        true
    }

    fn sub_limbs(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
        let mut r = [0u64; 4];
        let mut borrow: u64 = 0;
        for i in 0..4 {
            let (s1, bo1) = a[i].overflowing_sub(b[i]);
            let (s2, bo2) = s1.overflowing_sub(borrow);
            r[i] = s2;
            borrow = (bo1 || bo2) as u64;
        }
        r
    }

    fn add(self, rhs: Fe) -> Fe {
        let mut t = [0u64; 16];
        for i in 0..4 {
            Self::acc_add(&mut t, self.0[i] as u128 + rhs.0[i] as u128, i);
        }
        Self::reduce(&t)
    }

    fn sub(self, rhs: Fe) -> Fe {
        let mut r = [0u64; 4];
        let mut borrow: u64 = 0;
        for i in 0..4 {
            let (s1, bo1) = self.0[i].overflowing_sub(rhs.0[i]);
            let (s2, bo2) = s1.overflowing_sub(borrow);
            r[i] = s2;
            borrow = (bo1 || bo2) as u64;
        }
        if borrow != 0 {
            // The subtraction wrapped: add p back once.
            let mut carry: u64 = 0;
            for i in 0..4 {
                let s = r[i] as u128 + FIELD_P[i] as u128 + carry as u128;
                r[i] = s as u64;
                carry = (s >> 64) as u64;
            }
        }
        Fe(r)
    }

    fn mul(self, rhs: Fe) -> Fe {
        let mut t = [0u64; 16];
        for i in 0..4 {
            for j in 0..4 {
                Self::acc_add(&mut t, self.0[i] as u128 * rhs.0[j] as u128, i + j);
            }
        }
        Self::reduce(&t)
    }

    /// Square-and-multiply over the full 256-bit exponent.
    fn pow(self, exp: [u64; 4]) -> Fe {
        let mut r = Fe::ONE;
        for i in (0..4).rev() {
            for b in (0..64).rev() {
                r = r.mul(r);
                if (exp[i] >> b) & 1 == 1 {
                    r = r.mul(self);
                }
            }
        }
        r
    }
}

#[cfg(test)]
mod pda_tests {
    use super::*;

    fn hex32(b: &[u8; 32]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut s = String::with_capacity(64);
        for byte in b {
            s.push(HEX[(byte >> 4) as usize] as char);
            s.push(HEX[(byte & 0x0f) as usize] as char);
        }
        s
    }

    /// The Solana `create_program_address` byte layout, written
    /// independently of [`derive_vault_address`]: seeds in order, the
    /// bump as the last seed, the program id, then the domain
    /// separator. If the implementation's layout ever drifts from the
    /// spec, this test fails — the two layouts are written twice, on
    /// purpose.
    fn spec_layout(seeds: &[&[u8]], program_id: &[u8; 32], bump: u8) -> Vec<u8> {
        let mut v = Vec::new();
        for s in seeds {
            v.extend_from_slice(s);
        }
        v.push(bump);
        v.extend_from_slice(program_id);
        v.extend_from_slice(b"ProgramDerivedAddress");
        v
    }

    #[test]
    fn derive_layout_matches_solana_spec_byte_for_byte() {
        let cases: Vec<(Vec<Vec<u8>>, [u8; 32], u8)> = vec![
            (vec![b"vault".to_vec()], [0x07; 32], 255),
            (vec![b"vault".to_vec(), [0xAA; 32].to_vec()], [0x07; 32], 0),
            (vec![], [0x13; 32], 200),
            // Maxed-out seeds: 16 seeds × 32 bytes.
            ((0..16).map(|i| vec![i as u8; 32]).collect(), [0x99; 32], 1),
            // Empty seeds mixed with short ones.
            (vec![vec![], b"escrow".to_vec(), vec![]], [0x00; 32], 255),
        ];
        for (seeds, program_id, bump) in &cases {
            let refs: Vec<&[u8]> = seeds.iter().map(|s| s.as_slice()).collect();
            let got = derive_vault_address(&refs, program_id, *bump).unwrap();
            let want = super::super::sha256(&spec_layout(&refs, program_id, *bump));
            assert_eq!(
                got, want,
                "layout drift for seeds={seeds:?} bump={bump}: implementation disagrees with the spec layout"
            );
        }
    }

    #[test]
    fn known_vector_is_pinned() {
        // Regression pin: seeds [b"vault", 0xAA×32], program 0x07×32,
        // bump 255. Generated independently (Python hashlib); the
        // spec-layout test above proves the layout, this pins the
        // output.
        let seeds: &[&[u8]] = &[b"vault", &[0xAA; 32]];
        let addr = derive_vault_address(seeds, &[0x07; 32], 255).unwrap();
        assert_eq!(
            hex32(&addr),
            "6e5f70b17558d326e368429f9424cf97325902b80c94ccd06e0b9ed14db148c3"
        );
    }

    #[test]
    fn seed_limits_rejected_with_149() {
        // 17 seeds: over the Solana max.
        let many: Vec<Vec<u8>> = (0..17).map(|i| vec![i as u8]).collect();
        let refs: Vec<&[u8]> = many.iter().map(|s| s.as_slice()).collect();
        let err = derive_vault_address(&refs, &[0x07; 32], 255).unwrap_err();
        assert_eq!(err, EscrowError::InvalidVaultSeeds);
        assert_eq!(err.code(), 149);

        // One 33-byte seed: over the per-seed max.
        let big = [0xAAu8; 33];
        let err = VaultSeeds::new(&[&big[..]]).unwrap_err();
        assert_eq!(err, EscrowError::InvalidVaultSeeds);
        assert_eq!(err.code(), 149);

        // find_vault_bump maps invalid seeds to None (no bump to find).
        assert_eq!(find_vault_bump(&refs, &[0x07; 32]), None);
        assert_eq!(find_program_address(&refs, &[0x07; 32]), None);

        // Boundary: exactly 16 seeds of exactly 32 bytes each is fine.
        let max: Vec<Vec<u8>> = (0..16).map(|i| vec![i as u8; 32]).collect();
        let refs: Vec<&[u8]> = max.iter().map(|s| s.as_slice()).collect();
        assert!(VaultSeeds::new(&refs).is_ok());
        assert!(derive_vault_address(&refs, &[0x07; 32], 255).is_ok());
        // Empty seed list is allowed (Solana permits it).
        assert!(VaultSeeds::new(&[]).is_ok());
    }

    #[test]
    fn vault_seeds_builder_roundtrip() {
        let seeds: &[&[u8]] = &[b"vault", b"", &[0xCC; 32]];
        let vs = VaultSeeds::new(seeds).unwrap();
        assert_eq!(vs.seed_count(), 3);
        assert_eq!(vs.seed(0), b"vault");
        assert_eq!(vs.seed(1), b"");
        assert_eq!(vs.seed(2), &[0xCC; 32]);
        let collected: Vec<&[u8]> = vs.iter().collect();
        assert_eq!(collected, seeds);
        // Copy: the watch structs rely on it.
        let vs2 = vs;
        assert_eq!(vs, vs2);
    }

    #[test]
    fn ed25519_d_matches_definition() {
        // d = −121665 · inv(121666) mod p, recomputed from the
        // definition — the hardcoded ED25519_D must match exactly.
        let inv = Fe([121666, 0, 0, 0]).pow(P_MINUS_2);
        let d = Fe([121665, 0, 0, 0]).mul(inv);
        let neg = Fe::ZERO.sub(d);
        assert_eq!(ED25519_D, neg);
    }

    #[test]
    fn sqrt_m1_squares_to_minus_one() {
        let minus_one = Fe::ZERO.sub(Fe::ONE);
        assert_eq!(SQRT_M1.mul(SQRT_M1), minus_one);
    }

    #[test]
    fn field_arithmetic_spot_checks() {
        // 2^255 ≡ 19 (mod p): the reduction's defining relation.
        let two = Fe([2, 0, 0, 0]);
        let mut x = two;
        for _ in 0..254 {
            x = x.mul(two);
        }
        assert_eq!(x, Fe([19, 0, 0, 0]));
        // (p−1)² = 1.
        let p_minus_1 = Fe(Fe::sub_limbs(&FIELD_P, &[1, 0, 0, 0]));
        assert_eq!(p_minus_1.mul(p_minus_1), Fe::ONE);
        // Fermat: a^(p−1) = 1.
        let p_minus_1_exp = Fe::sub_limbs(&FIELD_P, &[1, 0, 0, 0]);
        for a in [3u64, 7, 12345, 0xDEAD_BEEF] {
            assert_eq!(Fe([a, 0, 0, 0]).pow(p_minus_1_exp), Fe::ONE);
        }
    }

    #[test]
    fn ed25519_curve_membership_vectors() {
        // The ed25519 base point (compressed): on the curve.
        let mut base = [0x66u8; 32];
        base[0] = 0x58;
        assert!(is_on_ed25519_curve(&base));

        // The identity point (0, 1): on the curve.
        let mut id = [0u8; 32];
        id[0] = 0x01;
        assert!(is_on_ed25519_curve(&id));

        // All-zero bytes: ON the curve. y = 0 gives x² = −1, solvable
        // because p ≡ 1 (mod 4) — the 2-torsion point (±√−1, 0).
        // Solana's decompression accepts it too, so the bump search
        // must treat it as on-curve.
        assert!(is_on_ed25519_curve(&[0u8; 32]));

        // y = p: rejected by the y < p gate.
        let mut yp = [0xFFu8; 32];
        yp[0] = 0xED;
        yp[31] = 0x7F;
        assert!(!is_on_ed25519_curve(&yp));

        // y = 2^255 − 1: rejected by the y < p gate.
        let mut ym = [0xFFu8; 32];
        ym[31] = 0x7F;
        assert!(!is_on_ed25519_curve(&ym));

        // y = 2: (y²−1)/(d·y²+1) is a non-residue — off the curve.
        let mut small = [0u8; 32];
        small[0] = 0x02;
        assert!(!is_on_ed25519_curve(&small));
    }

    #[test]
    fn bump_search_finds_first_off_curve() {
        let seeds: &[&[u8]] = &[b"escrow", b"vault-42"];
        let program_id = [0x13; 32];
        let bump = find_vault_bump(seeds, &program_id).expect("a bump always exists");
        // The returned bump's address is off-curve …
        let addr = derive_vault_address(seeds, &program_id, bump).unwrap();
        assert!(
            !is_on_ed25519_curve(&addr),
            "bump {bump} must be off-curve"
        );
        // … and every bump above it (scanned first) is on-curve, i.e.
        // the search really returned the FIRST off-curve candidate
        // from 255 down.
        if bump < 255 {
            for b in (bump + 1)..=255u8 {
                let a = derive_vault_address(seeds, &program_id, b).unwrap();
                assert!(
                    is_on_ed25519_curve(&a),
                    "bump {b} is on-curve but the search skipped past it"
                );
            }
        }
        // Regression pin: the found bump for these fixed inputs
        // (bump 255's candidate is on-curve, so the search skips it —
        // independently verified with a Python model).
        assert_eq!(bump, 254);
    }

    #[test]
    fn find_program_address_agrees_with_derive() {
        let seeds: &[&[u8]] = &[b"vault", &[0xAA; 32]];
        let program_id = [0x07; 32];
        let (addr, bump) = find_program_address(seeds, &program_id).unwrap();
        assert_eq!(addr, derive_vault_address(seeds, &program_id, bump).unwrap());
        assert!(!is_on_ed25519_curve(&addr));
        // The derivation input round-trips through VaultDerivation.
        let d = VaultDerivation::new(seeds, &program_id).unwrap();
        assert_eq!(d.address(), Some(addr));
        assert_eq!(d.bump(), Some(bump));
    }

    #[test]
    fn vault_derivation_rejects_bad_seeds() {
        let big = [0xAAu8; 33];
        let err = VaultDerivation::new(&[&big[..]], &[0x07; 32]).unwrap_err();
        assert_eq!(err, EscrowError::InvalidVaultSeeds);
    }
}
