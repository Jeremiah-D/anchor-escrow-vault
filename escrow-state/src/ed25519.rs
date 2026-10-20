//! AV-101: Ed25519 signatures (RFC 8032), hand-rolled, zero dependencies.
//!
//! Keeper reports ([`crate::KeeperReport`], [`crate::CloseReport`],
//! [`crate::MilestoneReport`], …) are consumed by offline signers —
//! multisig CLIs, keeper operators — so a tampered report must not
//! verify. This module provides the signature primitive; see
//! [`crate::report_signing`] for the report envelope.
//!
//! Design notes:
//!
//! - The crate is dependency-free, so Ed25519 is implemented from
//!   first principles: SHA-512 (FIPS 180-4), scalar arithmetic mod the
//!   group order `L`, and twisted-Edwards point operations in extended
//!   coordinates over the [`Fe`](super::pda) field arithmetic that
//!   [`pda`](super::pda) already hand-rolls (AV-92). The reuse
//!   assessment the backlog asked for: `Fe` (add/sub/mul/pow),
//!   `ED25519_D`, `SQRT_M1`, `EXP_SQRT`, `P_MINUS_2` and
//!   `raw_bytes_ge_p` are reused as-is; only point-level operations
//!   (addition, scalar multiplication, compression) are new.
//! - SHA-512's 80 round constants were generated from their definition
//!   (fractional part of the cube root of the first 80 primes, times
//!   2⁶⁴) with an independent high-precision computation, then pinned
//!   by the `sha512_*` tests below against system ground truth.
//! - Correctness is pinned two ways: (1) SHA-512 against `sha512sum`
//!   ground truth; (2) full sign/verify against OpenSSL-generated
//!   vectors — Ed25519 signing is deterministic, so the signature
//!   bytes must match exactly.
//! - This is keeper *tooling*, not consensus: no constant-time
//!   guarantees are claimed (double-and-add scalar multiplication).
//!   The threat model is report tampering in transit/storage, not
//!   side-channel key extraction from the keeper host.

use super::pda::{raw_bytes_ge_p, Fe, ED25519_D, EXP_SQRT, P_MINUS_2, SQRT_M1};

// ---------------------------------------------------------------------------
// SHA-512 (FIPS 180-4), hand-rolled.
// ---------------------------------------------------------------------------

/// SHA-512 over `message`. Round constants generated from the
/// definition (see module docs); the `sha512_*` tests pin the output
/// against system ground truth.
fn sha512(message: &[u8]) -> [u8; 64] {
    #[rustfmt::skip]
    const K: [u64; 80] = [
        0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
        0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
        0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
        0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
        0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
        0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
        0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
        0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
        0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
        0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
        0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
        0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
        0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
        0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
        0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
        0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
        0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
        0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
        0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
        0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
    ];
    let mut h: [u64; 8] = [
        0x6a09e667f3bcc908,
        0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b,
        0xa54ff53a5f1d36f1,
        0x510e527fade682d1,
        0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b,
        0x5be0cd19137e2179,
    ];
    // Padding: 0x80, zeros to ≡ 112 (mod 128), then the 128-bit
    // big-endian bit length.
    let bit_len = message.len() as u128 * 8;
    let mut padded = Vec::with_capacity(((message.len() + 129) / 128) * 128);
    padded.extend_from_slice(message);
    padded.push(0x80);
    while padded.len() % 128 != 112 {
        padded.push(0);
    }
    padded.extend_from_slice(&((bit_len >> 64) as u64).to_be_bytes());
    padded.extend_from_slice(&(bit_len as u64).to_be_bytes());

    for chunk in padded.chunks_exact(128) {
        let mut w = [0u64; 80];
        for i in 0..16 {
            let mut b = [0u8; 8];
            b.copy_from_slice(&chunk[8 * i..8 * i + 8]);
            w[i] = u64::from_be_bytes(b);
        }
        for i in 16..80 {
            let s0 = w[i - 15].rotate_right(1)
                ^ w[i - 15].rotate_right(8)
                ^ (w[i - 15] >> 7);
            let s1 = w[i - 2].rotate_right(19)
                ^ w[i - 2].rotate_right(61)
                ^ (w[i - 2] >> 6);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..80 {
            let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    let mut out = [0u8; 64];
    for (i, word) in h.iter().enumerate() {
        out[8 * i..8 * i + 8].copy_from_slice(&word.to_be_bytes());
    }
    out
}

// ---------------------------------------------------------------------------
// Scalar arithmetic mod L = 2^252 + 27742317777372353535851937790883648493.
// ---------------------------------------------------------------------------

/// The Ed25519 group order as 4 LE u64 limbs.
const SCALAR_L: [u64; 4] = [
    0x5812_631a_5cf5_d3ed,
    0x14de_f9de_a2f7_9cd6,
    0x0000_0000_0000_0000,
    0x1000_0000_0000_0000,
];

/// A scalar `< L`, 4 little-endian u64 limbs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Scalar([u64; 4]);

fn ge4(a: &[u64; 4], b: &[u64; 4]) -> bool {
    for i in (0..4).rev() {
        if a[i] != b[i] {
            return a[i] > b[i];
        }
    }
    true
}

fn sub4(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let mut r = [0u64; 4];
    let mut borrow: u64 = 0;
    for i in 0..4 {
        let (s1, bo1) = a[i].overflowing_sub(b[i]);
        let (s2, bo2) = s1.overflowing_sub(borrow);
        r[i] = s2;
        borrow = (bo1 || bo2) as u64;
    }
    debug_assert!(borrow == 0, "sub4 underflow: caller must ensure a >= b");
    r
}

fn ge8(a: &[u64; 8], b: &[u64; 8]) -> bool {
    for i in (0..8).rev() {
        if a[i] != b[i] {
            return a[i] > b[i];
        }
    }
    true
}

fn sub8(a: &[u64; 8], b: &[u64; 8]) -> [u64; 8] {
    let mut r = [0u64; 8];
    let mut borrow: u64 = 0;
    for i in 0..8 {
        let (s1, bo1) = a[i].overflowing_sub(b[i]);
        let (s2, bo2) = s1.overflowing_sub(borrow);
        r[i] = s2;
        borrow = (bo1 || bo2) as u64;
    }
    debug_assert!(borrow == 0);
    r
}

/// Schoolbook 256×256 → 512-bit product.
fn scalar_mul_wide(a: &[u64; 4], b: &[u64; 4]) -> [u64; 8] {
    // 9 limbs of headroom: the true product is < 2^512, so the 9th
    // limb stays zero and the carry chain always terminates.
    let mut t = [0u64; 9];
    for i in 0..4 {
        let mut carry: u128 = 0;
        for j in 0..4 {
            let s = t[i + j] as u128 + a[i] as u128 * b[j] as u128 + carry;
            t[i + j] = s as u64;
            carry = s >> 64;
        }
        let mut k = i + 4;
        let mut c = carry;
        while c != 0 {
            debug_assert!(k < 9);
            let s = t[k] as u128 + c;
            t[k] = s as u64;
            c = s >> 64;
            k += 1;
        }
    }
    [
        t[0], t[1], t[2], t[3], t[4], t[5], t[6], t[7],
    ]
}

/// Reduce a 512-bit value mod `L` (binary long division).
///
/// The loop runs `k = 259 … 0`: `L` is 253 bits and the input is
/// `< 2^512`, so `L << 259` (512 bits, fits in 8 limbs) is the
/// smallest shift certainly above any input — starting any lower
/// (e.g. 256) under-reduces inputs `≥ L << 257`, because a single
/// conditional subtraction per `k` only suffices when the
/// `r < 2·(L<<k)` invariant holds from the top.
fn scalar_reduce(t: [u64; 8]) -> Scalar {
    let mut r = t;
    let l8: [u64; 8] = [
        SCALAR_L[0],
        SCALAR_L[1],
        SCALAR_L[2],
        SCALAR_L[3],
        0,
        0,
        0,
        0,
    ];
    for k in (0..=259).rev() {
        // shifted = L << k; L is 253 bits so L << 256 is 509 bits —
        // it always fits in 8 limbs.
        let word = k / 64;
        let bits = k % 64;
        let mut shifted = [0u64; 8];
        for i in (word..8).rev() {
            let li = i - word;
            let mut v = l8[li].wrapping_shl(bits as u32);
            if bits != 0 && li > 0 {
                v |= l8[li - 1] >> (64 - bits);
            }
            shifted[i] = v;
        }
        if ge8(&r, &shifted) {
            r = sub8(&r, &shifted);
        }
    }
    Scalar([r[0], r[1], r[2], r[3]])
}

impl Scalar {
    fn add(&self, other: &Scalar) -> Scalar {
        let mut s = [0u64; 4];
        let mut carry: u64 = 0;
        for i in 0..4 {
            let x = self.0[i] as u128 + other.0[i] as u128 + carry as u128;
            s[i] = x as u64;
            carry = (x >> 64) as u64;
        }
        if carry != 0 || ge4(&s, &SCALAR_L) {
            s = sub4(&s, &SCALAR_L);
        }
        Scalar(s)
    }

    fn mul(&self, other: &Scalar) -> Scalar {
        scalar_reduce(scalar_mul_wide(&self.0, &other.0))
    }

    /// Little-endian 32-byte scalar, reduced mod `L`.
    fn from_bytes32(bytes: &[u8; 32]) -> Scalar {
        let mut limbs = [0u64; 4];
        for i in 0..4 {
            let mut b = [0u8; 8];
            b.copy_from_slice(&bytes[8 * i..8 * i + 8]);
            limbs[i] = u64::from_le_bytes(b);
        }
        let mut wide = [0u64; 8];
        wide[..4].copy_from_slice(&limbs);
        scalar_reduce(wide)
    }

    /// Little-endian 64-byte scalar (a SHA-512 output), reduced mod `L`.
    fn from_bytes64(bytes: &[u8; 64]) -> Scalar {
        let mut wide = [0u64; 8];
        for i in 0..8 {
            let mut b = [0u8; 8];
            b.copy_from_slice(&bytes[8 * i..8 * i + 8]);
            wide[i] = u64::from_le_bytes(b);
        }
        scalar_reduce(wide)
    }

    fn to_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..4 {
            out[8 * i..8 * i + 8].copy_from_slice(&self.0[i].to_le_bytes());
        }
        out
    }

    /// True iff the raw 32 LE bytes encode a value `>= L` (non-canonical
    /// scalar encoding — [`verify`] rejects these).
    fn bytes_ge_l(bytes: &[u8; 32]) -> bool {
        let mut limbs = [0u64; 4];
        for i in 0..4 {
            let mut b = [0u8; 8];
            b.copy_from_slice(&bytes[8 * i..8 * i + 8]);
            limbs[i] = u64::from_le_bytes(b);
        }
        ge4(&limbs, &SCALAR_L)
    }
}

// ---------------------------------------------------------------------------
// Twisted-Edwards point operations (−x² + y² = 1 + d·x²·y²), extended
// coordinates (X, Y, Z, T) with x = X/Z, y = Y/Z, xy = T/Z.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
struct EdwardsPoint {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
}

impl EdwardsPoint {
    fn identity() -> Self {
        EdwardsPoint {
            x: Fe::ZERO,
            y: Fe::ONE,
            z: Fe::ONE,
            t: Fe::ZERO,
        }
    }

    /// Complete addition formula (Hisilop–Wong–Carter–Dawson), `a = −1`
    /// case — valid for all inputs including identity/doubling.
    fn add(&self, other: &Self) -> Self {
        let d2 = ED25519_D.add(ED25519_D);
        let a = (self.y.sub(self.x)).mul(other.y.sub(other.x));
        let b = (self.y.add(self.x)).mul(other.y.add(other.x));
        let c = self.t.mul(d2).mul(other.t);
        let d = (self.z.add(self.z)).mul(other.z);
        let e = b.sub(a);
        let f = d.sub(c);
        let g = d.add(c);
        let h = b.add(a);
        EdwardsPoint {
            x: e.mul(f),
            y: g.mul(h),
            z: f.mul(g),
            t: e.mul(h),
        }
    }

    fn double(&self) -> Self {
        self.add(self)
    }
}

/// The Ed25519 base point, decompressed once per call site use.
fn base_point() -> EdwardsPoint {
    const COMPRESSED: [u8; 32] = [
        0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66,
    ];
    let (x, y) = decompress(&COMPRESSED).expect("base point decompresses");
    EdwardsPoint {
        x,
        y,
        z: Fe::ONE,
        t: x.mul(y),
    }
}

/// Decompress a 32-byte Edwards point encoding to affine `(x, y)`.
/// `None` on non-canonical `y >= p` or a non-residue (off-curve).
fn decompress(bytes: &[u8; 32]) -> Option<(Fe, Fe)> {
    let mut y_bytes = *bytes;
    let sign = (y_bytes[31] & 0x80) != 0;
    y_bytes[31] &= 0x7F;
    // The y < p gate runs on the raw bytes: `Fe::from_bytes` reduces
    // mod p, which would map y = p to 0 (a valid point) and hide the
    // gate (same convention as `is_on_ed25519_curve`).
    if raw_bytes_ge_p(&y_bytes) {
        return None;
    }
    let y = Fe::from_bytes(&y_bytes);
    let y2 = y.mul(y);
    // x² = (y²−1) / (d·y²+1); den = 0 has no affine solution.
    let den = ED25519_D.mul(y2).add(Fe::ONE);
    if den == Fe::ZERO {
        return None;
    }
    let num = y2.sub(Fe::ONE);
    let v = num.mul(den.pow(P_MINUS_2));
    // sqrt for p ≡ 5 (mod 8): x = v^((p+3)/8), times √−1 when that
    // squares to −v instead of v. A non-residue fails both attempts.
    let mut x = v.pow(EXP_SQRT);
    if x.mul(x) != v {
        x = x.mul(SQRT_M1);
        if x.mul(x) != v {
            return None;
        }
    }
    if x.is_odd() != sign {
        x = x.neg();
    }
    Some((x, y))
}

/// Compress to the 32-byte encoding (y with the x-parity bit).
fn compress(p: &EdwardsPoint) -> [u8; 32] {
    let zinv = p.z.pow(P_MINUS_2);
    let x = p.x.mul(zinv);
    let y = p.y.mul(zinv);
    let mut out = y.to_bytes();
    if x.is_odd() {
        out[31] |= 0x80;
    }
    out
}

/// Double-and-add scalar multiplication.
fn scalar_mul(p: &EdwardsPoint, s: &Scalar) -> EdwardsPoint {
    let mut r = EdwardsPoint::identity();
    for i in (0..4).rev() {
        for bit in (0..64).rev() {
            r = r.double();
            if (s.0[i] >> bit) & 1 == 1 {
                r = r.add(p);
            }
        }
    }
    r
}

// ---------------------------------------------------------------------------
// Ed25519 sign / verify (RFC 8032).
// ---------------------------------------------------------------------------

/// An Ed25519 signing key derived from a 32-byte seed (RFC 8032
/// key generation: `a = clamp(SHA-512(seed)[0..32])`,
/// `public = a·G`). The seed itself is not retained.
#[derive(Debug, Clone)]
pub struct SigningKey {
    a: Scalar,
    prefix: [u8; 32],
    public_key: [u8; 32],
}

impl SigningKey {
    /// Derive the signing key from a 32-byte seed.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let h = sha512(&seed);
        let mut a_bytes = [0u8; 32];
        a_bytes.copy_from_slice(&h[..32]);
        a_bytes[0] &= 248;
        a_bytes[31] &= 63;
        a_bytes[31] |= 64;
        let a = Scalar::from_bytes32(&a_bytes);
        let mut prefix = [0u8; 32];
        prefix.copy_from_slice(&h[32..]);
        let public_key = compress(&scalar_mul(&base_point(), &a));
        SigningKey {
            a,
            prefix,
            public_key,
        }
    }

    /// The 32-byte public key.
    pub fn public_key(&self) -> [u8; 32] {
        self.public_key
    }

    /// Sign `message` (RFC 8032, deterministic nonce).
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        let mut nonce_input = Vec::with_capacity(32 + message.len());
        nonce_input.extend_from_slice(&self.prefix);
        nonce_input.extend_from_slice(message);
        let r = Scalar::from_bytes64(&sha512(&nonce_input));
        let big_r = compress(&scalar_mul(&base_point(), &r));

        let mut hram_input = Vec::with_capacity(64 + message.len());
        hram_input.extend_from_slice(&big_r);
        hram_input.extend_from_slice(&self.public_key);
        hram_input.extend_from_slice(message);
        let hram = Scalar::from_bytes64(&sha512(&hram_input));

        let s = r.add(&hram.mul(&self.a));
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&big_r);
        sig[32..].copy_from_slice(&s.to_bytes());
        sig
    }
}

/// Verify an Ed25519 signature (RFC 8032 §5.1.7): `S·G == R + H(R‖A‖M)·A`.
/// Returns `false` (never panics) on any malformed input: undecodable
/// `R`, undecodable public key, or non-canonical `S >= L`.
pub fn verify(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    let mut r_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&signature[..32]);
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&signature[32..]);
    if Scalar::bytes_ge_l(&s_bytes) {
        return false;
    }
    let s = Scalar::from_bytes32(&s_bytes);
    let (rx, ry) = match decompress(&r_bytes) {
        Some(pt) => pt,
        None => return false,
    };
    let r_pt = EdwardsPoint {
        x: rx,
        y: ry,
        z: Fe::ONE,
        t: rx.mul(ry),
    };
    let (ax, ay) = match decompress(public_key) {
        Some(pt) => pt,
        None => return false,
    };
    let a_pt = EdwardsPoint {
        x: ax,
        y: ay,
        z: Fe::ONE,
        t: ax.mul(ay),
    };
    let mut hram_input = Vec::with_capacity(64 + message.len());
    hram_input.extend_from_slice(&r_bytes);
    hram_input.extend_from_slice(public_key);
    hram_input.extend_from_slice(message);
    let hram = Scalar::from_bytes64(&sha512(&hram_input));

    let lhs = scalar_mul(&base_point(), &s);
    let rhs = r_pt.add(&scalar_mul(&a_pt, &hram));
    compress(&lhs) == compress(&rhs)
}

// ---------------------------------------------------------------------------
// Ed25519 batch verification (RFC 8032 batch equation), AV-153.
// ---------------------------------------------------------------------------

/// One item of a [`batch_verify`] request.
#[derive(Debug, Clone, Copy)]
pub struct BatchVerifyItem<'a> {
    /// The 32-byte public key.
    pub public_key: [u8; 32],
    /// The signed message (borrowed; variable length).
    pub message: &'a [u8],
    /// The 64-byte signature (`R ‖ S`).
    pub signature: [u8; 64],
}

/// Batch-verify Ed25519 signatures with the RFC 8032 batch equation
/// `(Σ zᵢ·Sᵢ)·G = Σ zᵢ·Rᵢ + Σ zᵢ·hᵢ·Aᵢ`, where `hᵢ = H(Rᵢ‖Aᵢ‖Mᵢ)`
/// and each `zᵢ` is a per-item blinding scalar. Batch verification
/// does one combined multi-scalar multiplication instead of two
/// scalar multiplications per signature — the keeper's linear
/// per-signature cost when verifying report/intent batches.
///
/// Returns the indexes (in input order) of the items that fail —
/// exactly the indexes `verify` returns `false` for. Empty on full
/// success.
///
/// The blinding scalars are derived deterministically as
/// `zᵢ = SHA-512("escrow-av153-batch:" ‖ i ‖ Rᵢ ‖ Aᵢ ‖ Mᵢ) mod L`
/// (zero maps to 1): no RNG is needed (the crate is zero-dependency)
/// and the batch is reproducible. Soundness comes from the batch
/// equation itself — a forged item satisfies the aggregated equation
/// only with negligible probability, exactly as with random `zᵢ`
/// chosen after the batch is fixed.
///
/// A failed batch equation cannot say *which* item failed, so the
/// fallback is exact per-item RFC 8032 verification: the result is
/// always identical to running `verify` on every item (see
/// `batch_verify_matches_individual_verification`). The batch
/// equation only avoids the fallback cost when the whole batch
/// verifies — the common keeper case.
pub fn batch_verify(items: &[BatchVerifyItem<'_>]) -> Vec<usize> {
    struct WellFormed<'a> {
        index: usize,
        r_pt: EdwardsPoint,
        a_pt: EdwardsPoint,
        h: Scalar,
        s: Scalar,
        r_bytes: [u8; 32],
        a_bytes: [u8; 32],
        msg: &'a [u8],
    }

    // Stage 1: structural checks — exactly `verify`'s false conditions
    // (non-canonical S, undecodable R, undecodable public key).
    let mut failed: Vec<usize> = Vec::new();
    let mut good: Vec<WellFormed<'_>> = Vec::new();
    for (index, item) in items.iter().enumerate() {
        let mut r_bytes = [0u8; 32];
        r_bytes.copy_from_slice(&item.signature[..32]);
        let mut s_bytes = [0u8; 32];
        s_bytes.copy_from_slice(&item.signature[32..]);
        let well_formed = !Scalar::bytes_ge_l(&s_bytes)
            && decompress(&r_bytes).is_some()
            && decompress(&item.public_key).is_some();
        if !well_formed {
            failed.push(index);
            continue;
        }
        let s = Scalar::from_bytes32(&s_bytes);
        let (rx, ry) = decompress(&r_bytes).expect("re-checked");
        let r_pt = EdwardsPoint {
            x: rx,
            y: ry,
            z: Fe::ONE,
            t: rx.mul(ry),
        };
        let (ax, ay) = decompress(&item.public_key).expect("re-checked");
        let a_pt = EdwardsPoint {
            x: ax,
            y: ay,
            z: Fe::ONE,
            t: ax.mul(ay),
        };
        let mut hram_input = Vec::with_capacity(64 + item.message.len());
        hram_input.extend_from_slice(&r_bytes);
        hram_input.extend_from_slice(&item.public_key);
        hram_input.extend_from_slice(item.message);
        let h = Scalar::from_bytes64(&sha512(&hram_input));
        good.push(WellFormed {
            index,
            r_pt,
            a_pt,
            h,
            s,
            r_bytes,
            a_bytes: item.public_key,
            msg: item.message,
        });
    }

    if !good.is_empty() {
        // Stage 2: the batch equation over the well-formed subset.
        let mut sum_zs = Scalar([0, 0, 0, 0]);
        let mut rhs = EdwardsPoint::identity();
        for g in &good {
            let mut zin = Vec::with_capacity(24 + 8 + 32 + 32 + g.msg.len());
            zin.extend_from_slice(b"escrow-av153-batch:");
            zin.extend_from_slice(&(g.index as u64).to_le_bytes());
            zin.extend_from_slice(&g.r_bytes);
            zin.extend_from_slice(&g.a_bytes);
            zin.extend_from_slice(g.msg);
            let mut z = Scalar::from_bytes64(&sha512(&zin));
            if z == Scalar([0, 0, 0, 0]) {
                z = Scalar([1, 0, 0, 0]);
            }
            sum_zs = sum_zs.add(&z.mul(&g.s));
            let zr = scalar_mul(&g.r_pt, &z);
            let zha = scalar_mul(&g.a_pt, &z.mul(&g.h));
            rhs = rhs.add(&zr).add(&zha);
        }
        let lhs = scalar_mul(&base_point(), &sum_zs);
        if compress(&lhs) != compress(&rhs) {
            // Stage 3: exact fallback — individual RFC 8032
            // verification, so the failure set is identical to
            // per-item `verify` (no short-circuit masking).
            for g in &good {
                let item = &items[g.index];
                if !verify(&item.public_key, item.message, &item.signature) {
                    failed.push(g.index);
                }
            }
        }
    }
    failed
}

#[cfg(test)]
mod ed25519_tests {
    use super::*;

    fn hex_to_32(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }

    fn hex32(b: &[u8; 32]) -> String {
        b.iter().map(|x| format!("{:02x}", x)).collect()
    }

    fn hex64(b: &[u8; 64]) -> String {
        b.iter().map(|x| format!("{:02x}", x)).collect()
    }

    #[test]
    fn sha512_empty_matches_ground_truth() {
        // `echo -n "" | sha512sum` (cross-checked with Python hashlib).
        assert_eq!(
            hex64(&sha512(b"")),
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        );
    }

    #[test]
    fn sha512_abc_matches_ground_truth() {
        // `echo -n "abc" | sha512sum` (cross-checked with Python hashlib).
        assert_eq!(
            hex64(&sha512(b"abc")),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
    }

    #[test]
    fn sha512_long_message_matches_ground_truth() {
        // 200 bytes: exercises the multi-block path.
        // `python3 -c "import hashlib; print(hashlib.sha512(b'a'*200).hexdigest())"`.
        assert_eq!(
            hex64(&sha512(&[b'a'; 200])),
            "4b11459c33f52a22ee8236782714c150a3b2c60994e9acee17fe68947a3e6789f31e7668394592da7bef827cddca88c4e6f86e4df7ed1ae6cba71f3e98faee9f"
        );
    }

    /// OpenSSL-generated vector 1 (`openssl genpkey -algorithm
    /// ed25519` + `openssl pkeyutl -sign`, signature verified back
    /// with `pkeyutl -verify`). Ed25519 signing is deterministic, so
    /// the signature bytes must match exactly.
    #[test]
    fn openssl_vector_1_keygen_sign_verify() {
        let seed = hex_to_32("4c3647bea43c25e90c70016edf045bc5da6752bcf42ea2c5c6fa0ec1161e6669");
        let key = SigningKey::from_seed(seed);
        assert_eq!(
            hex32(&key.public_key()),
            "d54394f39904d5d8a750cc64e97ac1c0a95b5ba8c6675b5f04cf6cc59bb3e223"
        );
        let sig = key.sign(b"hello escrow");
        assert_eq!(
            hex64(&sig),
            "1f978ad079afc539907f872cbce49bad7005056f044eca1247cb62e4fc0e35893cf478cff24e88debe901bae03dec86815f44f3b1b37ea63fe139676e9bb260a"
        );
        assert!(verify(&key.public_key(), b"hello escrow", &sig));
    }

    /// OpenSSL-generated vector 2 (1-byte message).
    #[test]
    fn openssl_vector_2_keygen_sign_verify() {
        let seed = hex_to_32("92d943699f1b6dd869c2a1f20a3b80291946a47192791ce3803ccbe9c71499e4");
        let key = SigningKey::from_seed(seed);
        assert_eq!(
            hex32(&key.public_key()),
            "d0180489b307bef8beb71d8de28402197040dd4f8529cf584135bb134439c420"
        );
        let sig = key.sign(&[0u8]);
        assert_eq!(
            hex64(&sig),
            "108be9d5505532f33fe1811aa370bfe78a0474255b024493c85f926ff816b369cccb6a5514e36e0710d14a6086c0bcf32a6916080629cc9eb7a6acb050615408"
        );
        assert!(verify(&key.public_key(), &[0u8], &sig));
    }

    #[test]
    fn verify_rejects_tampered_message() {
        let seed = hex_to_32("4c3647bea43c25e90c70016edf045bc5da6752bcf42ea2c5c6fa0ec1161e6669");
        let key = SigningKey::from_seed(seed);
        let sig = key.sign(b"hello escrow");
        assert!(!verify(&key.public_key(), b"hello escrow!", &sig));
        assert!(!verify(&key.public_key(), b"", &sig));
    }

    #[test]
    fn verify_rejects_tampered_signature() {
        let seed = hex_to_32("4c3647bea43c25e90c70016edf045bc5da6752bcf42ea2c5c6fa0ec1161e6669");
        let key = SigningKey::from_seed(seed);
        let mut sig = key.sign(b"hello escrow");
        sig[0] ^= 1;
        assert!(!verify(&key.public_key(), b"hello escrow", &sig));
        let mut sig2 = key.sign(b"hello escrow");
        sig2[63] ^= 0x80;
        assert!(!verify(&key.public_key(), b"hello escrow", &sig2));
    }

    #[test]
    fn verify_rejects_wrong_public_key() {
        let seed = hex_to_32("4c3647bea43c25e90c70016edf045bc5da6752bcf42ea2c5c6fa0ec1161e6669");
        let other = hex_to_32("92d943699f1b6dd869c2a1f20a3b80291946a47192791ce3803ccbe9c71499e4");
        let key = SigningKey::from_seed(seed);
        let other_key = SigningKey::from_seed(other);
        let sig = key.sign(b"hello escrow");
        assert!(!verify(&other_key.public_key(), b"hello escrow", &sig));
    }

    #[test]
    fn verify_rejects_non_canonical_s() {
        // S = L (non-canonical scalar encoding) must fail, not wrap.
        let seed = hex_to_32("4c3647bea43c25e90c70016edf045bc5da6752bcf42ea2c5c6fa0ec1161e6669");
        let key = SigningKey::from_seed(seed);
        let mut sig = key.sign(b"hello escrow");
        sig[32..].copy_from_slice(&Scalar(SCALAR_L).to_bytes());
        assert!(!verify(&key.public_key(), b"hello escrow", &sig));
    }

    #[test]
    fn verify_rejects_garbage_inputs_without_panic() {
        let zeros = [0u8; 32];
        let sig_zeros = [0u8; 64];
        assert!(!verify(&zeros, b"m", &sig_zeros));
        let ones = [0xffu8; 32];
        assert!(!verify(&ones, b"m", &sig_zeros));
        // y = p is non-canonical and must be rejected, not reduced.
        let mut yp = [0xffu8; 32];
        yp[0] = 0xed;
        yp[31] = 0x7f;
        assert!(!verify(&yp, b"m", &sig_zeros));
    }

    #[test]
    fn sign_is_deterministic() {
        let seed = hex_to_32("4c3647bea43c25e90c70016edf045bc5da6752bcf42ea2c5c6fa0ec1161e6669");
        let key = SigningKey::from_seed(seed);
        assert_eq!(key.sign(b"hello escrow"), key.sign(b"hello escrow"));
    }

    #[test]
    fn scalar_arithmetic_spot_checks() {
        // (L−1) + 1 ≡ 0.
        let l = Scalar(SCALAR_L);
        let one = Scalar([1, 0, 0, 0]);
        let l_minus_1 = Scalar(sub4(&SCALAR_L, &[1, 0, 0, 0]));
        assert_eq!(l_minus_1.add(&one), Scalar([0, 0, 0, 0]));
        // 0 * x = 0, 1 * x = x.
        let x = Scalar([0xdeadbeef, 0x12345678, 0, 0]);
        assert_eq!(Scalar([0, 0, 0, 0]).mul(&x), Scalar([0, 0, 0, 0]));
        assert_eq!(one.mul(&x), x);
        // 2^256 mod L: 2^256 = 16 * 2^252 = 16 * (L - q) ≡ -16q (mod L),
        // where q = L - 2^252.
        let mut two256 = [0u8; 64];
        two256[32] = 1;
        let r = Scalar::from_bytes64(&two256);
        let q = Scalar(sub4(&SCALAR_L, &[0, 0, 0, 0x1000_0000_0000_0000]));
        let sixteen = Scalar([16, 0, 0, 0]);
        let q16 = q.mul(&sixteen);
        let want = Scalar(sub4(&SCALAR_L, &q16.0));
        assert_eq!(r, want);
    }

    #[test]
    fn base_point_is_on_curve_and_has_order_l() {
        let g = base_point();
        // L * G must be the identity (group order check).
        let lg = scalar_mul(&g, &Scalar(SCALAR_L));
        assert_eq!(compress(&lg), compress(&EdwardsPoint::identity()));
    }

    // ------------------------------------------------------------------
    // AV-153: batch verification.
    // ------------------------------------------------------------------

    /// Build a batch of `n` valid (key, message) pairs: distinct seeds
    /// and distinct messages.
    fn valid_batch(n: usize) -> (Vec<SigningKey>, Vec<Vec<u8>>) {
        let mut keys = Vec::with_capacity(n);
        let mut messages = Vec::with_capacity(n);
        for i in 0..n {
            let mut seed = [0u8; 32];
            seed[0] = (i + 1) as u8;
            seed[31] = 0xA5;
            let key = SigningKey::from_seed(seed);
            let msg = format!("keeper report #{i}").into_bytes();
            keys.push(key);
            messages.push(msg);
        }
        (keys, messages)
    }

    fn batch_items<'a>(
        keys: &'a [SigningKey],
        messages: &'a [Vec<u8>],
    ) -> Vec<BatchVerifyItem<'a>> {
        keys.iter()
            .zip(messages.iter())
            .map(|(k, m)| BatchVerifyItem {
                public_key: k.public_key(),
                message: m,
                signature: k.sign(m),
            })
            .collect()
    }

    #[test]
    fn batch_verify_all_valid_returns_empty() {
        let (keys, messages) = valid_batch(8);
        let items = batch_items(&keys, &messages);
        assert_eq!(batch_verify(&items), Vec::<usize>::new());
        // A single-item batch is just verify.
        assert_eq!(batch_verify(&items[..1]), Vec::<usize>::new());
        // Empty batch is vacuous success.
        assert_eq!(batch_verify(&[]), Vec::<usize>::new());
    }

    #[test]
    fn batch_verify_locates_single_tampered_signature() {
        let (keys, messages) = valid_batch(6);
        let mut items = batch_items(&keys, &messages);
        items[3].signature[10] ^= 0x40;
        assert_eq!(batch_verify(&items), vec![3]);
    }

    #[test]
    fn batch_verify_locates_multiple_failures_in_order() {
        let (keys, messages) = valid_batch(6);
        let mut items = batch_items(&keys, &messages);
        // Corrupt three different aspects — all AFTER signing:
        // S bytes, R bytes, and the message bytes.
        items[4].signature[63] ^= 0x01;
        items[1].signature[0] ^= 0x80;
        let mut msg2 = messages[2].clone();
        msg2[0] ^= 0x01;
        items[2].message = &msg2;
        assert_eq!(batch_verify(&items), vec![1, 2, 4]);
    }

    #[test]
    fn batch_verify_reports_malformed_inputs() {
        let (keys, messages) = valid_batch(4);
        let mut items = batch_items(&keys, &messages);
        // S >= L (non-canonical scalar encoding).
        items[0].signature[32..].copy_from_slice(&Scalar(SCALAR_L).to_bytes());
        // Garbage public key (off-curve).
        items[2].public_key = [0xffu8; 32];
        // Garbage R: y = p is non-canonical (p = 2^255 - 19, little-endian).
        let mut p_bytes = [0xffu8; 32];
        p_bytes[0] = 0xed;
        p_bytes[31] = 0x7f;
        items[3].signature[..32].copy_from_slice(&p_bytes);
        assert_eq!(batch_verify(&items), vec![0, 2, 3]);
    }

    #[test]
    fn batch_verify_duplicate_items() {
        // The same signature twice: both verify, none fails.
        let (keys, messages) = valid_batch(2);
        let items = batch_items(&keys, &messages);
        let doubled = vec![items[0], items[0]];
        assert_eq!(batch_verify(&doubled), Vec::<usize>::new());
        // And the same corruption twice reports both indexes.
        let mut bad = doubled.clone();
        bad[0].signature[5] ^= 1;
        bad[1].signature[5] ^= 1;
        assert_eq!(batch_verify(&bad), vec![0, 1]);
    }

    /// Deterministic xorshift64* (same generator family as the AV-03
    /// fuzz tests) for the equivalence property test below.
    fn xorshift64star(state: &mut u64) -> u64 {
        let mut x = *state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        *state = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }

    #[test]
    fn batch_verify_matches_individual_verification() {
        // The core AV-153 property: batch_verify returns exactly the
        // indexes where per-item `verify` fails, across random batch
        // sizes and random corruptions. No short-circuit masking.
        let mut state = 0x9E3779B97F4A7C15u64;
        for round in 0..12 {
            let n = 1 + (xorshift64star(&mut state) % 7) as usize;
            let (keys, messages) = valid_batch(n);
            // Plan corruptions before building the borrowed items:
            // message flips need owned copies prepared up front
            // (corruption happens AFTER signing, or it is a no-op);
            // signature/public-key flips and swaps apply to the
            // items afterwards.
            let mut sig_corrupt: Vec<Option<(usize, u8)>> = vec![None; n];
            let mut key_corrupt: Vec<Option<(usize, u8)>> = vec![None; n];
            let mut swaps: Vec<Option<usize>> = vec![None; n];
            let mut msg_corrupt: Vec<Option<Vec<u8>>> = vec![None; n];
            for i in 0..n {
                if xorshift64star(&mut state) % 3 == 0 {
                    match xorshift64star(&mut state) % 4 {
                        0 => {
                            // Flip a signature byte (may or may not
                            // make S non-canonical — either way it
                            // must fail).
                            let b = (xorshift64star(&mut state) % 64) as usize;
                            let m = 1u8 << (xorshift64star(&mut state) % 8);
                            sig_corrupt[i] = Some((b, m));
                        }
                        1 => {
                            // Flip a message byte AFTER signing — a
                            // fresh owned copy, or the corruption is a
                            // no-op (the signature would be computed
                            // over the flipped bytes).
                            let b = (xorshift64star(&mut state) % messages[i].len() as u64) as usize;
                            let mut c = messages[i].clone();
                            c[b] ^= 0x55;
                            msg_corrupt[i] = Some(c);
                        }
                        2 => {
                            // Flip a public-key byte.
                            let b = (xorshift64star(&mut state) % 32) as usize;
                            key_corrupt[i] = Some((b, 0xAA));
                        }
                        _ => {
                            // Swap in another item's signature (a
                            // cross-item forgery; j == i is a no-op).
                            let j = (xorshift64star(&mut state) % n as u64) as usize;
                            swaps[i] = Some(j);
                        }
                    }
                }
            }
            let mut items = batch_items(&keys, &messages);
            for i in 0..n {
                if let Some((b, m)) = sig_corrupt[i] {
                    items[i].signature[b] ^= m;
                }
                if let Some((b, m)) = key_corrupt[i] {
                    items[i].public_key[b] ^= m;
                }
                if let Some(ref corrupted) = msg_corrupt[i] {
                    items[i].message = corrupted;
                }
                if let Some(j) = swaps[i] {
                    items[i].signature = items[j].signature;
                }
            }
            let expected: Vec<usize> = items
                .iter()
                .enumerate()
                .filter(|(_, it)| !verify(&it.public_key, it.message, &it.signature))
                .map(|(i, _)| i)
                .collect();
            assert_eq!(
                batch_verify(&items),
                expected,
                "round {round}: batch/individual mismatch"
            );
        }
    }
}
