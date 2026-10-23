//! AV-185: secp256k1 / EVM signature verification, hand-rolled, zero dependencies.
//!
//! Cross-chain escrow: the taker can bind an EVM wallet (an Ethereum
//! address) to their escrow identity, and that wallet's signature then
//! authorizes a `release` — the Ethereum signer never needs a Solana key.
//! This module provides the signature primitive; the release-authorization
//! envelope ([`EvmTakerBinding`], [`release_authorization_hash`],
//! [`verify_release_authorization`]) is the envelope layer, mirroring the
//! `ed25519` module (primitive) / `report_signing` (envelope) split from
//! AV-101.
//!
//! Design notes:
//!
//! - The crate is dependency-free, so everything is implemented from
//!   first principles: Keccak-256 (the Ethereum variant, pad `0x01`),
//!   the secp256k1 base field `Fq` (`p = 2^256 - 2^32 - 977`, 4×u64
//!   limbs, special-form reduction), the scalar field mod the group
//!   order `n`, Jacobian point arithmetic (`a = 0` dbl/add formulas),
//!   and ECDSA public-key recovery.
//! - Reuse assessment the backlog asked for: `ed25519.rs` hand-rolls the
//!   ed25519 field (`2^255 - 19`) via `pda::Fe`; secp256k1's field is a
//!   *different* prime, so nothing is shared — but the *conventions* are
//!   reused: off-chain verification only, deterministic test pins
//!   against independent ground truth, fail-closed `Option`/`bool`
//!   returns (malformed input → `None`/`false`, never a panic).
//! - Correctness is pinned three ways: (1) Keccak-256 against
//!   `pycryptodome` ground truth; (2) `2*G` and full
//!   sign→recover against `python-ecdsa` (RFC 6979) vectors; (3) the
//!   recovered address must equal the independently derived Ethereum
//!   address.
//! - This is cross-chain *tooling*, not consensus: no constant-time
//!   guarantees are claimed (double-and-add scalar multiplication, binary
//!   exponentiation). The threat model is a forged release
//!   authorization, not side-channel key extraction from the verifier
//!   host.
//! - Orthogonal to [`crate::ed25519`] (ed25519 for keeper reports — this
//!   module is secp256k1/EVM).

// ---------------------------------------------------------------------------
// Keccak-256 (Ethereum variant: pad10*1 with domain suffix 0x01).
// ---------------------------------------------------------------------------

const KECCAK_RC: [u64; 24] = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
];

/// Rotation offsets `r[x + 5*y]` for the Keccak-f rho step.
const KECCAK_ROT: [[u32; 5]; 5] = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
];

fn keccakf(s: &mut [u64; 25]) {
    for &rc in KECCAK_RC.iter() {
        // Theta.
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = s[x] ^ s[x + 5] ^ s[x + 10] ^ s[x + 15] ^ s[x + 20];
        }
        let mut d = [0u64; 5];
        for x in 0..5 {
            d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
        }
        for x in 0..5 {
            for y in 0..5 {
                s[x + 5 * y] ^= d[x];
            }
        }
        // Rho + pi.
        let mut b = [0u64; 25];
        for x in 0..5 {
            for y in 0..5 {
                b[y + 5 * ((2 * x + 3 * y) % 5)] =
                    s[x + 5 * y].rotate_left(KECCAK_ROT[x][y]);
            }
        }
        // Chi.
        for x in 0..5 {
            for y in 0..5 {
                s[x + 5 * y] =
                    b[x + 5 * y] ^ ((!b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y]);
            }
        }
        // Iota.
        s[0] ^= rc;
    }
}

/// Streaming Keccak-256 (Ethereum variant). Rate is 136 bytes.
pub struct Keccak256 {
    s: [u64; 25],
    buf: [u8; 136],
    len: usize,
}

impl Keccak256 {
    /// A fresh hasher.
    pub fn new() -> Self {
        Keccak256 {
            s: [0u64; 25],
            buf: [0u8; 136],
            len: 0,
        }
    }

    fn absorb_block(&mut self) {
        for i in 0..17 {
            let mut lane = 0u64;
            for j in 0..8 {
                lane |= (self.buf[8 * i + j] as u64) << (8 * j);
            }
            self.s[i] ^= lane;
        }
        keccakf(&mut self.s);
        // Clear the buffer: the next update() writes only buf[0..take],
        // and finalize() absorbs all 136 bytes — stale bytes beyond the
        // new data would corrupt a multi-block message's final block.
        self.buf = [0u8; 136];
        self.len = 0;
    }

    /// Absorb more input.
    pub fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            let take = (136 - self.len).min(data.len());
            self.buf[self.len..self.len + take].copy_from_slice(&data[..take]);
            self.len += take;
            data = &data[take..];
            if self.len == 136 {
                self.absorb_block();
            }
        }
    }

    /// Pad (`0x01 ... 0x80`) and squeeze the 32-byte digest.
    pub fn finalize(mut self) -> [u8; 32] {
        self.buf[self.len] ^= 0x01;
        self.buf[135] ^= 0x80;
        // XOR the final (possibly partial) block without a permutation
        // when nothing was absorbed yet — no: always absorb the padded
        // block, then permute, then squeeze.
        for i in 0..17 {
            let mut lane = 0u64;
            for j in 0..8 {
                lane |= (self.buf[8 * i + j] as u64) << (8 * j);
            }
            self.s[i] ^= lane;
        }
        keccakf(&mut self.s);
        let mut out = [0u8; 32];
        for i in 0..4 {
            for j in 0..8 {
                out[8 * i + j] = (self.s[i] >> (8 * j)) as u8;
            }
        }
        out
    }
}

impl Default for Keccak256 {
    fn default() -> Self {
        Self::new()
    }
}

/// One-shot Keccak-256 (Ethereum variant).
pub fn keccak256(msg: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(msg);
    h.finalize()
}

// ---------------------------------------------------------------------------
// secp256k1 base field Fq: p = 2^256 - 2^32 - 977, 4 x u64 LE limbs.
// ---------------------------------------------------------------------------

const P: [u64; 4] = [
    0xFFFFFFFEFFFFFC2F,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
];

/// secp256k1 base field element, always fully reduced (`< p`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Fq([u64; 4]);

impl Fq {
    const ZERO: Fq = Fq([0, 0, 0, 0]);
    const ONE: Fq = Fq([1, 0, 0, 0]);

    fn from_u64(v: u64) -> Fq {
        Fq([v, 0, 0, 0])
    }

    fn is_zero(&self) -> bool {
        self.0 == [0, 0, 0, 0]
    }

    fn is_odd(&self) -> bool {
        self.0[0] & 1 == 1
    }

    /// Pack 32 big-endian bytes; the caller guarantees the value `< p`.
    fn from_be32_unchecked(b: &[u8; 32]) -> Fq {
        let mut limbs = [0u64; 4];
        for i in 0..4 {
            let mut v = 0u64;
            for j in 0..8 {
                v |= (b[8 * i + j] as u64) << (8 * (7 - j));
            }
            limbs[3 - i] = v;
        }
        let f = Fq(limbs);
        debug_assert!(f.lt_p());
        f
    }

    fn lt_p(&self) -> bool {
        for i in (0..4).rev() {
            if self.0[i] < P[i] {
                return true;
            }
            if self.0[i] > P[i] {
                return false;
            }
        }
        false // equal is not < p
    }

    fn to_be32(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..4 {
            for j in 0..8 {
                out[8 * i + j] = (self.0[3 - i] >> (8 * (7 - j))) as u8;
            }
        }
        out
    }

    fn add(&self, other: &Fq) -> Fq {
        let mut o = [0u64; 4];
        let mut carry = 0u128;
        for i in 0..4 {
            let v = self.0[i] as u128 + other.0[i] as u128 + carry;
            o[i] = v as u64;
            carry = v >> 64;
        }
        if carry == 1 {
            // True sum is o + 2^256; result is o + (2^256 - p) = o + (2^32 + 977).
            // Bound: o < 2p - 2 - 2^256 = 2^256 - 2^33 - 1956, so adding
            // 2^32 + 977 cannot overflow 2^256 and stays < p.
            let mut c = 0u128;
            let v = o[0] as u128 + 977 + (1u128 << 32) + c;
            o[0] = v as u64;
            c = v >> 64;
            for i in 1..4 {
                let v = o[i] as u128 + c;
                o[i] = v as u64;
                c = v >> 64;
            }
            debug_assert!(c == 0);
        } else if ge4(&o, &P) {
            o = sub4(&o, &P);
        }
        Fq(o)
    }

    fn sub(&self, other: &Fq) -> Fq {
        let (o, borrow) = sub_borrow4(&self.0, &other.0);
        if borrow == 0 {
            return Fq(o);
        }
        // True value is o + 2^256 - 2^256 ... = o - (2^256 - p) = o - (2^32 + 977).
        let (o2, borrow2) = sub_borrow4(&o, &[977 + (1u64 << 32), 0, 0, 0]);
        debug_assert!(borrow2 == 0);
        // The 2^32 part: subtracting (2^32 + 977) as limb0 handles the low
        // 64 bits; the value o >= 2^256 - p > 2^32 + 977 so no underflow.
        Fq(o2)
    }

    fn neg(&self) -> Fq {
        if self.is_zero() {
            *self
        } else {
            Fq(sub4(&P, &self.0))
        }
    }

    fn mul(&self, other: &Fq) -> Fq {
        // 64-bit limbs -> 32-bit limbs, schoolbook product.
        let mut a32 = [0u64; 8];
        let mut b32 = [0u64; 8];
        for i in 0..4 {
            a32[2 * i] = self.0[i] & 0xFFFF_FFFF;
            a32[2 * i + 1] = self.0[i] >> 32;
            b32[2 * i] = other.0[i] & 0xFFFF_FFFF;
            b32[2 * i + 1] = other.0[i] >> 32;
        }
        // Each t[k] < 8 * 2^64 = 2^67: no u128 overflow.
        let mut t = [0u128; 16];
        for i in 0..8 {
            for j in 0..8 {
                t[i + j] += a32[i] as u128 * b32[j] as u128;
            }
        }
        // Carry-propagate base 2^32 into 17 limbs (exact product).
        let mut c = [0u64; 17];
        let mut carry = 0u128;
        for k in 0..16 {
            let v = t[k] + carry;
            c[k] = (v & 0xFFFF_FFFF) as u64;
            carry = v >> 32;
        }
        c[16] = carry as u64;
        // Fold limbs k >= 8: 2^(32k) = 2^(32(k-8)) * 2^256
        //                 equiv 2^(32(k-8)) * (2^32 + 977).
        let mut r = [0u128; 10];
        for k in 0..8 {
            r[k] = c[k] as u128;
        }
        for k in 8..17 {
            let hi = c[k] as u128;
            r[k - 8] += hi * 977;
            r[k - 7] += hi;
        }
        for m in [9usize, 8] {
            let top = r[m];
            r[m] = 0;
            r[m - 8] += top * 977;
            r[m - 7] += top;
        }
        // r[0..8] < 2^53 each. Normalize base 2^32 -> h + C1 * 2^256.
        let mut h = [0u64; 8];
        let mut carry = 0u128;
        for k in 0..8 {
            let v = r[k] + carry;
            h[k] = (v & 0xFFFF_FFFF) as u64;
            carry = v >> 32;
        }
        // r[0..8] < 2^53 each (u128). Normalize base 2^32 -> h + C1 * 2^256.
        let mut h = [0u64; 8];
        let mut c1 = 0u128;
        for k in 0..8 {
            let v = r[k] + c1;
            h[k] = (v & 0xFFFF_FFFF) as u64;
            c1 = v >> 32;
        }
        // Exact value = H + C1 * (2^32 + 977). Compute in 9 base-2^32
        // limbs (canonical: every limb < 2^32 after the masked adds
        // below), then reduce by a single conditional subtraction of p.
        // Bound: C1 < 2^24, so S < 2^256 + 2^57 < 2p — one subtraction
        // always suffices, and the value stays canonical throughout.
        const P32: [u64; 8] = [
            0xFFFFFC2F, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
            0xFFFFFFFF, 0xFFFFFFFF,
        ];
        let mut s = [0u64; 9];
        for k in 0..8 {
            s[k] = h[k];
        }
        // Add C1 * 977 at limb 0.
        let mut carry = c1 * 977;
        let mut k = 0;
        while carry != 0 && k < 9 {
            let v = s[k] as u128 + carry;
            s[k] = (v & 0xFFFF_FFFF) as u64;
            carry = v >> 32;
            k += 1;
        }
        // Add C1 at limb 1 (the C1 * 2^32 term).
        carry = c1;
        k = 1;
        while carry != 0 && k < 9 {
            let v = s[k] as u128 + carry;
            s[k] = (v & 0xFFFF_FFFF) as u64;
            carry = v >> 32;
            k += 1;
        }
        // Single conditional subtraction (S < 2p, canonical limbs, so the
        // lexicographic compare against P32 is valid and the borrow chain
        // below keeps every limb in [0, 2^32)).
        let mut ge = false;
        for i in (0..9).rev() {
            let pi = if i < 8 { P32[i] } else { 0 };
            if s[i] != pi {
                ge = s[i] > pi;
                break;
            }
            if i == 0 {
                ge = true;
            }
        }
        if ge {
            let mut borrow: i64 = 0;
            for i in 0..9 {
                let pi = if i < 8 { P32[i] as i64 } else { 0 };
                let v = s[i] as i64 - pi - borrow;
                if v < 0 {
                    s[i] = (v + (1i64 << 32)) as u64;
                    borrow = 1;
                } else {
                    s[i] = v as u64;
                    borrow = 0;
                }
            }
            debug_assert!(borrow == 0);
            debug_assert!(s[8] == 0);
        }
        Fq([
            s[0] | (s[1] << 32),
            s[2] | (s[3] << 32),
            s[4] | (s[5] << 32),
            s[6] | (s[7] << 32),
        ])
    }

    fn sqr(&self) -> Fq {
        self.mul(self)
    }

    /// `self^exp`, binary square-and-multiply, `exp` as 4 LE u64 limbs.
    fn pow(&self, exp: &[u64; 4]) -> Fq {
        let mut result = Fq::ONE;
        for i in (0..4).rev() {
            for b in (0..64).rev() {
                result = result.sqr();
                if (exp[i] >> b) & 1 == 1 {
                    result = result.mul(self);
                }
            }
        }
        result
    }

    /// Multiplicative inverse via Fermat (`p` prime). `None` on zero.
    fn inv(&self) -> Option<Fq> {
        if self.is_zero() {
            return None;
        }
        // p - 2
        Some(self.pow(&[
            0xFFFFFFFEFFFFFC2D,
            0xFFFFFFFFFFFFFFFF,
            0xFFFFFFFFFFFFFFFF,
            0xFFFFFFFFFFFFFFFF,
        ]))
    }
}

fn ge4(a: &[u64; 4], b: &[u64; 4]) -> bool {
    for i in (0..4).rev() {
        if a[i] > b[i] {
            return true;
        }
        if a[i] < b[i] {
            return false;
        }
    }
    true
}

fn sub4(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let (o, _) = sub_borrow4(a, b);
    o
}

fn sub_borrow4(a: &[u64; 4], b: &[u64; 4]) -> ([u64; 4], u64) {
    let mut o = [0u64; 4];
    let mut borrow = 0i128;
    for i in 0..4 {
        let v = a[i] as i128 - b[i] as i128 - borrow;
        o[i] = v as u64;
        borrow = if v < 0 { 1 } else { 0 };
    }
    (o, borrow as u64)
}

// ---------------------------------------------------------------------------
// Scalar field mod n (secp256k1 group order).
// ---------------------------------------------------------------------------

const N: [u64; 4] = [
    0xBFD25E8CD0364141,
    0xBAAEDCE6AF48A03B,
    0xFFFFFFFFFFFFFFFE,
    0xFFFFFFFFFFFFFFFF,
];

/// Scalar mod `n`, always fully reduced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Scalar([u64; 4]);

impl Scalar {
    const ZERO: Scalar = Scalar([0, 0, 0, 0]);

    fn is_zero(&self) -> bool {
        self.0 == [0, 0, 0, 0]
    }

    /// Pack 32 big-endian bytes; `None` when the value is `>= n`.
    fn from_be32_exact(b: &[u8; 32]) -> Option<Scalar> {
        let mut limbs = [0u64; 4];
        for i in 0..4 {
            let mut v = 0u64;
            for j in 0..8 {
                v |= (b[8 * i + j] as u64) << (8 * (7 - j));
            }
            limbs[3 - i] = v;
        }
        if ge4(&limbs, &N) {
            return None;
        }
        Some(Scalar(limbs))
    }

    /// Pack 32 big-endian bytes, reducing mod `n` (input `< 2^256 < 2n`,
    /// so at most one subtraction).
    fn from_be32_reduced(b: &[u8; 32]) -> Scalar {
        let mut limbs = [0u64; 4];
        for i in 0..4 {
            let mut v = 0u64;
            for j in 0..8 {
                v |= (b[8 * i + j] as u64) << (8 * (7 - j));
            }
            limbs[3 - i] = v;
        }
        if ge4(&limbs, &N) {
            Scalar(sub4(&limbs, &N))
        } else {
            Scalar(limbs)
        }
    }

    fn add(&self, other: &Scalar) -> Scalar {
        let mut o = [0u64; 4];
        let mut carry = 0u128;
        for i in 0..4 {
            let v = self.0[i] as u128 + other.0[i] as u128 + carry;
            o[i] = v as u64;
            carry = v >> 64;
        }
        // Result < 2n: subtract n when carry or >= n.
        if carry == 1 || ge4(&o, &N) {
            // carry == 1 implies o = (a + b) mod 2^256 and the true sum
            // is o + 2^256; subtracting n once: borrow chain handles it
            // because o + 2^256 - n = o - (n - 2^256)... do it on 5 limbs.
            let mut w = [0u64; 5];
            for i in 0..4 {
                w[i] = o[i];
            }
            w[4] = carry as u64;
            let mut borrow = 0i128;
            for i in 0..5 {
                let ni = if i < 4 { N[i] } else { 0 };
                let v = w[i] as i128 - ni as i128 - borrow;
                w[i] = v as u64;
                borrow = if v < 0 { 1 } else { 0 };
            }
            debug_assert!(borrow == 0);
            Scalar([w[0], w[1], w[2], w[3]])
        } else {
            Scalar(o)
        }
    }

    fn neg(&self) -> Scalar {
        if self.is_zero() {
            *self
        } else {
            Scalar(sub4(&N, &self.0))
        }
    }

    fn mul(&self, other: &Scalar) -> Scalar {
        // Schoolbook into 9 u64 limbs (true product < n^2 < 2^512, so
        // limb 8 stays zero).
        let mut r = [0u64; 9];
        for i in 0..4 {
            let mut carry = 0u128;
            for j in 0..4 {
                let v = r[i + j] as u128 + self.0[i] as u128 * other.0[j] as u128 + carry;
                r[i + j] = v as u64;
                carry = v >> 64;
            }
            let mut k = i + 4;
            let mut c = carry;
            while c != 0 && k < 9 {
                let v = r[k] as u128 + c;
                r[k] = v as u64;
                c = v >> 64;
                k += 1;
            }
        }
        scalar_reduce(r)
    }

    fn sqr(&self) -> Scalar {
        self.mul(self)
    }

    fn pow(&self, exp: &[u64; 4]) -> Scalar {
        let mut result = Scalar([1, 0, 0, 0]);
        for i in (0..4).rev() {
            for b in (0..64).rev() {
                result = result.sqr();
                if (exp[i] >> b) & 1 == 1 {
                    result = result.mul(self);
                }
            }
        }
        result
    }

    /// Multiplicative inverse via Fermat (`n` prime). `None` on zero.
    fn inv(&self) -> Option<Scalar> {
        if self.is_zero() {
            return None;
        }
        // n - 2
        Some(self.pow(&[
            0xBFD25E8CD036413F,
            0xBAAEDCE6AF48A03B,
            0xFFFFFFFFFFFFFFFE,
            0xFFFFFFFFFFFFFFFF,
        ]))
    }
}

/// Reduce a 512-bit value (9 LE u64 limbs) mod `n` by shift-and-subtract.
/// Obviously correct; the scalar field is only used for a few operations
/// per recovery (one inverse), so the 512-iteration loop is affordable.
fn scalar_reduce(mut r: [u64; 9]) -> Scalar {
    for k in (0..512).rev() {
        let ws = k / 64;
        let bs = (k % 64) as u32;
        if ws + 4 > 9 {
            continue; // N << k overflows 9 limbs, hence > r
        }
        let mut t = [0u64; 9];
        let mut carry = 0u64;
        for i in 0..4 {
            let v = ((N[i] as u128) << bs) | carry as u128;
            t[ws + i] = v as u64;
            carry = (v >> 64) as u64;
        }
        if ws + 4 < 9 {
            t[ws + 4] = carry;
        } else if carry != 0 {
            continue; // overflowed 9 limbs: t > r
        }
        // if r >= t: r -= t
        let mut ge = true;
        for i in (0..9).rev() {
            if r[i] > t[i] {
                break;
            }
            if r[i] < t[i] {
                ge = false;
                break;
            }
        }
        if ge {
            let mut borrow = 0i128;
            for i in 0..9 {
                let v = r[i] as i128 - t[i] as i128 - borrow;
                r[i] = v as u64;
                borrow = if v < 0 { 1 } else { 0 };
            }
        }
    }
    Scalar([r[0], r[1], r[2], r[3]])
}

// ---------------------------------------------------------------------------
// secp256k1 curve: Jacobian point arithmetic (a = 0).
// ---------------------------------------------------------------------------

const GX: Fq = Fq([
    0x59F2815B16F81798,
    0x029BFCDB2DCE28D9,
    0x55A06295CE870B07,
    0x79BE667EF9DCBBAC,
]);
const GY: Fq = Fq([
    0x9C47D08FFB10D4B8,
    0xFD17B448A6855419,
    0x5DA4FBFC0E1108A8,
    0x483ADA7726A3C465,
]);

#[derive(Clone, Copy, Debug)]
struct Point {
    x: Fq,
    y: Fq,
    z: Fq,
    inf: bool,
}

impl Point {
    fn infinity() -> Point {
        Point {
            x: Fq::ZERO,
            y: Fq::ZERO,
            z: Fq::ZERO,
            inf: true,
        }
    }

    fn generator() -> Point {
        Point {
            x: GX,
            y: GY,
            z: Fq::ONE,
            inf: false,
        }
    }

    fn is_infinity(&self) -> bool {
        self.inf
    }

    /// Doubling, `dbl-1989` for `a = 0`:
    /// S = 4XY^2, M = 3X^2, X' = M^2 - 2S, Y' = M(S - X') - 8Y^4, Z' = 2YZ.
    fn dbl(&self) -> Point {
        if self.inf {
            return *self;
        }
        let y2 = self.y.sqr();
        let s = self.x.mul(&y2).add(&self.x.mul(&y2)).add(&self.x.mul(&y2)).add(&self.x.mul(&y2));
        let x2 = self.x.sqr();
        let m = x2.add(&x2).add(&x2);
        let x3 = m.sqr().sub(&s).sub(&s);
        let y4 = y2.sqr();
        let y3 = m
            .mul(&s.sub(&x3))
            .sub(&y4.add(&y4).add(&y4).add(&y4).add(&y4).add(&y4).add(&y4).add(&y4));
        let z3 = self.y.add(&self.y).mul(&self.z);
        Point {
            x: x3,
            y: y3,
            z: z3,
            inf: false,
        }
    }

    /// Addition, `add-1998` for `a = 0`.
    fn add(&self, other: &Point) -> Point {
        if self.inf {
            return *other;
        }
        if other.inf {
            return *self;
        }
        let z1z1 = self.z.sqr();
        let z2z2 = other.z.sqr();
        let u1 = self.x.mul(&z2z2);
        let u2 = other.x.mul(&z1z1);
        let s1 = self.y.mul(&z2z2.mul(&other.z));
        let s2 = other.y.mul(&z1z1.mul(&self.z));
        if u1 == u2 {
            if s1 == s2 {
                return self.dbl();
            } else {
                return Point::infinity();
            }
        }
        let h = u2.sub(&u1);
        let r_ = s2.sub(&s1);
        let h2 = h.sqr();
        let h3 = h2.mul(&h);
        let u1h2 = u1.mul(&h2);
        let x3 = r_.sqr().sub(&h3).sub(&u1h2).sub(&u1h2);
        let y3 = r_.mul(&u1h2.sub(&x3)).sub(&s1.mul(&h3));
        let z3 = h.mul(&self.z).mul(&other.z);
        Point {
            x: x3,
            y: y3,
            z: z3,
            inf: false,
        }
    }

    /// Double-and-add scalar multiplication (not constant-time; see
    /// module docs).
    fn mul_scalar(&self, scalar: &Scalar) -> Point {
        let mut r = Point::infinity();
        for i in (0..4).rev() {
            for b in (0..64).rev() {
                r = r.dbl();
                if (scalar.0[i] >> b) & 1 == 1 {
                    r = r.add(self);
                }
            }
        }
        r
    }

    /// Jacobian -> affine. `None` for the point at infinity.
    fn to_affine(&self) -> Option<(Fq, Fq)> {
        if self.inf {
            return None;
        }
        let zinv = self.z.inv()?;
        let zinv2 = zinv.sqr();
        Some((self.x.mul(&zinv2), self.y.mul(&zinv2).mul(&zinv)))
    }
}

/// Recover the affine point with the given x-coordinate and y parity.
/// `None` when `x^3 + 7` is not a quadratic residue (fail-closed).
fn point_from_x(x: Fq, y_odd: bool) -> Option<(Fq, Fq)> {
    // y^2 = x^3 + 7; p = 3 (mod 4) so sqrt is y = (x^3+7)^((p+1)/4).
    let y2 = x.sqr().mul(&x).add(&Fq::from_u64(7));
    let y = y2.pow(&[
        0xFFFFFFFFBFFFFF0C,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
        0x3FFFFFFFFFFFFFFF,
    ]);
    if y.sqr() != y2 {
        return None;
    }
    let y = if y.is_odd() == y_odd { y } else { y.neg() };
    Some((x, y))
}

// ---------------------------------------------------------------------------
// ECDSA recovery and the EVM release-authorization envelope.
// ---------------------------------------------------------------------------

/// An Ethereum-format ECDSA signature: big-endian `r`, `s` and `v`
/// (`27`/`28`, the Ethereum convention). Malformed values fail closed at
/// recovery time — never a panic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvmSignature {
    /// Big-endian `r` (must be `< n`).
    pub r: [u8; 32],
    /// Big-endian `s` (must be `< n`, nonzero).
    pub s: [u8; 32],
    /// Ethereum recovery id: `27` or `28`.
    pub v: u8,
}

/// Domain separation for release authorizations (EIP-191 style personal
/// envelope is *not* used here — the preimage is fully specified).
pub const RELEASE_AUTH_DOMAIN: &[u8] = b"ESCROW-RELEASE-V1";

/// Off-chain binding of an EVM wallet to the escrow's taker: once bound,
/// that address's signature authorizes a release (cross-chain escrow —
/// the Ethereum signer never needs a Solana key).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvmTakerBinding {
    /// The escrow's taker (Solana-side identity, 32 bytes).
    pub taker: [u8; 32],
    /// The bound Ethereum address (20 bytes).
    pub evm_address: [u8; 20],
}

/// Bind an EVM wallet to a taker. `None` for the zero address
/// (fail-closed: nobody holds it, so binding it is always a bug).
pub fn bind_evm_taker(taker: [u8; 32], evm_address: [u8; 20]) -> Option<EvmTakerBinding> {
    if evm_address == [0u8; 20] {
        return None;
    }
    Some(EvmTakerBinding { taker, evm_address })
}

/// The release-authorization message hash:
/// `keccak256(domain || escrow_id || taker || evm_address || amount_le || nonce_le)`.
/// The `nonce` lets the taker authorize a *specific* release amount once;
/// replaying the signature for a different amount or escrow fails.
pub fn release_authorization_hash(
    binding: &EvmTakerBinding,
    escrow_id: &[u8; 32],
    amount: u64,
    nonce: u64,
) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(RELEASE_AUTH_DOMAIN);
    h.update(escrow_id);
    h.update(&binding.taker);
    h.update(&binding.evm_address);
    h.update(&amount.to_le_bytes());
    h.update(&nonce.to_le_bytes());
    h.finalize()
}

/// EIP-191 `personal_sign` hash:
/// `keccak256("\x19Ethereum Signed Message:\n" || len || message)`.
/// Wallets sign this envelope; use it when the EVM side signs with
/// `personal_sign` / `eth_sign` rather than the raw
/// [`release_authorization_hash`] preimage.
pub fn personal_sign_hash(message: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(b"\x19Ethereum Signed Message:\n");
    let mut len = message.len() as u64;
    let mut digits = [0u8; 20];
    let mut n = 0usize;
    if len == 0 {
        digits[0] = b'0';
        n = 1;
    }
    while len > 0 {
        digits[n] = b'0' + (len % 10) as u8;
        n += 1;
        len /= 10;
    }
    for i in (0..n).rev() {
        h.update(&digits[i..i + 1]);
    }
    h.update(message);
    h.finalize()
}

/// Ethereum address of an uncompressed public key:
/// `keccak256(x || y)[12..32]` (the `0x04` prefix is *not* hashed).
fn eth_address(x: &Fq, y: &Fq) -> [u8; 20] {
    let xb = x.to_be32();
    let yb = y.to_be32();
    let mut h = Keccak256::new();
    h.update(&xb);
    h.update(&yb);
    let d = h.finalize();
    let mut out = [0u8; 20];
    out.copy_from_slice(&d[12..32]);
    out
}

/// Recover the signer's Ethereum address from a 32-byte message hash and
/// an Ethereum-format signature. `None` (fail-closed) on any malformed
/// input: bad `v`, `r`/`s` out of range or zero, non-residue x, or the
/// point at infinity.
pub fn recover_address(msg_hash: &[u8; 32], sig: &EvmSignature) -> Option<[u8; 20]> {
    let recid = match sig.v {
        27 => 0,
        28 => 1,
        _ => return None,
    };
    let r = Scalar::from_be32_exact(&sig.r)?;
    let s = Scalar::from_be32_exact(&sig.s)?;
    if r.is_zero() || s.is_zero() {
        return None;
    }
    // R = (r, y) with the parity bit from the recovery id. r < n < p,
    // so the x-coordinate needs no reduction.
    let (rx, ry) = point_from_x(Fq::from_be32_unchecked(&sig.r), recid == 1)?;
    let r_j = Point {
        x: rx,
        y: ry,
        z: Fq::ONE,
        inf: false,
    };
    // Q = r^-1 * (s*R - z*G) (SEC 1, 4.1.6). Note the inverse is of r,
    // not s: from s = k^-1 (z + r*d), R = k*G, Q = d*G follows
    // s*R = z*G + r*Q, i.e. Q = r^-1 (s*R - z*G).
    let z = Scalar::from_be32_reduced(msg_hash);
    let r_inv = r.inv()?;
    let u1 = z.mul(&r_inv).neg();
    let u2 = s.mul(&r_inv);
    let q = Point::generator()
        .mul_scalar(&u1)
        .add(&r_j.mul_scalar(&u2));
    let (qx, qy) = q.to_affine()?;
    Some(eth_address(&qx, &qy))
}

/// Verify that `sig` over `msg_hash` was made by `address`.
/// Fail-closed: malformed signatures verify as `false`, never panic.
pub fn verify_eth_signature(
    address: &[u8; 20],
    msg_hash: &[u8; 32],
    sig: &EvmSignature,
) -> bool {
    match recover_address(msg_hash, sig) {
        Some(a) => a == *address,
        None => false,
    }
}

/// Verify an EVM release authorization: the bound address must have
/// signed [`release_authorization_hash`] for exactly this
/// `(escrow_id, amount, nonce)`. A signature for any other amount, nonce
/// or escrow fails — the authorization is single-use by construction.
pub fn verify_release_authorization(
    binding: &EvmTakerBinding,
    escrow_id: &[u8; 32],
    amount: u64,
    nonce: u64,
    sig: &EvmSignature,
) -> bool {
    let hash = release_authorization_hash(binding, escrow_id, amount, nonce);
    verify_eth_signature(&binding.evm_address, &hash, sig)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h32(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }

    fn h20(s: &str) -> [u8; 20] {
        let mut out = [0u8; 20];
        for i in 0..20 {
            out[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }

    // -- Keccak-256 pins (independent ground truth: pycryptodome) --------

    #[test]
    fn keccak_empty_pin() {
        assert_eq!(
            keccak256(b""),
            h32("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
        );
    }

    #[test]
    fn keccak_hello_pin() {
        assert_eq!(
            keccak256(b"hello"),
            h32("1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8")
        );
    }

    #[test]
    fn keccak_multiblock_pins() {
        // 300 bytes > the 136-byte rate: exercises multi-block absorb.
        let long = vec![b'a'; 300];
        assert_eq!(
            keccak256(&long),
            h32("5b7e0e47a96f32a88b4f14ca177982790807c40e1a105742ba0fc1babe1ef826")
        );
        // Exactly one rate block: exercises the pad-on-full-block path.
        let exact = vec![b'b'; 136];
        assert_eq!(
            keccak256(&exact),
            h32("121b76d0b19f3c2c7632310b92c54cddd59d16a6b5aafe84696426f10e5733bf")
        );
    }

    #[test]
    fn keccak_streaming_matches_oneshot() {
        let msg = b"streaming absorb must equal one-shot absorb";
        let mut h = Keccak256::new();
        for chunk in msg.chunks(7) {
            h.update(chunk);
        }
        assert_eq!(h.finalize(), keccak256(msg));
    }

    // -- Field arithmetic properties -------------------------------------

    #[test]
    fn fq_arithmetic_properties() {
        // Build test values from small limbs (fully reduced by construction).
        let a = Fq::from_u64(123456789).mul(&Fq::from_u64(987654321));
        let b = Fq::from_u64(0xdeadbeef);
        let c = Fq([
            0xFFFFFFFEFFFFFC2E,
            0xFFFFFFFFFFFFFFFF,
            0xFFFFFFFFFFFFFFFF,
            0xFFFFFFFFFFFFFFFF,
        ]); // p - 1, little-endian limbs
        assert_eq!(a.add(&b), b.add(&a));
        assert_eq!(a.mul(&b), b.mul(&a));
        assert_eq!(a.mul(&b.add(&c)), a.mul(&b).add(&a.mul(&c)));
        assert_eq!(a.sub(&a), Fq::ZERO);
        assert_eq!(a.add(&c).add(&Fq::ONE), a); // a + (p-1) + 1 = a
        assert_eq!(Fq::from_u64(2).mul(&Fq::from_u64(3)), Fq::from_u64(6));
        // Inverse round-trips.
        for v in [2u64, 7, 123456789, 0xFFFFFFFFFFFFFFFF] {
            let x = Fq::from_u64(v);
            assert_eq!(x.mul(&x.inv().unwrap()), Fq::ONE);
        }
        assert!(Fq::ZERO.inv().is_none());
    }

    #[test]
    fn scalar_arithmetic_properties() {
        let a = Scalar([123456789, 987654321, 0xdeadbeef, 42]);
        let b = Scalar([0xFFFFFFFFFFFFFFFF, 1, 2, 3]);
        assert_eq!(a.add(&b), b.add(&a));
        assert_eq!(a.mul(&b), b.mul(&a));
        let c = Scalar([7, 7, 7, 7]);
        assert_eq!(a.mul(&b.add(&c)), a.mul(&b).add(&a.mul(&c)));
        for v in [
            Scalar([2, 0, 0, 0]),
            Scalar([0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 1]),
        ] {
            assert_eq!(v.mul(&v.inv().unwrap()), Scalar([1, 0, 0, 0]));
        }
        assert!(Scalar::ZERO.inv().is_none());
    }

    // -- Curve pins (independent ground truth: python-ecdsa) --------------

    #[test]
    fn generator_is_on_curve() {
        // y^2 = x^3 + 7
        let lhs = GY.sqr();
        let rhs = GX.sqr().mul(&GX).add(&Fq::from_u64(7));
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn double_generator_pin() {
        let g2 = Point::generator().dbl();
        let (x, y) = g2.to_affine().unwrap();
        assert_eq!(
            x.to_be32(),
            h32("c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")
        );
        assert_eq!(
            y.to_be32(),
            h32("1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a")
        );
    }

    #[test]
    fn n_times_generator_is_infinity() {
        let n = Scalar(N);
        assert!(Point::generator().mul_scalar(&n).is_infinity());
    }

    // -- Recovery pins (independent: pycryptodome + python-ecdsa RFC6979) --

    /// Vector 1: personal_sign("escrow-release AV-185 vector"), recid 0.
    fn vector1() -> ([u8; 32], EvmSignature, [u8; 20]) {
        (
            h32("5e7a58eb014dbac1340c869b7591b17b9c99e7ad97bd46b222b4b261bdc66894"),
            EvmSignature {
                r: h32("02f385e08fca719460f414ab4b431653d6ca5e776f0184d8ffa757df50a65edb"),
                s: h32("1a12a0e4c89b773c1545f8c20f24dc91b033d71952fc25dca80230796ea40454"),
                v: 27,
            },
            h20("5872c63afbea32cb4540bbe9f8db08a3c6af8942"),
        )
    }

    #[test]
    fn personal_sign_hash_matches_vector_preimage() {
        // The vector's msg_hash is keccak256 of the EIP-191 preimage; this
        // pins personal_sign_hash against pycryptodome independently of
        // the recover path.
        assert_eq!(
            personal_sign_hash(b"escrow-release AV-185 vector"),
            h32("5e7a58eb014dbac1340c869b7591b17b9c99e7ad97bd46b222b4b261bdc66894")
        );
    }

    #[test]
    fn recover_vector1_recid0() {
        let (hash, sig, addr) = vector1();
        assert_eq!(recover_address(&hash, &sig), Some(addr));
        assert!(verify_eth_signature(&addr, &hash, &sig));
    }

    #[test]
    fn recover_vector3_recid1() {
        // "recid hunt 0", v = 28.
        let hash = h32("249372b63e5da852bc634480e6c1997715ef60a58eeba409280ef89f36bc7b32");
        let sig = EvmSignature {
            r: h32("b1d8c615b38b082913bc6117c0937ff87c3a239457f989e91276c60a6c2dab44"),
            s: h32("705824834688481ccc1683166e8886f7e902bbe2d7afea186593508d0c9fb925"),
            v: 28,
        };
        let addr = h20("9799c01d8f0145cb8f7001513858ea0c8074e318");
        assert_eq!(recover_address(&hash, &sig), Some(addr));
    }

    #[test]
    fn recover_rejects_malformed() {
        let (hash, sig, addr) = vector1();
        // Bad v values fail closed.
        for v in [0u8, 1, 26, 29, 255] {
            let bad = EvmSignature { v, ..sig };
            assert_eq!(recover_address(&hash, &bad), None);
            assert!(!verify_eth_signature(&addr, &hash, &bad));
        }
        // r >= n, s == 0 fail closed.
        let n_plus = EvmSignature { r: h32("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"), ..sig };
        assert_eq!(recover_address(&hash, &n_plus), None);
        let s_zero = EvmSignature { s: [0u8; 32], ..sig };
        assert_eq!(recover_address(&hash, &s_zero), None);
    }

    #[test]
    fn recover_tampered_hash_fails_verification() {
        let (hash, sig, addr) = vector1();
        let mut tampered = hash;
        tampered[0] ^= 0x01;
        // Recovery still yields *an* address (fail-open would be a bug
        // only if it equaled the bound one)...
        let recovered = recover_address(&tampered, &sig).unwrap();
        assert_ne!(recovered, addr);
        // ...and verification against the bound address fails.
        assert!(!verify_eth_signature(&addr, &tampered, &sig));
    }

    // -- Release-authorization envelope ------------------------------------

    /// Vector 2: release_authorization_hash over
    /// (escrow_id = 0xaa*32, taker = 0xbb*32, amount = 1500000, nonce = 7).
    fn vector2() -> (EvmTakerBinding, [u8; 32], u64, u64, EvmSignature) {
        let binding = bind_evm_taker([0xbb; 32], h20("abde9547ea59f98d0a1e82537bcc2befac150fcf")).unwrap();
        (
            binding,
            [0xaa; 32],
            1_500_000,
            7,
            EvmSignature {
                r: h32("43864cafd2bae66c1f865459174af391f2cbfb6d0d2adf5edb02e42030b94931"),
                s: h32("17d5c3aa4163e8cc41657090ba0deec491da29ead6536950d6aaa5d2295295db"),
                v: 27,
            },
        )
    }

    #[test]
    fn release_authorization_hash_pin() {
        let (binding, escrow_id, amount, nonce, _) = vector2();
        assert_eq!(
            release_authorization_hash(&binding, &escrow_id, amount, nonce),
            h32("eaf44c93a4ae534623fc70e8c19263d6e14aa47527897fe73773c94c69be602a")
        );
    }

    #[test]
    fn verify_release_authorization_positive_and_replay_resistant() {
        let (binding, escrow_id, amount, nonce, sig) = vector2();
        assert!(verify_release_authorization(&binding, &escrow_id, amount, nonce, &sig));
        // A different amount, nonce, or escrow is a different message:
        // the signature does not transfer.
        assert!(!verify_release_authorization(&binding, &escrow_id, amount + 1, nonce, &sig));
        assert!(!verify_release_authorization(&binding, &escrow_id, amount, nonce + 1, &sig));
        assert!(!verify_release_authorization(&binding, &[0xac; 32], amount, nonce, &sig));
        // A different bound address rejects the same signature.
        let other = bind_evm_taker([0xbb; 32], h20("9799c01d8f0145cb8f7001513858ea0c8074e318")).unwrap();
        assert!(!verify_release_authorization(&other, &escrow_id, amount, nonce, &sig));
    }

    #[test]
    fn bind_rejects_zero_address() {
        assert_eq!(bind_evm_taker([0xbb; 32], [0u8; 20]), None);
    }
}
