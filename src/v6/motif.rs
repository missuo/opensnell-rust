//! The v6.0.0 "motif": the deterministic filler written into every non-salt
//! byte of the salt region, each frame's header-AAD and each frame's padding.
//!
//! It depends only on the PSK, the tag and the output length, never on the
//! salt. Reverse-engineered from snell-server v6.0.0 (fill @0x3a7c0, keystream
//! @0x39d90) and validated byte for byte against it (opensnell
//! `v6b2_motif.go`).

use super::prf::{Prf, reduce, splitmix64};

/// Tag of the salt-region filler. Frames use their index `k` as the tag.
pub(crate) const TAG_REGION: u32 = 0xffff_ffff;

/// `ROWS[k]` lists 16 byte values with exactly `k` bits set (row 0 unused).
const ROWS: [[u8; 16]; 8] = [
    [0; 16],
    [
        0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
        0x80,
    ],
    [
        0x03, 0x05, 0x09, 0x11, 0x21, 0x41, 0x81, 0x06, 0x0a, 0x12, 0x22, 0x42, 0x82, 0x0c, 0x18,
        0x24,
    ],
    [
        0x07, 0x0b, 0x13, 0x23, 0x43, 0x83, 0x0d, 0x19, 0x31, 0x61, 0xc1, 0x0e, 0x1c, 0x38, 0x70,
        0xe0,
    ],
    [
        0x0f, 0x17, 0x27, 0x47, 0x87, 0x1b, 0x33, 0x63, 0xc3, 0x1d, 0x39, 0x71, 0xe1, 0x3c, 0x78,
        0xf0,
    ],
    [
        0xf8, 0xf4, 0xec, 0xdc, 0xbc, 0x7c, 0xf2, 0xe6, 0xce, 0x9e, 0x3e, 0xf1, 0xe3, 0xc7, 0x8f,
        0x1f,
    ],
    [
        0xfc, 0xfa, 0xf6, 0xee, 0xde, 0xbe, 0x7e, 0xf9, 0xf5, 0xed, 0xdd, 0xbd, 0x7d, 0xf3, 0xe7,
        0xdb,
    ],
    [
        0xfe, 0xfd, 0xfb, 0xf7, 0xef, 0xdf, 0xbf, 0x7f, 0xfe, 0xfd, 0xfb, 0xf7, 0xef, 0xdf, 0xbf,
        0x7f,
    ],
];

#[derive(Clone)]
pub(crate) struct Motif {
    /// Base fields of keystream domains 0 and 2.
    base0: u64,
    base2: u64,
    /// Domain-1 base for the mode-0 bit-percent PRF.
    base1: u64,
    pub(crate) mode: u32,
    bit_min: u32,
    bit_max: u32,
    a1: u32,
    a2: u32,
    a3: u32,
    digit_off: u32,
    m3: u32,
    period: u32,
}

impl Motif {
    pub(crate) fn new(prf: &Prf) -> Self {
        Self {
            base0: prf.base(0),
            base2: prf.base(2),
            base1: prf.base(1),
            mode: prf.get(6, 0, 0) & 3,
            bit_min: reduce(prf.get(12, 0, 0), 24, 41),
            bit_max: reduce(prf.get(13, 0, 0), 58, 76),
            a1: reduce(prf.get(6, 1, 0), 24, 128),
            a2: reduce(prf.get(6, 2, 0), 16, 96),
            a3: reduce(prf.get(6, 3, 0), 16, 96),
            digit_off: reduce(prf.get(6, 4, 0), 0, 9),
            m3: reduce(prf.get(6, 5, 0), 1, 8),
            period: reduce(prf.get(6, 6, 0), 7, 23),
        }
    }

    /// The SplitMix64 counter stream for (domain, tag, out.len()). The length
    /// is mixed into the seed, so a stream is not a prefix of a longer one.
    fn keystream(&self, domain: u32, tag: u32, out: &mut [u8]) {
        let base = if domain == 0 { self.base0 } else { self.base2 };
        let n = out.len() as u64;
        let mut x = u64::from(tag)
            .wrapping_mul(0xd6e8_feb8_6659_fd93)
            .wrapping_add(0xb57d_e1f3_f82c_b33f)
            ^ u64::from(domain).wrapping_mul(0xa24b_aed4_963e_e407)
            ^ n.wrapping_mul(0x1656_67b1_9e37_79f9)
                .wrapping_add(0x0d4c_d3e7_b14a_36d7)
            ^ base;
        for chunk in out.chunks_mut(8) {
            x = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let v = splitmix64(x).to_le_bytes();
            chunk.copy_from_slice(&v[..chunk.len()]);
        }
    }

    /// Writes the motif for `tag` into `out`.
    pub(crate) fn fill(&self, tag: u32, out: &mut [u8]) {
        if out.is_empty() {
            return;
        }
        self.keystream(0, tag, out);
        match self.mode {
            0 => {
                // Fixed popcount per byte, chosen by the bit-percent PRF.
                let pct = reduce(
                    super::prf::prf_base(self.base1, 1, 0, tag),
                    self.bit_min,
                    self.bit_max,
                ) & 0xff;
                let e = pct * 8;
                let ones = if e <= 49 {
                    1
                } else if e > 749 {
                    7
                } else {
                    (e + 50) / 100
                };
                let row = &ROWS[ones as usize];
                for (i, o) in out.iter_mut().enumerate() {
                    let b = *o;
                    let x = (i as u8).wrapping_add(b);
                    *o = row[usize::from((x ^ b) & 0xf)].rotate_left(u32::from(((b >> 4) ^ x) & 7));
                }
            }
            1 => {
                // UTF-8-looking byte classes.
                let sum = self.a1 + self.a2 + self.a3;
                for (i, o) in out.iter_mut().enumerate() {
                    let b = *o;
                    let c = u32::from(b) % sum;
                    *o = if c < self.a1 {
                        0x20 + b.wrapping_add(i as u8) % 95
                    } else if c < self.a1 + self.a2 {
                        0x80 + (b ^ i as u8) % 64
                    } else {
                        0xc0 + b.wrapping_add(i.wrapping_mul(7) as u8) % 64
                    };
                }
            }
            2 => {
                // High nibble offset, low nibble a decimal digit.
                for (i, o) in out.iter_mut().enumerate() {
                    let b = *o;
                    let hi = (u32::from(b >> 4) + (i & 3) as u32 + 3) << 4;
                    let lo = (u32::from(b & 0xf) + self.digit_off + (i & 1) as u32) % 10;
                    *o = (hi as u8) | (lo as u8);
                }
            }
            _ => {
                // XOR with a second stream, interleaved with ASCII digit runs.
                let mut ks2 = [0u8; 32];
                self.keystream(2, tag, &mut ks2);
                let stride = (self.m3 as usize * 4).min(32);
                let p = (self.period as usize).max(5);
                let mul = self.m3 as usize + 3;
                for (i, o) in out.iter_mut().enumerate() {
                    let rem = i % p;
                    if rem < p - 3 {
                        *o = (mul.wrapping_mul(i) as u8) ^ ks2[i % stride];
                    } else if rem < p - 1 {
                        *o = b'0' + *o % 10;
                    }
                }
            }
        }
    }
}
