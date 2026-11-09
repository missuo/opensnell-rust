//! The v6.0.0 parameter PRF: a BLAKE2b-256 seed of the PSK expanded by a
//! wyhash-style mix and SplitMix64 (reverse-engineered from snell-server
//! v6.0.0; see opensnell `v6b2_profile.go`).

use blake2::{Blake2b256, Digest};

/// Opaque domain-separation constant prepended to the PSK for the seed.
const SEED_PREFIX: [u8; 24] = [
    0x8d, 0x41, 0xa7, 0x13, 0x5c, 0xe2, 0x09, 0xbb, 0x70, 0x2f, 0xd6, 0x94, 0x33, 0x18, 0xc0, 0x6e,
    0x4a, 0x91, 0x25, 0xfd, 0xb8, 0x03, 0x77, 0xac,
];

/// Number of parameter domains (indices into the official label table).
pub(crate) const DOMAINS: usize = 40;

/// Family base-field constant for a family domain.
const fn family_const(fd: u32) -> u64 {
    match fd {
        16 => 0xc9f4_260b_7d1e_835a, // mix
        5 => 0xb46c_2e7d_9a15_38f1,  // pad / misc
        0 => 0x5d92_17c0_83e6_4ab9,  // length / prefix
        21 => 0x62d0_b5e1_9c4a_783f, // chunk
        28 => 0x917b_3c48_e6a2_05d4, // write
        2 => 0xa71f_0c54_d839_6e2b,  // padding-motif
        3 => 0x3e8a_91b5_2740_f6cd,  // mix-offset (salt scatter)
        _ => 0,
    }
}

/// Family a parameter domain routes to (the official jump table).
const fn route(d: u32) -> u32 {
    match d {
        3 | 16..=20 => 16,
        4..=13 | 27 => 5,
        0 | 1 | 14 | 15 | 33 | 34 => 0,
        21..=26 | 38 | 39 => 21,
        28..=32 | 35..=37 => 28,
        2 => 2,
        _ => 0,
    }
}

/// SplitMix64 finalizer.
#[inline(always)]
pub(crate) const fn splitmix64(mut z: u64) -> u64 {
    z ^= z >> 30;
    z = z.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z ^= z >> 27;
    z = z.wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// Family base field for family domain `fd`.
fn base_field(fd: u32, k: &[u64; 4]) -> u64 {
    let x = (u64::from(fd).wrapping_mul(0xd6e8_feb8_6659_fd93))
        ^ family_const(fd).wrapping_add(0xa076_1d64_78bd_642f)
        ^ k[0]
        ^ k[1].wrapping_add(0x9e37_79b9_7f4a_7c15)
        ^ k[2].rotate_left(17)
        ^ k[3].rotate_right(11);
    splitmix64(x)
}

/// The core PRF given an explicit base field.
#[inline(always)]
pub(crate) fn prf_base(base: u64, d: u32, a: u32, b: u32) -> u32 {
    let h = base
        ^ u64::from(a)
            .wrapping_mul(0x5899_65cc_7537_4cc3)
            .wrapping_add(0x33a2_13ec_50ff_e2e9)
        ^ u64::from(d).wrapping_mul(0x9e37_79b9_7f4a_7c15)
        ^ u64::from(b)
            .wrapping_mul(0xe703_7ed1_a0b4_28db)
            .wrapping_add(0x8f39_07f7_b2b8_0c35);
    let h = splitmix64(h);
    (h ^ (h >> 32)) as u32
}

/// `lo + v % (hi - lo + 1)`, or `lo` when the range is empty.
#[inline(always)]
pub(crate) const fn reduce(v: u32, lo: u32, hi: u32) -> u32 {
    if hi <= lo { lo } else { lo + v % (hi - lo + 1) }
}

/// The PSK-keyed PRF with every domain's routed base field precomputed.
#[derive(Clone)]
pub(crate) struct Prf {
    routed: [u64; DOMAINS],
    /// `base_field(3)` taken directly (not routed); keys the salt scatter.
    scatter: u64,
}

impl Prf {
    pub(crate) fn new(psk: &[u8]) -> Self {
        let digest = Blake2b256::new()
            .chain_update(SEED_PREFIX)
            .chain_update(psk)
            .finalize();
        let mut k = [0u64; 4];
        for (i, w) in k.iter_mut().enumerate() {
            *w = u64::from_le_bytes(digest[i * 8..i * 8 + 8].try_into().expect("8 bytes"));
        }
        let mut routed = [0u64; DOMAINS];
        for (d, slot) in routed.iter_mut().enumerate() {
            *slot = base_field(route(d as u32), &k);
        }
        Self {
            routed,
            scatter: base_field(3, &k),
        }
    }

    /// The scalar-parameter PRF `prf(d, a, b)`.
    #[inline(always)]
    pub(crate) fn get(&self, d: u32, a: u32, b: u32) -> u32 {
        prf_base(self.routed[d as usize], d, a, b)
    }

    /// The per-frame "stream" form: `shapeStream(domain, salt32, ctr)`, which
    /// maps to `prf(domain, a = ctr, b = salt32)`.
    #[inline(always)]
    pub(crate) fn stream(&self, d: u32, salt32: u32, ctr: u32) -> u32 {
        self.get(d, ctr, salt32)
    }

    /// Routed base field of domain `d`.
    #[inline(always)]
    pub(crate) fn base(&self, d: u32) -> u64 {
        self.routed[d as usize]
    }

    /// Direct `base_field(3)` used by the salt scatter (perm and mask).
    #[inline(always)]
    pub(crate) fn scatter_base(&self) -> u64 {
        self.scatter
    }
}
