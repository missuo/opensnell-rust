//! The PSK-derived v6.0.0 protocol profile: salt scatter, header-AAD lengths,
//! padding/write-target shaping, the padding<->ciphertext swap and the
//! per-frame payload (chunk) policy. A port of opensnell `v6b2_profile.go`,
//! `v6b2_shape.go` and `v6_shape.go`; every value is GDB-validated against the
//! official server there.

use super::motif::{Motif, TAG_REGION};
use super::prf::{Prf, reduce};

/// Salt length; the salt bytes are scattered inside the region.
const SALT_LEN: usize = 16;
/// Clamp of the per-frame padding top-up and of the padding upper bound.
pub(crate) const PAD_CAP: u32 = 730;
/// Number of write-next buckets.
const BUCKETS: usize = 8;
/// Sealed 7-byte frame header length.
const SEALED_HEADER: u32 = 7 + 16;
const TAG: u32 = 16;

/// Write-target and padding shaping scalars.
#[derive(Clone, Debug)]
pub(crate) struct Shape {
    pad_lo: u32,
    pad_hi: u32,
    pad_count: u32,
    pad_interval: u32,
    small_limit: u32,
    e6: u32,
    fa: u32,
    e8: [u32; BUCKETS],
    d6: [u32; BUCKETS],
    write_mode: u32,
    write_jitter: u32,
    pub(crate) swap_mode: u32,
    swap_rounds: u32,
    swap_block: u32,
    swap_p4a: u32,
    swap_off: u32,
}

/// The official per-frame payload sizing ("chunk" family).
#[derive(Clone, Debug)]
pub(crate) struct Chunk {
    /// 0 = linear ramp, 1 = bucket pick, 2 = ramp ± jitter.
    pub(crate) mode: u32,
    pub(crate) initial: u32,
    /// Extra clamp on frame 0.
    pub(crate) first: u32,
    pub(crate) max: u32,
    pub(crate) step: u32,
    pub(crate) jitter: u32,
    pub(crate) bucket: [u32; BUCKETS],
    /// Seconds without a write after which the ramp restarts.
    pub(crate) idle_reset_secs: u32,
}

/// Everything a v6 default-mode stream needs, derived once per PSK.
#[derive(Clone)]
pub(crate) struct Profile {
    prf: Prf,
    /// Salt region length on the wire (32..=144).
    pub(crate) region_len: usize,
    h_lo: u32,
    h_rng: u32,
    /// Region positions of the 16 salt bytes.
    pub(crate) perm: [u8; SALT_LEN],
    /// XOR mask applied to the scattered salt.
    pub(crate) mask: [u8; SALT_LEN],
    /// The salt region with the motif filled in and the salt positions zero.
    pub(crate) region: Box<[u8]>,
    /// 0xff at every motif (non-salt) region position, 0 at salt positions.
    pub(crate) region_mask: Box<[u8]>,
    pub(crate) shape: Shape,
    pub(crate) chunk: Chunk,
    pub(crate) motif: Motif,
    #[cfg(test)]
    pub(crate) rounds: u32,
    #[cfg(test)]
    pub(crate) m: u8,
}

impl Profile {
    pub(crate) fn derive(psk: &[u8]) -> Self {
        let prf = Prf::new(psk);
        let p = |d, a, b| prf.get(d, a, b);

        let rounds = reduce(p(17, 0x51A7, 0), 1, 4);
        let m = reduce(p(18, 0x51A7, 0), 17, 251) as u8;

        let (rlo, rhi) = clamp_pair(
            reduce(p(14, 0x7053, 0), 16, 96),
            reduce(p(15, 0x7053, 0), 16, 160),
        );
        let region_len = (reduce(p(33, 0x7053, 0), rlo, rhi) + 16) as usize;

        let (hlo, hhi) = clamp_pair(reduce(p(14, 0, 0), 8, 80), reduce(p(15, 0, 0), 16, 160));

        // Salt scatter: Fisher-Yates over [0, R) keyed by the direct
        // base_field(3); perm uses the domain-3 term, the mask domain 2.
        let sb = prf.scatter_base();
        let mut buf: Vec<u8> = (0..region_len as u32).map(|i| i as u8).collect();
        for round in 0..rounds {
            for i in 0..region_len {
                let v = super::prf::prf_base(sb, 3, i as u32, round + 0x51A7);
                let j = i + (v % (region_len - i) as u32) as usize;
                buf.swap(i, j);
            }
        }
        let mut perm = [0u8; SALT_LEN];
        perm.copy_from_slice(&buf[..SALT_LEN]);
        let mut mask = [0u8; SALT_LEN];
        for (j, slot) in mask.iter_mut().enumerate() {
            let v = super::prf::prf_base(sb, 2, j as u32, 0x51A7);
            *slot = ((j as u32).wrapping_mul(u32::from(m)) ^ (v & 0xff)) as u8;
        }

        let motif = Motif::new(&prf);
        let mut region = vec![0u8; region_len].into_boxed_slice();
        motif.fill(TAG_REGION, &mut region);
        let mut region_mask = vec![0xffu8; region_len].into_boxed_slice();
        for &pos in &perm {
            region[usize::from(pos)] = 0;
            region_mask[usize::from(pos)] = 0;
        }

        let shape = derive_shape(&prf);
        let chunk = derive_chunk(&prf);
        Self {
            prf,
            region_len,
            h_lo: hlo,
            h_rng: hhi - hlo + 1,
            perm,
            mask,
            region,
            region_mask,
            shape,
            chunk,
            motif,
            #[cfg(test)]
            rounds,
            #[cfg(test)]
            m,
        }
    }

    /// Header-AAD (filler) length of frame `k`.
    #[inline]
    pub(crate) fn header_aad_len(&self, k: u32) -> usize {
        (self.h_lo + self.prf.get(33, 0, k) % self.h_rng) as usize
    }

    /// Lays the salt into a region that already holds the motif.
    pub(crate) fn scatter_salt(&self, region: &mut [u8], salt: &[u8; SALT_LEN]) {
        for j in 0..SALT_LEN {
            region[usize::from(self.perm[j])] = salt[j] ^ self.mask[j];
        }
    }

    /// Recovers the salt from a region read off the wire.
    pub(crate) fn gather_salt(&self, region: &[u8]) -> [u8; SALT_LEN] {
        let mut salt = [0u8; SALT_LEN];
        for j in 0..SALT_LEN {
            salt[j] = region[usize::from(self.perm[j])] ^ self.mask[j];
        }
        salt
    }

    /// Whether frame `k` carrying `pay_len` bytes gets base padding.
    ///
    /// Base padding applies to the first `pad_count` frames, to every
    /// `pad_interval`-th frame, and to small data frames. A zero chunk is
    /// gated only by the first two rules.
    fn pad_gated(&self, k: u32, pay_len: u32) -> bool {
        let s = &self.shape;
        s.pad_count > k
            || (s.pad_interval > 0 && k.is_multiple_of(s.pad_interval))
            || (pay_len > 0 && pay_len <= s.small_limit)
    }

    /// The per-frame shaping target frame size.
    pub(crate) fn write_target(&self, k: u32, accumulated: u32) -> u32 {
        let s = &self.shape;
        // Frames past the largest bucket get no top-up.
        if accumulated > 1459 {
            return accumulated;
        }
        let acc = i64::from(accumulated);
        let pct = acc * i64::from(s.fa) / 100;
        let mut bucket = if k < s.e6 && (k as usize) < BUCKETS {
            i64::from(s.e8[k as usize])
        } else {
            i64::from(s.d6[(self.prf.stream(35, k, accumulated) % BUCKETS as u32) as usize])
        };
        // write-mode 2 jitters the bucket by a signed offset in [-W, +W].
        if s.write_mode == 2 && s.write_jitter > 0 {
            let w = i64::from(s.write_jitter);
            let rem = i64::from(self.prf.stream(36, k, 0) % (2 * s.write_jitter + 1));
            bucket += rem - w;
            if bucket <= 0 {
                bucket = 1;
            }
        }
        let coin = self.prf.stream(35, k, pct as u32) & 1;
        let mut target = if coin == 0 {
            bucket + pct
        } else {
            bucket - pct / 2
        };
        // Top-up: jump to a larger write bucket, or bump by pad_hi.
        let mut i = 0;
        while acc > target && i < 300 {
            let idx = (self.prf.stream(37, k, target as u32) % BUCKETS as u32) as usize;
            let next = i64::from(s.d6[idx]);
            if next > target {
                target = next;
            } else {
                target += i64::from(s.pad_hi);
                if target > 0xffff {
                    break;
                }
            }
            i += 1;
        }
        target as u32
    }

    /// Padding length of frame `k` (snell-server v6.0.0 @0x3b040).
    ///
    /// `pay_len == 0` is a zero chunk: it carries no sealed payload, so its
    /// overhead has no data tag.
    pub(crate) fn pad_len(
        &self,
        k: u32,
        pay_len: u32,
        header_aad_len: u32,
        first_frame: bool,
    ) -> u32 {
        let s = &self.shape;
        let base = if self.pad_gated(k, pay_len) {
            reduce(self.prf.stream(34, k, pay_len), s.pad_lo, s.pad_hi)
        } else {
            0
        };
        let mut overhead = header_aad_len + SEALED_HEADER + pay_len;
        if pay_len > 0 {
            overhead += TAG;
        }
        if first_frame {
            overhead += self.region_len as u32;
        }
        let accumulated = overhead + base;
        let wt = self.write_target(k, accumulated);
        if accumulated < wt {
            base + (wt - accumulated).min(PAD_CAP)
        } else {
            base
        }
    }

    /// Applies (and inverts: it is an involution) the padding<->ciphertext
    /// interleave of frame `frame` in place. `ct` is the ciphertext with tag.
    pub(crate) fn swap(&self, padding: &mut [u8], ct: &mut [u8], frame: u32) {
        let s = &self.shape;
        let lim = padding.len().min(ct.len());
        if lim == 0 {
            return;
        }
        if s.swap_mode == 1 {
            // Block swap: per round, every other block of `swap_block` bytes.
            let bs = s.swap_block as usize;
            if bs == 0 {
                return;
            }
            for r in 0..s.swap_rounds as usize {
                let mut i = (r & 1) * bs;
                while i + bs <= lim {
                    padding[i..i + bs].swap_with_slice(&mut ct[i..i + bs]);
                    i += 2 * bs;
                }
            }
            return;
        }
        // Periodic single-byte swap (modes 0 and 2).
        for r in 0..s.swap_rounds {
            let period = (s.swap_p4a + r % 3).max(1);
            let phi = if s.swap_mode == 2 {
                self.prf.get(3, r, frame).wrapping_add(s.swap_off) % period
            } else {
                s.swap_off % period
            };
            let mut i = phi as usize;
            while i < lim {
                std::mem::swap(&mut padding[i], &mut ct[i]);
                i += period as usize;
            }
        }
    }

    /// Chunk-policy PRF for frame `k` at ramp value `ramp` (domain 38 bucket
    /// pick or 39 jitter).
    #[inline]
    pub(crate) fn chunk_prf(&self, domain: u32, k: u32, ramp: u32) -> u32 {
        self.prf.stream(domain, k, ramp)
    }

    /// Whether `prefix` (at least 32 bytes) carries this profile's motif at
    /// every non-salt position.
    pub(crate) fn match_region_prefix(&self, prefix: &[u8]) -> bool {
        let diff = prefix
            .iter()
            .zip(self.region_mask.iter().zip(self.region.iter()))
            .fold(0u8, |acc, (b, (m, want))| acc | ((b & m) ^ want));
        diff == 0
    }
}

/// Derives a (lo, hi) bound pair: hi = lo + span, clamped to 128.
fn clamp_pair(lo: u32, span: u32) -> (u32, u32) {
    let hi = (lo + span).min(128);
    (lo.min(hi), hi)
}

fn derive_shape(prf: &Prf) -> Shape {
    let b = |d, x| prf.get(d, x, 0);
    let pad_lo = reduce(b(7, 0), 24, 160);
    let pad_hi = (pad_lo + reduce(b(8, 0), 160, 960)).min(PAD_CAP);
    let mut e8 = [0; BUCKETS];
    let mut d6 = [0; BUCKETS];
    for i in 0..BUCKETS {
        e8[i] = reduce(b(31, i as u32), 360, 1460);
        d6[i] = reduce(b(30, i as u32), 320, 1460);
    }
    Shape {
        pad_lo: pad_lo.min(pad_hi),
        pad_hi,
        pad_count: reduce(b(9, 0), 2, 8),
        pad_interval: reduce(b(10, 0), 2, 11),
        small_limit: reduce(b(11, 0), 96, 768),
        e6: reduce(b(29, 0), 4, 8),
        fa: reduce(b(28, 0x504C), 8, 48),
        e8,
        d6,
        write_mode: b(28, 0) % 3,
        write_jitter: reduce(b(32, 0), 8, 96),
        swap_mode: b(16, 0) % 3,
        swap_rounds: reduce(b(17, 0), 1, 3),
        swap_block: reduce(b(20, 0), 8, 64),
        swap_p4a: reduce(b(18, 0), 2, 13),
        swap_off: reduce(b(19, 0), 0, 15),
    }
}

fn derive_chunk(prf: &Prf) -> Chunk {
    let p = |d, a| prf.get(d, a, 0);
    let initial = reduce(p(22, 0), 0x200, 0x5b4).clamp(96, 1460);
    let max = reduce(p(23, 0), 0x2000, 0x3fff);
    let step = reduce(p(24, 0), 0x400, 0x1000).min(0xb68).min(max);
    let jitter = reduce(p(25, 0), 0x10, 0xc0).min(0xb6);
    let mut bucket = [0; BUCKETS];
    for (i, slot) in bucket.iter_mut().enumerate() {
        *slot = reduce(p(26, i as u32), 0x1000, max).clamp(0x1000, max);
    }
    let first = reduce(p(22, 0xf17c), 0x100, 0x300).min(initial).max(0x100);
    Chunk {
        mode: p(21, 0) % 3,
        initial,
        first,
        max,
        step,
        jitter,
        bucket,
        idle_reset_secs: reduce(p(27, 0), 12, 90),
    }
}

impl std::fmt::Debug for Profile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Profile")
            .field("region_len", &self.region_len)
            .field("chunk", &self.chunk)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_golden() {
        // Captured from the live snell-server v6.0.0b2 via GDB.
        let p = Profile::derive(b"0123456789abcdef");
        assert_eq!(
            (p.rounds, p.m, p.region_len, p.h_lo, p.h_rng),
            (1, 237, 111, 43, 19)
        );
        assert_eq!(
            p.perm,
            [
                80, 54, 53, 81, 86, 110, 44, 15, 105, 65, 109, 40, 24, 75, 16, 97
            ]
        );
        assert_eq!(hex::encode(p.mask), "9bcc46aaf7b9c9df525089892199d1d0");
        for (k, want) in [44, 45, 47, 49].into_iter().enumerate() {
            assert_eq!(p.header_aad_len(k as u32), want);
        }
        let p2 = Profile::derive(b"snell-v6-test-key-2");
        assert_eq!((p2.rounds, p2.m), (4, 247));
    }

    #[test]
    fn write_target_mode_a() {
        let p = Profile::derive(b"interop-psk-base-01");
        assert_eq!(p.shape.write_mode, 0);
        for (k, acc, want) in [
            (0, 856, 1147),
            (0, 878, 1563),
            (0, 848, 1554),
            (0, 777, 1159),
            (0, 972, 1128),
            (0, 1415, 1943),
            (0, 1727, 1727),
            (1, 998, 1288),
        ] {
            assert_eq!(p.write_target(k, acc), want, "k={k} acc={acc}");
        }
    }

    #[test]
    fn write_target_mode_b() {
        let p = Profile::derive(b"interop-psk-base-08");
        assert_eq!((p.shape.write_mode, p.shape.write_jitter), (2, 9));
        for (k, acc, want) in [
            (0, 1263, 1923),
            (0, 480, 1325),
            (0, 531, 1331),
            (0, 735, 1224),
            (0, 950, 1211),
            (1, 1005, 1545),
            (1, 470, 1481),
            (2, 865, 1465),
        ] {
            assert_eq!(p.write_target(k, acc), want, "k={k} acc={acc}");
        }
    }

    #[test]
    fn swap_mode2_phase() {
        let p = Profile::derive(b"interop-psk-base-06");
        assert_eq!(p.shape.swap_mode, 2);
        for (r, want) in [548644951u32, 1737043106, 1267027012]
            .into_iter()
            .enumerate()
        {
            assert_eq!(p.prf.get(3, r as u32, 0), want);
        }
    }

    #[test]
    fn zero_chunk_pad_len_official() {
        // Session-ending zero chunks on reuse connections, from snell-server v6.0.0.
        let cases: &[(&str, u32, u32)] = &[
            ("0523415a9b337210", 1, 532),
            ("0523415a9b337210", 3, 730),
            ("0523415a9b337210", 5, 730),
            ("0523415a9b337210", 7, 730),
            ("0523415a9b337210", 9, 730),
            ("0000005a00337710", 1, 183),
            ("0000005a00337710", 3, 406),
            ("0000005a00337710", 5, 1007),
            ("0000005a00337710", 7, 822),
            ("0000005a00337710", 9, 730),
            ("0315275a5d337410", 1, 606),
            ("0315275a5d337410", 3, 1335),
            ("0315275a5d337410", 5, 613),
            ("0315275a5d337410", 7, 730),
            ("0315275a5d337410", 9, 730),
            ("020e1a5a3e337510", 5, 730),
            ("020e1a5a3e337510", 7, 210),
            ("020e1a5a3e337510", 9, 463),
        ];
        for &(psk, k, want) in cases {
            let p = Profile::derive(psk.as_bytes());
            let got = p.pad_len(k, 0, p.header_aad_len(k) as u32, false);
            assert_eq!(got, want, "{psk} k={k}");
        }
    }

    #[test]
    fn salt_round_trip() {
        let p = Profile::derive(b"0123456789abcdef");
        let salt: [u8; 16] = std::array::from_fn(|i| (i * 7 + 3) as u8);
        let mut region = p.region.to_vec();
        p.scatter_salt(&mut region, &salt);
        assert_eq!(p.gather_salt(&region), salt);
        assert!(p.match_region_prefix(&region));
    }

    #[test]
    fn swap_is_involution() {
        for psk in [
            "interop-psk-base-01",
            "interop-psk-base-06",
            "interop-psk-base-08",
            "0523415a9b337210",
        ] {
            let p = Profile::derive(psk.as_bytes());
            let mut pad: Vec<u8> = (0..700u32).map(|i| i as u8).collect();
            let mut ct: Vec<u8> = (0..900u32).map(|i| (i * 3) as u8).collect();
            let (pad0, ct0) = (pad.clone(), ct.clone());
            p.swap(&mut pad, &mut ct, 3);
            p.swap(&mut pad, &mut ct, 3);
            assert_eq!((pad, ct), (pad0, ct0), "{psk}");
        }
    }
}
