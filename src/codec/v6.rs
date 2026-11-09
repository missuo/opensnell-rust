//! The shaped Snell v6.0.0 frame format, `mode = default` (a port of opensnell
//! `v6.go`).
//!
//! ```text
//! [salt region R (first frame only): motif with the salt scattered in]
//! per frame k: [header-AAD H(k): motif] [sealed header 23, AAD = header-AAD]
//!              [padding: motif] [sealed payload, AAD = padding]
//! ```
//!
//! Padding and the payload ciphertext are interleaved by a profile-derived
//! swap. Lengths, filler bytes and per-frame payload sizes all come from the
//! PSK profile and match the official server byte for byte.

use std::time::{Duration, Instant};

use super::{Decoded, HEADER_LEN, SEALED_HEADER_LEN, parse_header, put_header, put_payload};
use crate::crypto::{Cipher, SALT_LEN, TAG_LEN, random_salt};
use crate::error::{Error, Result};
use crate::key::Key;
use crate::v6::Profile;

/// Smallest per-frame payload cap the chunk policy produces.
const MIN_CHUNK: i64 = 0x40;

pub(crate) struct Encoder {
    key: Key,
    cipher: Cipher,
    /// The salt region, sent with the first frame.
    region: Option<Box<[u8]>>,
    /// Frame index.
    k: u32,
    /// Chunk-policy ramp (per direction, like the official writer).
    ramp: u32,
    last_write: Option<Instant>,
}

impl Encoder {
    pub(crate) fn new(key: Key) -> Result<Self> {
        let salt = random_salt();
        let profile = key
            .profile()
            .ok_or(Error::Config("not a v6 default-mode key"))?;
        let mut region = profile.region.clone();
        profile.scatter_salt(&mut region, &salt);
        let cipher = Cipher::new(key.psk(), &salt)?;
        Ok(Self {
            key,
            cipher,
            region: Some(region),
            k: 0,
            ramp: 0,
            last_write: None,
        })
    }

    #[inline]
    fn profile(&self) -> &Profile {
        self.key.profile().expect("v6 encoder holds a v6 key")
    }

    /// Encodes one write, cut into frames by the official chunk policy.
    pub(crate) fn encode(&mut self, data: &[u8], out: &mut Vec<u8>) {
        self.touch();
        if data.is_empty() {
            // The zero chunk takes one ramp step like a one-frame write.
            self.advance();
            self.encode_frame(&[], &[], out);
            return;
        }
        let mut rest = data;
        let mut frames = 0;
        while !rest.is_empty() {
            let mut cap = self.next_cap();
            if self.k == 0 {
                cap = cap.min(self.profile().chunk.first as usize);
            }
            let (now, later) = rest.split_at(cap.min(rest.len()));
            self.encode_frame(&[], now, out);
            rest = later;
            frames += 1;
        }
        // A write split into two or more frames advances the ramp one extra
        // step once it is done.
        if frames >= 2 {
            self.advance();
        }
    }

    /// Restarts the ramp on first use and after `idle_reset` seconds without a
    /// write, then stamps the write time.
    fn touch(&mut self) {
        let now = Instant::now();
        let c = &self.key.profile().expect("v6 key").chunk;
        match self.last_write {
            None => self.ramp = c.initial,
            Some(t) if t + Duration::from_secs(c.idle_reset_secs.into()) < now => {
                self.ramp = c.initial
            }
            Some(_) => {}
        }
        self.last_write = Some(now);
    }

    fn advance(&mut self) {
        let c = &self.key.profile().expect("v6 key").chunk;
        self.ramp = (self.ramp + c.step).min(c.max);
    }

    /// The payload cap of the next frame, then one ramp step.
    fn next_cap(&mut self) -> usize {
        let p = self.key.profile().expect("v6 key");
        let c = &p.chunk;
        if self.ramp == 0 {
            self.ramp = c.initial;
        }
        let cur = self.ramp;
        let cap = match c.mode {
            1 => i64::from(c.bucket[(p.chunk_prf(38, self.k, cur) % 8) as usize]),
            2 => {
                let js = c.jitter;
                let d = i64::from(p.chunk_prf(39, self.k, cur) % (2 * js + 1)) - i64::from(js);
                (i64::from(cur) + d).max(MIN_CHUNK)
            }
            _ => i64::from(cur),
        };
        let cap = cap.clamp(MIN_CHUNK, i64::from(c.max)) as usize;
        self.advance();
        cap
    }

    /// Emits one frame carrying `head ++ body` (empty: a zero chunk).
    pub(crate) fn encode_frame(&mut self, head: &[u8], body: &[u8], out: &mut Vec<u8>) {
        let p = self.key.profile().expect("v6 key");
        let k = self.k;
        let pay = head.len() + body.len();
        let first = self.region.is_some();
        let hlen = p.header_aad_len(k);
        let pad = p.pad_len(k, pay as u32, hlen as u32, first) as usize;
        let region_len = if first { p.region_len } else { 0 };
        let sealed_pay = if pay > 0 { pay + TAG_LEN } else { 0 };

        let start = out.len();
        out.resize(
            start + region_len + hlen + SEALED_HEADER_LEN + pad + sealed_pay,
            0,
        );
        let mut f = &mut out[start..];

        if let Some(region) = self.region.take() {
            f[..region_len].copy_from_slice(&region);
            f = &mut f[region_len..];
        }

        // Header-AAD filler, then the header sealed with it as AAD.
        let (aad, rest) = f.split_at_mut(hlen);
        p.motif.fill(k, aad);
        let (hdr, rest) = rest.split_at_mut(SEALED_HEADER_LEN);
        put_header(hdr, pad, pay);
        let (h, tag) = hdr.split_at_mut(HEADER_LEN);
        self.cipher.seal(aad, h, tag);

        // Padding filler, then the payload sealed with the padding as AAD and
        // interleaved with it.
        let (padding, sealed) = rest.split_at_mut(pad);
        p.motif.fill(k, padding);
        if pay > 0 {
            let (pt, tag) = sealed.split_at_mut(pay);
            put_payload(pt, head, body);
            self.cipher.seal(padding, pt, tag);
            p.swap(padding, sealed, k);
        }
        self.k = self.k.wrapping_add(1);
    }
}

pub(crate) struct Decoder {
    key: Key,
    cipher: Option<Cipher>,
    /// Index of the next frame header.
    k: u32,
    header: Option<(usize, usize)>,
}

impl Decoder {
    pub(crate) fn new(key: Key) -> Self {
        Self {
            key,
            cipher: None,
            k: 0,
            header: None,
        }
    }

    pub(crate) fn with_region(key: Key, region: &[u8]) -> Result<Self> {
        let mut d = Self::new(key);
        d.cipher = Some(d.cipher_for(region)?);
        Ok(d)
    }

    fn cipher_for(&self, region: &[u8]) -> Result<Cipher> {
        let salt: [u8; SALT_LEN] = self.key.profile().expect("v6 key").gather_salt(region);
        Cipher::new(self.key.psk(), &salt)
    }

    pub(crate) fn decode(&mut self, buf: &mut [u8]) -> Result<Decoded> {
        let p = self.key.profile().expect("v6 key");
        let Some(cipher) = self.cipher.as_mut() else {
            if buf.len() < p.region_len {
                return Ok(Decoded::NeedMore(p.region_len));
            }
            self.cipher = Some(self.cipher_for(&buf[..p.region_len])?);
            return Ok(Decoded::Advance(p.region_len));
        };
        match self.header {
            None => {
                let hlen = p.header_aad_len(self.k);
                let need = hlen + SEALED_HEADER_LEN;
                if buf.len() < need {
                    return Ok(Decoded::NeedMore(need));
                }
                let (aad, sealed) = buf[..need].split_at_mut(hlen);
                let n = cipher.open(aad, sealed)?;
                let (pad, pay) = parse_header(&sealed[..n])?;
                self.k = self.k.wrapping_add(1);
                if pay == 0 && pad == 0 {
                    return Ok(Decoded::ZeroChunk(need));
                }
                self.header = Some((pad, pay));
                Ok(Decoded::Advance(need))
            }
            Some((pad, 0)) => {
                // The official server and Surge pad zero chunks: the padding
                // follows the header with no sealed payload.
                if buf.len() < pad {
                    return Ok(Decoded::NeedMore(pad));
                }
                self.header = None;
                Ok(Decoded::ZeroChunk(pad))
            }
            Some((pad, pay)) => {
                let need = pad + pay + TAG_LEN;
                if buf.len() < need {
                    return Ok(Decoded::NeedMore(need));
                }
                let (padding, sealed) = buf[..need].split_at_mut(pad);
                // The peer derives the same interleave from the PSK; undo it
                // and authenticate with the recovered padding.
                p.swap(padding, sealed, self.k.wrapping_sub(1));
                cipher.open(padding, sealed)?;
                self.header = None;
                Ok(Decoded::Frame {
                    consumed: need,
                    start: pad,
                    end: pad + pay,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::Mode;

    /// Per-frame payload lengths captured live from the official snell-server
    /// v6.0.0 (one upstream send per write; a 0 write is a zero chunk).
    #[test]
    fn chunk_policy_matches_official() {
        let cases: &[(&str, &str, &[usize], &[usize])] = &[
            (
                "mode0-single-frames",
                "a196c8ea65c3054f941ebbec",
                &[62, 1000, 1000, 20000, 1000, 20000],
                &[62, 1000, 1000, 5929, 7487, 6584, 1000, 12141, 7859],
            ),
            (
                "mode0-exact-boundary",
                "a196c8ea65c3054f941ebbec",
                &[62, 13113, 1000, 20000],
                &[62, 2813, 4371, 5929, 1000, 10603, 9397],
            ),
            (
                "mode0-reuse-zero-chunk",
                "a196c8ea65c3054f941ebbec",
                &[62, 12000, 0, 62, 12000, 0, 62, 12000],
                &[62, 2813, 4371, 4816, 62, 12000, 62, 12000],
            ),
            (
                "mode2-bursts",
                "a96bd65f60e01ce46b92adfa",
                &[
                    63, 20000, 20000, 20000, 20000, 20000, 20000, 20000, 20000, 20000, 20000,
                    20000, 20000,
                ],
                &[
                    63, 2405, 3517, 4561, 5631, 3886, 8826, 10062, 1112, 13100, 6900, 13100, 6900,
                    13100, 6900, 13024, 6976, 13100, 6900, 13057, 6943, 13065, 6935, 13100, 6900,
                    13100, 6900, 13031, 6969,
                ],
            ),
        ];
        for &(name, psk, writes, want) in cases {
            let key = Key::v6(psk, Mode::Default).unwrap();
            let mut enc = Encoder::new(key.clone()).unwrap();
            let mut wire = Vec::new();
            for &n in writes {
                enc.encode(&vec![b'x'; n], &mut wire);
            }
            let mut dec = Decoder::new(key);
            let mut got = Vec::new();
            let mut off = 0;
            loop {
                match dec.decode(&mut wire[off..]).unwrap() {
                    Decoded::NeedMore(_) => break,
                    Decoded::Advance(n) | Decoded::ZeroChunk(n) => off += n,
                    Decoded::Frame {
                        consumed,
                        start,
                        end,
                    } => {
                        assert!(wire[off + start..off + end].iter().all(|&b| b == b'x'));
                        got.push(end - start);
                        off += consumed;
                    }
                }
            }
            assert_eq!(off, wire.len(), "{name}: trailing bytes");
            assert_eq!(got, want, "{name}");
        }
    }

    /// The writer puts the official motif on the wire: the salt-region filler
    /// and frame 0's header-AAD depend only on the PSK, the salt does not.
    #[test]
    fn writer_emits_motif() {
        let key = Key::v6("0523415a9b337210", Mode::Default).unwrap();
        let p = key.profile().unwrap();
        let mut wires = [Vec::new(), Vec::new()];
        for w in &mut wires {
            Encoder::new(key.clone())
                .unwrap()
                .encode(b"CONNECT example.com:443", w);
        }
        let hlen = p.header_aad_len(0);
        let mut aad = vec![0; hlen];
        p.motif.fill(0, &mut aad);
        for w in &wires {
            assert!(key.match_region(&w[..p.region_len]));
            assert_eq!(&w[p.region_len..p.region_len + hlen], &aad[..]);
        }
        assert_ne!(p.gather_salt(&wires[0]), p.gather_salt(&wires[1]));
    }
}
