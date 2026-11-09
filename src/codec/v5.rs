//! The Snell v4/v5 frame format (a port of opensnell `v4.go`).
//!
//! ```text
//! [salt 16 (first frame only)]
//! per frame: [sealed header 23] [padding (first frame only)] [sealed payload]
//! ```
//!
//! The first frame carries 256–511 bytes of padding whose even-indexed bytes
//! are swapped with the payload ciphertext. One write is cut into frames of a
//! single size that ramps up between writes, as snell-server v5.0.1 and Surge
//! do.

use std::time::{Duration, Instant};

use rand::{Rng, RngExt};

use super::{
    Decoded, HEADER_LEN, MAX_PAYLOAD, SEALED_HEADER_LEN, parse_header, put_header, put_payload,
};
use crate::crypto::{Cipher, SALT_LEN, TAG_LEN, random_salt};
use crate::error::{Error, Result};
use crate::key::Key;

const FRAME_SIZE: usize = 1460;
const INITIAL_PADDING_MIN: u16 = 0x100;
const INITIAL_PADDING_SPAN: u16 = 0x100;
/// Ramp step between writes (`FRAME_SIZE - 39`).
const RAMP_STEP: usize = FRAME_SIZE - 39;
/// A write this long after the previous one restarts the ramp.
const RAMP_RESET: Duration = Duration::from_secs(30);

pub(crate) struct Encoder {
    cipher: Cipher,
    salt: Option<[u8; SALT_LEN]>,
    initial_padding: u16,
    payload_limit: usize,
    last_write: Option<Instant>,
}

impl Encoder {
    pub(crate) fn new(psk: &[u8]) -> Result<Self> {
        let salt = random_salt();
        let delta = rand::rng().random_range(0..INITIAL_PADDING_SPAN);
        Ok(Self {
            cipher: Cipher::new(psk, &salt)?,
            salt: Some(salt),
            initial_padding: INITIAL_PADDING_MIN + delta,
            payload_limit: 0,
            last_write: None,
        })
    }

    pub(crate) fn encode(&mut self, data: &[u8], out: &mut Vec<u8>) {
        if data.is_empty() {
            self.frame(&[], &[], 0, out);
            return;
        }
        let limit = self.next_payload_limit();
        for chunk in data.chunks(limit) {
            let pad = self.next_padding(chunk.len());
            self.frame(&[], chunk, pad, out);
        }
    }

    pub(crate) fn encode_packet(&mut self, head: &[u8], body: &[u8], out: &mut Vec<u8>) {
        let pad = self.next_padding(head.len() + body.len());
        self.frame(head, body, pad, out);
    }

    /// The frame size of this write: small enough on the first write for
    /// salt + padding + payload to fit one MTU, then growing by 1421 per write
    /// up to the frame cap, restarting after 30 s of silence.
    fn next_payload_limit(&mut self) -> usize {
        let now = Instant::now();
        let limit = match self.last_write {
            None => FRAME_SIZE - 55 - usize::from(self.initial_padding),
            Some(t) if now.duration_since(t) > RAMP_RESET => RAMP_STEP,
            Some(_) => self.payload_limit,
        };
        self.last_write = Some(now);
        self.payload_limit = if limit < MAX_PAYLOAD {
            (limit + RAMP_STEP).min(MAX_PAYLOAD)
        } else {
            MAX_PAYLOAD
        };
        if limit == 0 || limit > MAX_PAYLOAD {
            MAX_PAYLOAD
        } else {
            limit
        }
    }

    /// Only the first data frame (the one carrying the salt) is padded.
    fn next_padding(&self, payload_len: usize) -> usize {
        if self.salt.is_none() || payload_len == 0 {
            0
        } else {
            usize::from(self.initial_padding)
        }
    }

    fn frame(&mut self, head: &[u8], body: &[u8], pad: usize, out: &mut Vec<u8>) {
        let pay = head.len() + body.len();
        let sealed_pay = if pay > 0 { pay + TAG_LEN } else { 0 };
        let salt_len = if self.salt.is_some() { SALT_LEN } else { 0 };
        let start = out.len();
        out.resize(start + salt_len + SEALED_HEADER_LEN + pad + sealed_pay, 0);
        let mut f = &mut out[start..];

        if let Some(salt) = self.salt.take() {
            f[..SALT_LEN].copy_from_slice(&salt);
            f = &mut f[SALT_LEN..];
        }
        let (hdr, rest) = f.split_at_mut(SEALED_HEADER_LEN);
        put_header(hdr, pad, pay);
        let (h, tag) = hdr.split_at_mut(HEADER_LEN);
        self.cipher.seal(&[], h, tag);

        if pay == 0 {
            return;
        }
        let (padding, sealed) = rest.split_at_mut(pad);
        let (pt, tag) = sealed.split_at_mut(pay);
        put_payload(pt, head, body);
        self.cipher.seal(&[], pt, tag);
        if pad > 0 {
            fill_padding(padding, sealed);
            swap_even(padding, sealed);
        }
    }
}

/// Exchanges the even-indexed bytes of `padding` and `ct` over their common
/// length. The receiver applies the same swap to undo it.
fn swap_even(padding: &mut [u8], ct: &mut [u8]) {
    let lim = padding.len().min(ct.len());
    for i in (0..lim).step_by(2) {
        std::mem::swap(&mut padding[i], &mut ct[i]);
    }
}

/// Picks padding bytes so the bit ratio of padding plus ciphertext stays in a
/// "natural" band, defeating the flat-entropy fingerprint of AEAD output.
fn fill_padding(padding: &mut [u8], ct: &[u8]) {
    let mut rng = rand::rng();
    let ones: usize = ct[..ct.len() & !3]
        .iter()
        .map(|b| b.count_ones() as usize)
        .sum();
    let zeros = (8 * ct.len()).saturating_sub(ones);
    if zeros == 0 {
        rng.fill_bytes(padding);
        return;
    }
    let ratio = ones as f64 / zeros as f64;
    if ratio <= 0.5 || ratio >= 1.6 {
        rng.fill_bytes(padding);
        return;
    }
    let base = if zeros < ones { 0.4 } else { 1.6 };
    let target = base + rng.random::<f64>() / 10.0;
    let total_bits = (8 * (padding.len() + ct.len())) as f64;
    let target_ones = (total_bits * (target / (target + 1.0)) - ones as f64) as i64;
    if target_ones < 0 || target_ones > 8 * padding.len() as i64 {
        rng.fill_bytes(padding);
        return;
    }
    // A uniformly random bitset with exactly `target_ones` bits set.
    let bits = 8 * padding.len();
    let mut set: Vec<bool> = (0..bits).map(|i| (i as i64) < target_ones).collect();
    for i in (1..bits).rev() {
        set.swap(i, rng.random_range(0..=i));
    }
    padding.fill(0);
    for (i, _) in set.iter().enumerate().filter(|(_, b)| **b) {
        padding[i / 8] |= 1 << (i % 8);
    }
}

pub(crate) struct Decoder {
    key: Key,
    cipher: Option<Cipher>,
    header: Option<(usize, usize)>,
}

impl Decoder {
    pub(crate) fn new(key: Key) -> Self {
        Self {
            key,
            cipher: None,
            header: None,
        }
    }

    pub(crate) fn decode(&mut self, buf: &mut [u8]) -> Result<Decoded> {
        let Some(cipher) = self.cipher.as_mut() else {
            if buf.len() < SALT_LEN {
                return Ok(Decoded::NeedMore(SALT_LEN));
            }
            let salt: [u8; SALT_LEN] = buf[..SALT_LEN].try_into().expect("salt length");
            self.cipher = Some(Cipher::new(self.key.psk(), &salt)?);
            return Ok(Decoded::Advance(SALT_LEN));
        };
        match self.header {
            None => {
                if buf.len() < SEALED_HEADER_LEN {
                    return Ok(Decoded::NeedMore(SEALED_HEADER_LEN));
                }
                let n = cipher.open(&[], &mut buf[..SEALED_HEADER_LEN])?;
                let (pad, pay) = parse_header(&buf[..n])?;
                if pay == 0 {
                    if pad != 0 {
                        return Err(Error::Frame("zero chunk with padding"));
                    }
                    return Ok(Decoded::ZeroChunk(SEALED_HEADER_LEN));
                }
                if pay > MAX_PAYLOAD || pad > MAX_PAYLOAD {
                    return Err(Error::Frame("frame too large"));
                }
                self.header = Some((pad, pay));
                Ok(Decoded::Advance(SEALED_HEADER_LEN))
            }
            Some((pad, pay)) => {
                let need = pad + pay + TAG_LEN;
                if buf.len() < need {
                    return Ok(Decoded::NeedMore(need));
                }
                let (padding, sealed) = buf[..need].split_at_mut(pad);
                if pad > 0 {
                    swap_even(padding, sealed);
                }
                cipher.open(&[], sealed)?;
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

    fn frames(key: &Key, wire: &mut [u8]) -> Vec<Vec<u8>> {
        let mut d = Decoder::new(key.clone());
        let mut out = Vec::new();
        let mut off = 0;
        loop {
            match d.decode(&mut wire[off..]).unwrap() {
                Decoded::NeedMore(_) => return out,
                Decoded::Advance(n) => off += n,
                Decoded::Frame {
                    consumed,
                    start,
                    end,
                } => {
                    out.push(wire[off + start..off + end].to_vec());
                    off += consumed;
                }
                Decoded::ZeroChunk(n) => {
                    out.push(Vec::new());
                    off += n;
                }
            }
        }
    }

    /// snell-server v5.0.1 and Surge cut every frame of one write to the same
    /// size and step that size by 1421 between writes.
    #[test]
    fn frame_size_per_write() {
        let key = Key::v5("psk").unwrap();
        let mut e = Encoder::new(key.psk()).unwrap();
        let first = FRAME_SIZE - 55 - usize::from(e.initial_padding);
        let mut wire = Vec::new();
        for n in [17, 20000, 70000] {
            e.encode(&vec![0x5a; n], &mut wire);
        }
        e.encode(&[], &mut wire);
        let sizes: Vec<usize> = frames(&key, &mut wire).iter().map(Vec::len).collect();

        let mut want = vec![17];
        for (n, limit) in [(20000, first + RAMP_STEP), (70000, first + 2 * RAMP_STEP)] {
            let mut left = n;
            while left > 0 {
                want.push(left.min(limit));
                left -= left.min(limit);
            }
        }
        want.push(0);
        assert_eq!(sizes, want);
    }

    #[test]
    fn packet_round_trip_and_padding() {
        let key = Key::v5("psk").unwrap();
        let mut e = Encoder::new(key.psk()).unwrap();
        let mut wire = Vec::new();
        e.encode_packet(b"head", &[7u8; 900], &mut wire);
        // salt + sealed header + 256..512 padding + sealed payload
        let pad = wire.len() - SALT_LEN - SEALED_HEADER_LEN - (904 + TAG_LEN);
        assert!((256..512).contains(&pad), "padding {pad}");
        let got = frames(&key, &mut wire);
        assert_eq!(got.len(), 1);
        assert_eq!(&got[0][..4], b"head");
        assert!(got[0][4..].iter().all(|&b| b == 7));
    }
}
