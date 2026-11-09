//! Snell v6 `mode = unshaped`: the v6 AES core with every obfuscation layer
//! removed (a port of opensnell `v6_unshaped.go`).
//!
//! ```text
//! [salt 16 (first frame only)]
//! per frame: [sealed header 23 (padLen = 0)] [sealed payload]
//! ```

use super::{
    Decoded, HEADER_LEN, MAX_UNPADDED_PAYLOAD, SEALED_HEADER_LEN, parse_header, put_header,
    put_payload,
};
use crate::crypto::{Cipher, SALT_LEN, TAG_LEN, random_salt};
use crate::error::{Error, Result};
use crate::key::Key;

pub(crate) struct Encoder {
    cipher: Cipher,
    salt: Option<[u8; SALT_LEN]>,
}

impl Encoder {
    pub(crate) fn new(psk: &[u8]) -> Result<Self> {
        let salt = random_salt();
        Ok(Self {
            cipher: Cipher::new(psk, &salt)?,
            salt: Some(salt),
        })
    }

    /// Each write becomes one frame; only writes over 65535 bytes are split.
    pub(crate) fn encode(&mut self, data: &[u8], out: &mut Vec<u8>) {
        if data.is_empty() {
            self.encode_frame(&[], &[], out);
        }
        for chunk in data.chunks(MAX_UNPADDED_PAYLOAD) {
            self.encode_frame(&[], chunk, out);
        }
    }

    pub(crate) fn encode_frame(&mut self, head: &[u8], body: &[u8], out: &mut Vec<u8>) {
        let pay = head.len() + body.len();
        let sealed_pay = if pay > 0 { pay + TAG_LEN } else { 0 };
        let salt_len = if self.salt.is_some() { SALT_LEN } else { 0 };
        let start = out.len();
        out.resize(start + salt_len + SEALED_HEADER_LEN + sealed_pay, 0);
        let mut f = &mut out[start..];
        if let Some(salt) = self.salt.take() {
            f[..SALT_LEN].copy_from_slice(&salt);
            f = &mut f[SALT_LEN..];
        }
        let (hdr, sealed) = f.split_at_mut(SEALED_HEADER_LEN);
        put_header(hdr, 0, pay);
        let (h, tag) = hdr.split_at_mut(HEADER_LEN);
        self.cipher.seal(&[], h, tag);
        if pay > 0 {
            let (pt, tag) = sealed.split_at_mut(pay);
            put_payload(pt, head, body);
            self.cipher.seal(&[], pt, tag);
        }
    }
}

pub(crate) struct Decoder {
    key: Key,
    cipher: Option<Cipher>,
    payload: Option<usize>,
}

impl Decoder {
    pub(crate) fn new(key: Key) -> Self {
        Self {
            key,
            cipher: None,
            payload: None,
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
        match self.payload {
            None => {
                if buf.len() < SEALED_HEADER_LEN {
                    return Ok(Decoded::NeedMore(SEALED_HEADER_LEN));
                }
                let n = cipher.open(&[], &mut buf[..SEALED_HEADER_LEN])?;
                let (pad, pay) = parse_header(&buf[..n])?;
                if pad != 0 {
                    return Err(Error::Frame("unshaped frame carries padding"));
                }
                if pay == 0 {
                    return Ok(Decoded::ZeroChunk(SEALED_HEADER_LEN));
                }
                self.payload = Some(pay);
                Ok(Decoded::Advance(SEALED_HEADER_LEN))
            }
            Some(pay) => {
                let need = pay + TAG_LEN;
                if buf.len() < need {
                    return Ok(Decoded::NeedMore(need));
                }
                cipher.open(&[], &mut buf[..need])?;
                self.payload = None;
                Ok(Decoded::Frame {
                    consumed: need,
                    start: 0,
                    end: pay,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::Mode;

    /// unshaped frames use the full 16-bit payLen range, like the official
    /// v6.0.0 server: a 70000-byte write becomes 65535 + 4465.
    #[test]
    fn unpadded_frame_cap() {
        for mode in [Mode::Unshaped, Mode::UnsafeRaw] {
            let key = Key::v6("0523415a9b337210", mode).unwrap();
            let mut enc = super::super::Encoder::new(&key).unwrap();
            let mut wire = Vec::new();
            enc.encode(&vec![1u8; 70000], &mut wire).unwrap();
            enc.encode(&[], &mut wire).unwrap();
            let mut dec = super::super::Decoder::new(&key);
            let (mut off, mut got) = (0, Vec::new());
            loop {
                match dec.decode(&mut wire[off..]).unwrap() {
                    Decoded::NeedMore(_) => break,
                    Decoded::Advance(n) => off += n,
                    Decoded::ZeroChunk(n) => {
                        got.push(0);
                        off += n;
                    }
                    Decoded::Frame {
                        consumed,
                        start,
                        end,
                    } => {
                        got.push(end - start);
                        off += consumed;
                    }
                }
            }
            assert_eq!(got, [65535, 4465, 0], "{mode}");
        }
    }
}
