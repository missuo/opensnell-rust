//! Snell v6 `mode = unsafe-raw`: no encryption, no obfuscation, but the v6
//! frame structure in cleartext (a port of opensnell `v6_raw.go`).
//!
//! ```text
//! per frame: [04 00 00 | padLen = 0 | payLen] [payload]
//! ```

use super::{Decoded, HEADER_LEN, MAX_UNPADDED_PAYLOAD, put_header, put_payload};
use crate::error::{Error, Result};

pub(crate) struct Encoder;

impl Encoder {
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
        let start = out.len();
        out.resize(start + HEADER_LEN + pay, 0);
        let (hdr, payload) = out[start..].split_at_mut(HEADER_LEN);
        put_header(hdr, 0, pay);
        put_payload(payload, head, body);
    }
}

#[derive(Default)]
pub(crate) struct Decoder {
    header: Option<(usize, usize)>,
}

impl Decoder {
    pub(crate) fn decode(&mut self, buf: &mut [u8]) -> Result<Decoded> {
        match self.header {
            None => {
                if buf.len() < HEADER_LEN {
                    return Ok(Decoded::NeedMore(HEADER_LEN));
                }
                if buf[0] != 4 {
                    return Err(Error::Frame("bad frame header"));
                }
                let pad = usize::from(u16::from_be_bytes([buf[3], buf[4]]));
                let pay = usize::from(u16::from_be_bytes([buf[5], buf[6]]));
                if pay == 0 {
                    if pad != 0 {
                        return Err(Error::Frame("zero chunk with padding"));
                    }
                    return Ok(Decoded::ZeroChunk(HEADER_LEN));
                }
                self.header = Some((pad, pay));
                Ok(Decoded::Advance(HEADER_LEN))
            }
            Some((pad, pay)) => {
                let need = pad + pay;
                if buf.len() < need {
                    return Ok(Decoded::NeedMore(need));
                }
                self.header = None;
                Ok(Decoded::Frame {
                    consumed: need,
                    start: pad,
                    end: need,
                })
            }
        }
    }
}
