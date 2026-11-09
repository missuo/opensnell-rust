//! Sans-I/O frame codecs for every Snell wire.
//!
//! An [`Encoder`] turns plaintext into wire bytes appended to a `Vec`; a
//! [`Decoder`] decrypts frames in place inside the receive buffer. Each
//! direction has its own salt, key and nonce counter, so the two halves are
//! fully independent.

mod raw;
mod unshaped;
mod v5;
mod v6;

use crate::error::{Error, Result};
use crate::key::{Key, Wire};

/// Largest payload of one frame on the v4/v5 and shaped v6 wires, and of a
/// UDP datagram frame on every wire.
pub(crate) const MAX_PAYLOAD: usize = 0x3FFF;
/// Largest payload of one unshaped / unsafe-raw stream frame.
pub(crate) const MAX_UNPADDED_PAYLOAD: usize = 0xFFFF;

/// Plain frame header: `04 00 00 | padLen(BE16) | payLen(BE16)`.
pub(crate) const HEADER_LEN: usize = 7;
/// Sealed frame header (header + GCM tag).
pub(crate) const SEALED_HEADER_LEN: usize = HEADER_LEN + crate::crypto::TAG_LEN;

/// Writes a frame header.
#[inline]
pub(crate) fn put_header(dst: &mut [u8], pad: usize, pay: usize) {
    dst[0] = 4;
    dst[1] = 0;
    dst[2] = 0;
    dst[3..5].copy_from_slice(&(pad as u16).to_be_bytes());
    dst[5..7].copy_from_slice(&(pay as u16).to_be_bytes());
}

/// Parses a decrypted frame header into `(pad, pay)`.
#[inline]
pub(crate) fn parse_header(h: &[u8]) -> Result<(usize, usize)> {
    if h.len() != HEADER_LEN || h[0] != 4 {
        return Err(Error::Frame("bad frame header"));
    }
    Ok((
        usize::from(u16::from_be_bytes([h[3], h[4]])),
        usize::from(u16::from_be_bytes([h[5], h[6]])),
    ))
}

/// Copies `head ++ body` into `dst` (which is exactly that long).
#[inline]
pub(crate) fn put_payload(dst: &mut [u8], head: &[u8], body: &[u8]) {
    let (a, b) = dst.split_at_mut(head.len());
    a.copy_from_slice(head);
    b.copy_from_slice(body);
}

/// Progress of a [`Decoder`] over the receive buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Decoded {
    /// The buffer must hold at least this many bytes to make progress.
    NeedMore(usize),
    /// A prefix (salt region or frame header) was consumed; decode again.
    Advance(usize),
    /// A data frame: its plaintext is `buf[start..end]` and the frame occupies
    /// `buf[..consumed]`.
    Frame {
        consumed: usize,
        start: usize,
        end: usize,
    },
    /// A zero chunk (half-close) occupying `buf[..consumed]`.
    ZeroChunk(usize),
}

/// Encrypting half of a Snell stream.
pub(crate) enum Encoder {
    V5(v5::Encoder),
    V6(v6::Encoder),
    Unshaped(unshaped::Encoder),
    Raw(raw::Encoder),
}

impl Encoder {
    pub(crate) fn new(key: &Key) -> Result<Self> {
        Ok(match key.wire() {
            Wire::V5 => Encoder::V5(v5::Encoder::new(key.psk())?),
            Wire::V6(_) => Encoder::V6(v6::Encoder::new(key.clone())?),
            Wire::V6Unshaped => Encoder::Unshaped(unshaped::Encoder::new(key.psk())?),
            Wire::V6Raw => Encoder::Raw(raw::Encoder),
        })
    }

    /// Encodes one write. The wire's chunk policy decides how `data` is cut
    /// into frames; an empty `data` encodes a zero chunk (half-close).
    pub(crate) fn encode(&mut self, data: &[u8], out: &mut Vec<u8>) -> Result<()> {
        match self {
            Encoder::V5(e) => e.encode(data, out),
            Encoder::V6(e) => e.encode(data, out),
            Encoder::Unshaped(e) => e.encode(data, out),
            Encoder::Raw(e) => e.encode(data, out),
        }
        Ok(())
    }

    /// Encodes `head ++ body` as exactly one frame (a UDP datagram).
    pub(crate) fn encode_packet(
        &mut self,
        head: &[u8],
        body: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<()> {
        if head.len() + body.len() > MAX_PAYLOAD {
            return Err(Error::Frame("packet too large"));
        }
        match self {
            Encoder::V5(e) => e.encode_packet(head, body, out),
            Encoder::V6(e) => e.encode_frame(head, body, out),
            Encoder::Unshaped(e) => e.encode_frame(head, body, out),
            Encoder::Raw(e) => e.encode_frame(head, body, out),
        }
        Ok(())
    }
}

/// Decrypting half of a Snell stream.
pub(crate) enum Decoder {
    V5(v5::Decoder),
    V6(v6::Decoder),
    Unshaped(unshaped::Decoder),
    Raw(raw::Decoder),
}

impl Decoder {
    pub(crate) fn new(key: &Key) -> Self {
        match key.wire() {
            Wire::V5 => Decoder::V5(v5::Decoder::new(key.clone())),
            Wire::V6(_) => Decoder::V6(v6::Decoder::new(key.clone())),
            Wire::V6Unshaped => Decoder::Unshaped(unshaped::Decoder::new(key.clone())),
            Wire::V6Raw => Decoder::Raw(raw::Decoder::default()),
        }
    }

    /// A default-mode v6 decoder whose salt region was already read (the
    /// server reads it to identify the key).
    pub(crate) fn v6_with_region(key: &Key, region: &[u8]) -> Result<Self> {
        Ok(Decoder::V6(v6::Decoder::with_region(key.clone(), region)?))
    }

    /// Decodes from the front of `buf`, decrypting in place.
    pub(crate) fn decode(&mut self, buf: &mut [u8]) -> Result<Decoded> {
        match self {
            Decoder::V5(d) => d.decode(buf),
            Decoder::V6(d) => d.decode(buf),
            Decoder::Unshaped(d) => d.decode(buf),
            Decoder::Raw(d) => d.decode(buf),
        }
    }
}
