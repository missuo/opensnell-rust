//! Snell cryptography: Argon2id key derivation and AES-128-GCM.
//!
//! Every Snell wire that encrypts (v4/v5, v6 default and v6 unshaped) derives a
//! fresh AES-128-GCM key per direction from the PSK and a 16-byte random salt:
//! `Argon2id(psk, salt, t=3, m=8 KiB, p=1) -> 32 bytes`, of which the first 16
//! are the key. The nonce is a little-endian frame counter starting at 0.

#[cfg(feature = "aws-lc")]
use aws_lc_rs::aead;
#[cfg(all(feature = "ring", not(feature = "aws-lc")))]
use ring::aead;

#[cfg(not(any(feature = "aws-lc", feature = "ring")))]
compile_error!("opensnell needs an AES-GCM backend: enable the `aws-lc` or `ring` feature");

use crate::error::Error;

/// Length of the per-direction random salt.
pub(crate) const SALT_LEN: usize = 16;
/// AES-GCM authentication tag length.
pub(crate) const TAG_LEN: usize = 16;

const KEY_LEN: usize = 16;
const ARGON2_OUT: usize = 32;
const ARGON2_M_KIB: u32 = 8;
const ARGON2_T: u32 = 3;

/// Derives the AES-128 key for `salt`: Argon2id(psk, salt, t=3, m=8, p=1)[..16].
fn derive_key(psk: &[u8], salt: &[u8; SALT_LEN]) -> Result<[u8; KEY_LEN], Error> {
    use argon2::{Algorithm, Argon2, Block, Params, Version};

    let params = Params::new(ARGON2_M_KIB, ARGON2_T, 1, Some(ARGON2_OUT))
        .map_err(|_| Error::Config("invalid argon2 parameters"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; ARGON2_OUT];
    // 8 KiB of working memory on the stack: no allocation per connection.
    let mut memory = [Block::default(); ARGON2_M_KIB as usize];
    argon
        .hash_password_into_with_memory(psk, salt, &mut out, &mut memory[..])
        .map_err(|_| Error::Config("psk is not usable as an argon2 password"))?;
    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&out[..KEY_LEN]);
    Ok(key)
}

/// Fills `buf` from the operating system CSPRNG.
pub(crate) fn random_bytes(buf: &mut [u8]) {
    // getrandom only fails when the OS has no entropy source at all, which a
    // network service cannot run without.
    getrandom::fill(buf).expect("operating system random source unavailable");
}

/// A random 16-byte salt.
pub(crate) fn random_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    random_bytes(&mut salt);
    salt
}

/// One direction of a Snell AEAD stream: the session key plus its nonce
/// counter. Each seal/open consumes one nonce.
pub(crate) struct Cipher {
    key: aead::LessSafeKey,
    counter: u64,
}

impl Cipher {
    /// Builds the cipher for `salt`, running the Argon2id KDF.
    pub(crate) fn new(psk: &[u8], salt: &[u8; SALT_LEN]) -> Result<Self, Error> {
        let raw = derive_key(psk, salt)?;
        let unbound = aead::UnboundKey::new(&aead::AES_128_GCM, &raw)
            .map_err(|_| Error::Config("invalid AES-128-GCM key"))?;
        Ok(Self {
            key: aead::LessSafeKey::new(unbound),
            counter: 0,
        })
    }

    #[inline]
    fn next_nonce(&mut self) -> aead::Nonce {
        let mut n = [0u8; 12];
        n[..8].copy_from_slice(&self.counter.to_le_bytes());
        self.counter = self.counter.wrapping_add(1);
        aead::Nonce::assume_unique_for_key(n)
    }

    /// Encrypts `in_out` in place and writes the tag into `tag`.
    #[inline]
    pub(crate) fn seal(&mut self, aad: &[u8], in_out: &mut [u8], tag: &mut [u8]) {
        let nonce = self.next_nonce();
        let t = self
            .key
            .seal_in_place_separate_tag(nonce, aead::Aad::from(aad), in_out)
            // Sealing only fails for inputs beyond GCM's 64 GiB limit; frames
            // are at most 64 KiB.
            .expect("AES-GCM seal of a bounded frame");
        tag.copy_from_slice(t.as_ref());
    }

    /// Decrypts `in_out` (ciphertext followed by the tag) in place and returns
    /// the plaintext length. Consumes a nonce even when authentication fails.
    #[inline]
    pub(crate) fn open(&mut self, aad: &[u8], in_out: &mut [u8]) -> Result<usize, Error> {
        let nonce = self.next_nonce();
        self.key
            .open_in_place(nonce, aead::Aad::from(aad), in_out)
            .map(|p| p.len())
            .map_err(|_| Error::Auth)
    }
}

impl std::fmt::Debug for Cipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cipher")
            .field("counter", &self.counter)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_round_trip() {
        let salt = [7u8; SALT_LEN];
        let mut tx = Cipher::new(b"psk", &salt).unwrap();
        let mut rx = Cipher::new(b"psk", &salt).unwrap();
        for msg in [&b""[..], b"hello", &[0xAB; 4000]] {
            let mut buf = msg.to_vec();
            buf.resize(msg.len() + TAG_LEN, 0);
            let (pt, tag) = buf.split_at_mut(msg.len());
            tx.seal(b"aad", pt, tag);
            assert_eq!(rx.open(b"aad", &mut buf).unwrap(), msg.len());
            assert_eq!(&buf[..msg.len()], msg);
        }
        assert_eq!(tx.counter, 3);
    }

    #[test]
    fn wrong_psk_fails() {
        let salt = [1u8; SALT_LEN];
        let mut tx = Cipher::new(b"right", &salt).unwrap();
        let mut rx = Cipher::new(b"wrong", &salt).unwrap();
        let mut buf = vec![0u8; 5 + TAG_LEN];
        let (pt, tag) = buf.split_at_mut(5);
        tx.seal(&[], pt, tag);
        assert!(rx.open(&[], &mut buf).is_err());
    }
}
