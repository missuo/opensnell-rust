use std::fmt;
use std::str::FromStr;
use std::sync::Arc;

use crate::error::{Error, Result};
use crate::v6::Profile;

/// Snell protocol version.
///
/// v4 and v5 share one wire format (v5 only adds the server-side QUIC proxy),
/// so they are interchangeable on TCP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Version {
    /// Snell v4.
    V4,
    /// Snell v5 (the default).
    #[default]
    V5,
    /// Snell v6.0.0. Every v6 beta from b2 on is wire-identical to it.
    V6,
}

impl Version {
    /// Whether this is the v6 wire.
    pub fn is_v6(self) -> bool {
        self == Version::V6
    }
}

impl FromStr for Version {
    type Err = Error;

    /// Accepts `v4`/`4`, `v5`/`5` (also the empty string) and `v6`/`6` plus the
    /// v6 release spellings (`v6.0.0`, `v6b3`, `v6rc2`, ...).
    fn from_str(s: &str) -> Result<Self> {
        let v = s.trim().to_ascii_lowercase();
        let v = v.strip_prefix('v').unwrap_or(&v);
        match v {
            "" | "5" => Ok(Version::V5),
            "4" => Ok(Version::V4),
            _ if v == "6"
                || v.starts_with("6.0.0")
                || v.starts_with("6b")
                || v.starts_with("6rc") =>
            {
                Ok(Version::V6)
            }
            _ => Err(Error::Config("unknown snell version (use v4, v5 or v6)")),
        }
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Version::V4 => "v4",
            Version::V5 => "v5",
            Version::V6 => "v6",
        })
    }
}

/// Snell v6 encryption mode. It must match on client and server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Mode {
    /// Obfuscation and AES: the PSK-shaped v6 wire.
    #[default]
    Default,
    /// AES only, no obfuscation.
    Unshaped,
    /// No encryption and no obfuscation. Only for already secured networks.
    UnsafeRaw,
}

impl FromStr for Mode {
    type Err = Error;

    /// Accepts `default` (also the empty string), `unshaped` and `unsafe-raw`
    /// (`unsafe_raw`, `raw`).
    fn from_str(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "" | "default" => Ok(Mode::Default),
            "unshaped" => Ok(Mode::Unshaped),
            "unsafe-raw" | "unsafe_raw" | "raw" => Ok(Mode::UnsafeRaw),
            _ => Err(Error::Config(
                "unknown mode (use default, unshaped or unsafe-raw)",
            )),
        }
    }
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Mode::Default => "default",
            Mode::Unshaped => "unshaped",
            Mode::UnsafeRaw => "unsafe-raw",
        })
    }
}

/// The frame format a key speaks.
pub(crate) enum Wire {
    V5,
    V6(Box<Profile>),
    V6Unshaped,
    V6Raw,
}

struct Inner {
    psk: Box<[u8]>,
    version: Version,
    wire: Wire,
}

/// A pre-shared key together with the wire it is used on.
///
/// Building a key derives everything that depends only on the PSK (for v6 the
/// whole protocol profile), so build it once and clone it: clones share the
/// derived state.
#[derive(Clone)]
pub struct Key(Arc<Inner>);

/// How many leading bytes of a default-mode v6 connection identify its key
/// (see [`Key::match_prefix`]).
pub const V6_PREFIX_LEN: usize = 32;

const V6_PSK_MIN: usize = 12;
const V6_PSK_MAX: usize = 255;

impl Key {
    /// Builds a key. `mode` must be [`Mode::Default`] unless `version` is v6.
    ///
    /// A v6 PSK must be 12–255 bytes long, the range the official v6 server
    /// accepts.
    pub fn new(psk: impl AsRef<[u8]>, version: Version, mode: Mode) -> Result<Self> {
        let psk = psk.as_ref();
        if psk.is_empty() {
            return Err(Error::Config("psk must not be empty"));
        }
        let wire = match (version, mode) {
            (Version::V4 | Version::V5, Mode::Default) => Wire::V5,
            (Version::V4 | Version::V5, _) => {
                return Err(Error::Config("mode is a v6-only option"));
            }
            (Version::V6, mode) => {
                if !(V6_PSK_MIN..=V6_PSK_MAX).contains(&psk.len()) {
                    return Err(Error::Config("v6 psk must be 12-255 bytes"));
                }
                match mode {
                    Mode::Default => Wire::V6(Box::new(Profile::derive(psk))),
                    Mode::Unshaped => Wire::V6Unshaped,
                    Mode::UnsafeRaw => Wire::V6Raw,
                }
            }
        };
        Ok(Key(Arc::new(Inner {
            psk: psk.into(),
            version,
            wire,
        })))
    }

    /// Shorthand for a v5 key.
    pub fn v5(psk: impl AsRef<[u8]>) -> Result<Self> {
        Self::new(psk, Version::V5, Mode::Default)
    }

    /// Shorthand for a v6 key in the given mode.
    pub fn v6(psk: impl AsRef<[u8]>, mode: Mode) -> Result<Self> {
        Self::new(psk, Version::V6, mode)
    }

    /// The pre-shared key.
    pub fn psk(&self) -> &[u8] {
        &self.0.psk
    }

    /// The protocol version.
    pub fn version(&self) -> Version {
        self.0.version
    }

    /// The v6 mode ([`Mode::Default`] for v4/v5).
    pub fn mode(&self) -> Mode {
        match self.0.wire {
            Wire::V5 | Wire::V6(_) => Mode::Default,
            Wire::V6Unshaped => Mode::Unshaped,
            Wire::V6Raw => Mode::UnsafeRaw,
        }
    }

    pub(crate) fn wire(&self) -> &Wire {
        &self.0.wire
    }

    /// The v6 profile. Callers only use it after matching [`Wire::V6`].
    pub(crate) fn profile(&self) -> Option<&Profile> {
        match &self.0.wire {
            Wire::V6(p) => Some(p),
            _ => None,
        }
    }

    /// Whether the first [`V6_PREFIX_LEN`] bytes of a connection carry this
    /// key's motif. Only default-mode v6 keys can match; for any other key
    /// this is `false`.
    ///
    /// On the v6 wire the non-salt bytes of the salt region depend only on the
    /// PSK, so a server holding many keys can pick the right one before doing
    /// any key derivation. A random prefix matches with probability at most
    /// 2^-128.
    pub fn match_prefix(&self, prefix: &[u8]) -> bool {
        match self.profile() {
            Some(p) if prefix.len() >= V6_PREFIX_LEN => {
                p.match_region_prefix(&prefix[..V6_PREFIX_LEN])
            }
            _ => false,
        }
    }

    /// The expected first [`V6_PREFIX_LEN`] bytes and the mask of positions
    /// that are fixed for this key (`0xff`) versus salt (`0x00`):
    /// `(b & mask) == want` holds for every connection made with this key.
    /// Use it to build an index over many keys. `None` unless default-mode v6.
    pub fn prefix_template(&self) -> Option<([u8; V6_PREFIX_LEN], [u8; V6_PREFIX_LEN])> {
        let p = self.profile()?;
        let mut want = [0; V6_PREFIX_LEN];
        let mut mask = [0; V6_PREFIX_LEN];
        want.copy_from_slice(&p.region[..V6_PREFIX_LEN]);
        mask.copy_from_slice(&p.region_mask[..V6_PREFIX_LEN]);
        Some((want, mask))
    }

    /// Length of the salt region a default-mode v6 connection starts with
    /// (32–144 bytes).
    pub fn region_len(&self) -> Option<usize> {
        self.profile().map(|p| p.region_len)
    }

    /// Whether a full salt region carries this key's motif at every non-salt
    /// position.
    pub fn match_region(&self, region: &[u8]) -> bool {
        match self.profile() {
            Some(p) => region.len() == p.region_len && p.match_region_prefix(region),
            None => false,
        }
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Key")
            .field("version", &self.version())
            .field("mode", &self.mode())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse() {
        for (s, v) in [
            ("", Version::V5),
            ("v4", Version::V4),
            ("5", Version::V5),
            ("v6", Version::V6),
            ("v6.0.0", Version::V6),
            ("v6b3", Version::V6),
            ("V6RC2", Version::V6),
        ] {
            assert_eq!(s.parse::<Version>().unwrap(), v, "{s}");
        }
        assert!("v7".parse::<Version>().is_err());
        assert_eq!("unsafe_raw".parse::<Mode>().unwrap(), Mode::UnsafeRaw);
        assert_eq!("".parse::<Mode>().unwrap(), Mode::Default);
        assert!("fast".parse::<Mode>().is_err());
    }

    #[test]
    fn validation() {
        assert!(Key::v6("short", Mode::Default).is_err());
        assert!(Key::new("psk", Version::V5, Mode::Unshaped).is_err());
        assert!(Key::v5("").is_err());
        assert!(Key::v5("any length works").is_ok());
    }

    #[test]
    fn prefix_matching() {
        let keys: Vec<Key> = (0..32)
            .map(|i| Key::v6(format!("user-{i:03}-psk-0123456789"), Mode::Default).unwrap())
            .collect();
        for (i, k) in keys.iter().enumerate() {
            let p = k.profile().unwrap();
            let mut region = p.region.to_vec();
            p.scatter_salt(&mut region, &crate::crypto::random_salt());
            assert!(k.match_region(&region));
            for (j, other) in keys.iter().enumerate() {
                assert_eq!(other.match_prefix(&region), i == j);
            }
        }
        let mut junk = [0u8; V6_PREFIX_LEN];
        for _ in 0..1000 {
            crate::crypto::random_bytes(&mut junk);
            assert!(keys.iter().all(|k| !k.match_prefix(&junk)));
        }
    }
}
