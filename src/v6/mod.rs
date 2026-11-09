//! Snell v6.0.0 PSK-derived protocol profile.

mod motif;
mod prf;
mod profile;

pub(crate) use profile::Profile;

#[cfg(test)]
mod tests;
