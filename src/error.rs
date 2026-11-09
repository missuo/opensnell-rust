use std::io;

/// Errors produced by this crate.
///
/// Stream I/O surfaces errors as [`io::Error`]; protocol errors are wrapped
/// inside it and can be recovered with [`Error::from_io`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Transport error.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// A frame failed AEAD authentication (wrong PSK, or corrupted data).
    #[error("snell: authentication failed")]
    Auth,
    /// The peer sent a malformed frame.
    #[error("snell: invalid frame: {0}")]
    Frame(&'static str),
    /// The client sent a malformed request header.
    #[error("snell: invalid request: {0}")]
    Request(&'static str),
    /// The server answered the request with an error.
    #[error("snell: server reported code {code}: {message}")]
    Server {
        /// Error code (see the `code` constants in [`crate::server`]).
        code: u8,
        /// Message sent by the server.
        message: String,
    },
    /// Invalid configuration or argument.
    #[error("snell: {0}")]
    Config(&'static str),
}

impl Error {
    /// Returns the Snell error wrapped in an [`io::Error`] produced by this
    /// crate, if there is one.
    pub fn from_io(err: &io::Error) -> Option<&Error> {
        err.get_ref()?.downcast_ref::<Error>()
    }
}

impl From<Error> for io::Error {
    fn from(err: Error) -> Self {
        let kind = match &err {
            Error::Io(_) => {
                let Error::Io(e) = err else { unreachable!() };
                return e;
            }
            Error::Auth | Error::Frame(_) | Error::Request(_) => io::ErrorKind::InvalidData,
            Error::Server { .. } => io::ErrorKind::ConnectionRefused,
            Error::Config(_) => io::ErrorKind::InvalidInput,
        };
        io::Error::new(kind, err)
    }
}

pub(crate) type Result<T, E = Error> = std::result::Result<T, E>;
