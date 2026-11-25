// encoding.rs

/// Why a byte string failed to decode.
///
/// `Unsupported` is the only soft error: the input may be valid under a newer
/// version, so keep it and stop verifying. Every other variant means reject.
#[derive(Debug)]
pub enum DecodeError {
    /// The bytes don't follow the encoding: truncated, trailing data, or an invalid point.
    Malformed,
    /// A tag, kind or version this client doesn't know. Possibly valid in a newer version.
    Unsupported,
    /// A small-order key, or one with a torsion component.
    BadKey,
}
