// encoding.rs

pub enum DecodeError {
    Malformed,
    Unsupported,
    WeakKey,
}
