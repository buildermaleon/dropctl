//! Crypto primitives for secure peer-to-peer communication
//! 
//! Security model:
//! - X25519 for key exchange (Curve25519 ECDH)
//! - Ed25519 for identity signing
//! - ChaCha20-Poly1305 for AEAD encryption
//! - HKDF for key derivation

pub mod keys;
pub mod session;

pub use keys::*;
pub use session::*;
