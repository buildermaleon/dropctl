//! DropCtl - Secure peer-to-peer file transfer
//! 
//! A fast, secure CLI tool for transferring files between hosts using
//! X25519 key exchange and ChaCha20-Poly1305 encryption.

pub mod crypto;
pub mod protocol;
pub mod transfer;
pub mod config;

pub use crypto::{KeyPair, load_or_generate_keypair, KnownHost};
pub use crypto::session::{handshake_initiator, handshake_responder, SecureSession};
pub use protocol::{Message, Handshake};
