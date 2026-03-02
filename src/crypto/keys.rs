//! Key management for identity and key exchange

use {
    anyhow::{Context, Result},
    ed25519_dalek::{SigningKey, VerifyingKey, Signer, Signature},
    x25519_dalek::{PublicKey as X25519Public, StaticSecret},
    rand::rngs::OsRng,
    sha2::Sha256,
    base64::{Engine as _, engine::general_purpose::STANDARD as BASE64},
    std::path::Path,
};

/// Local keypair for identity and key exchange
pub struct KeyPair {
    /// Ed25519 signing key (identity)
    signing: SigningKey,
    /// X25519 static secret (for ECDH)
    x25519_secret: StaticSecret,
    /// Cached X25519 public key
    x25519_public: X25519Public,
    /// Cached Ed25519 public key
    pub verifying: VerifyingKey,
}

impl KeyPair {
    /// Generate a new random keypair
    pub fn generate() -> Self {
        let signing = SigningKey::generate(&mut OsRng);
        let verifying = signing.verifying_key();
        
        let x25519_secret = StaticSecret::random_from_rng(OsRng);
        let x25519_public = X25519Public::from(&x25519_secret);
        
        Self {
            signing,
            x25519_secret,
            x25519_public,
            verifying,
        }
    }
    
    /// Get the Ed25519 public key (identity)
    pub fn identity(&self) -> &VerifyingKey {
        &self.verifying
    }
    
    /// Get the X25519 public key (for ECDH)
    pub fn public_key(&self) -> &X25519Public {
        &self.x25519_public
    }
    
    /// Sign data with our identity key
    pub fn sign(&self, data: &[u8]) -> Signature {
        self.signing.sign(data)
    }
    
    /// Perform ECDH with peer's X25519 public key
    pub fn derive_shared_secret(&self, peer_public: &X25519Public) -> [u8; 32] {
        let shared = self.x25519_secret.diffie_hellman(peer_public);
        shared.to_bytes()
    }
    
    /// Serialize public keys to string format
    pub fn serialize_public(&self) -> String {
        format!(
            "{}:{}",
            BASE64.encode(self.verifying.as_bytes()),
            BASE64.encode(self.x25519_public.as_bytes())
        )
    }
    
    /// Deserialize public keys from string format
    pub fn deserialize_public(data: &str) -> Result<(VerifyingKey, X25519Public)> {
        let parts: Vec<&str> = data.split(':').collect();
        anyhow::ensure!(parts.len() == 2, "Invalid public key format");
        
        let verify_bytes = BASE64.decode(parts[0]).context("Invalid base64 in identity")?;
        let x25519_bytes = BASE64.decode(parts[1]).context("Invalid base64 in public key")?;
        
        anyhow::ensure!(verify_bytes.len() == 32, "Invalid identity key length");
        anyhow::ensure!(x25519_bytes.len() == 32, "Invalid X25519 key length");
        
        let verifying = VerifyingKey::from_bytes(
            verify_bytes.as_slice().try_into().unwrap()
        ).context("Invalid identity key")?;
        
        let x25519_public = x25519_dalek::PublicKey::from(
            <[u8; 32]>::try_from(x25519_bytes.as_slice()).unwrap()
        );
        
        Ok((verifying, x25519_public))
    }
}

/// Known host entry with verified public key
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KnownHost {
    pub name: String,
    pub identity: String,      // Ed25519 public key (base64)
    pub x25519_public: String, // X25519 public key (base64)
    pub first_seen: u64,
    pub last_seen: u64,
}

impl KnownHost {
    pub fn new(name: String, keypair: &KeyPair) -> Self {
        Self {
            name,
            identity: BASE64.encode(keypair.verifying.as_bytes()),
            x25519_public: BASE64.encode(keypair.public_key().as_bytes()),
            first_seen: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            last_seen: 0,
        }
    }
}

/// Load or generate keypair from disk
pub fn load_or_generate_keypair(path: &Path) -> Result<KeyPair> {
    if path.exists() {
        let data = std::fs::read_to_string(path).context("Failed to read key file")?;
        let lines: Vec<&str> = data.lines().collect();
        anyhow::ensure!(lines.len() >= 2, "Invalid key file format");
        
        let signing_bytes = BASE64.decode(lines[0]).context("Invalid base64 for signing")?;
        let x25519_bytes = BASE64.decode(lines[1]).context("Invalid base64 for X25519")?;
        
        let signing = SigningKey::from_bytes(
            signing_bytes.as_slice().try_into().unwrap()
        );
        let verifying = signing.verifying_key();
        let x25519_secret = x25519_dalek::StaticSecret::from(
            <[u8; 32]>::try_from(x25519_bytes.as_slice()).unwrap()
        );
        let x25519_public = x25519_dalek::PublicKey::from(&x25519_secret);
        
        Ok(KeyPair {
            signing,
            verifying,
            x25519_secret,
            x25519_public,
        })
    } else {
        // Generate new keypair
        let keypair = KeyPair::generate();
        
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        
        // Save to disk (only public parts actually - for now we save both for simplicity)
        let data = format!(
            "{}\n{}\n",
            BASE64.encode(keypair.signing.to_bytes().as_slice()),
            BASE64.encode(keypair.x25519_secret.to_bytes().as_slice())
        );
        std::fs::write(path, data)?;
        
        tracing::info!("Generated new keypair at {:?}", path);
        Ok(keypair)
    }
}

/// Derive encryption key from shared secret using HKDF
pub fn derive_session_key(master_secret: &[u8], info: &[u8]) -> [u8; 32] {
    let hk = hkdf::Hkdf::<Sha256>::new(Some(info), master_secret);
    let mut okm = [0u8; 32];
    hk.expand(&[], &mut okm).expect("HKDF expand failed");
    okm
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_keypair_generation() {
        let kp = KeyPair::generate();
        let serialized = kp.serialize_public();
        let (verify, x25519) = KeyPair::deserialize_public(&serialized).unwrap();
        
        assert_eq!(verify, *kp.identity());
        assert_eq!(x25519, *kp.public_key());
    }
    
    #[test]
    fn test_key_derivation() {
        let alice = KeyPair::generate();
        let bob = KeyPair::generate();
        
        let secret_alice = alice.derive_shared_secret(bob.public_key());
        let secret_bob = bob.derive_shared_secret(alice.public_key());
        
        assert_eq!(secret_alice, secret_bob);
    }
}
