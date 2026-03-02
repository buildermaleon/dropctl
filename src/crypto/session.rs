//! Secure session management with ChaCha20-Poly1305 AEAD

use {
    anyhow::{Context, Result},
    chacha20poly1305::{
        aead::{Aead, KeyInit, OsRng},
        ChaCha20Poly1305, Nonce,
    },
    std::sync::Arc,
    tokio::sync::Mutex,
    base64::Engine as _,
    base64::engine::general_purpose::STANDARD as BASE64,
    rand::RngCore,
};

use super::{derive_session_key, KeyPair};

/// Session state after handshake
pub struct Session {
    /// Derived encryption key for sending
    send_key: [u8; 32],
    /// Derived encryption key for receiving  
    recv_key: [u8; 32],
    /// Sequence numbers for nonce derivation
    send_nonce: u64,
    recv_nonce: u64,
    /// Peer identity for verification
    peer_identity: Option<ed25519_dalek::VerifyingKey>,
    /// Our identity
    our_identity: ed25519_dalek::VerifyingKey,
}

impl Session {
    /// Create session from handshake result
    pub fn new(
        shared_secret: [u8; 32],
        our_identity: ed25519_dalek::VerifyingKey,
        peer_identity: ed25519_dalek::VerifyingKey,
        is_initiator: bool,
    ) -> Self {
        // Derive separate keys for each direction using HKDF
        let send_info = if is_initiator { b"dropctl-send" } else { b"dropctl-recv" };
        let recv_info = if is_initiator { b"dropctl-recv" } else { b"dropctl-send" };
        
        let send_key = derive_session_key(&shared_secret, send_info);
        let recv_key = derive_session_key(&shared_secret, recv_info);
        
        Self {
            send_key,
            recv_key,
            send_nonce: 0,
            recv_nonce: 0,
            peer_identity: Some(peer_identity),
            our_identity,
        }
    }
    
    /// Encrypt data with ChaCha20-Poly1305
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new_from_slice(&self.send_key)
            .context("Invalid send key")?;
        
        // Build nonce from sequence number (12 bytes)
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..].copy_from_slice(&self.send_nonce.to_le_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        tracing::debug!("Encrypting {} bytes with nonce index {}", plaintext.len(), self.send_nonce);
        
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| anyhow::anyhow!("Encryption failed: {:?}", e))?;
        
        self.send_nonce += 1;
        
        // Prepend nonce to ciphertext
        let mut result = nonce_bytes.to_vec();
        result.extend(ciphertext);
        Ok(result)
    }
    
    /// Decrypt data with ChaCha20-Poly1305
    pub fn decrypt(&mut self, mut data: &[u8]) -> Result<Vec<u8>> {
        anyhow::ensure!(data.len() >= 12, "Ciphertext too short");
        
        let nonce_bytes: [u8; 12] = data[..12].try_into().unwrap();
        data = &data[12..];
        
        tracing::debug!("Decrypting {} bytes with nonce index {}", data.len(), self.recv_nonce);
        
        let cipher = ChaCha20Poly1305::new_from_slice(&self.recv_key)
            .context("Invalid recv key")?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let plaintext = cipher
            .decrypt(nonce, data)
            .map_err(|e| anyhow::anyhow!("Decryption failed: {:?}", e))?;
        
        self.recv_nonce += 1;
        
        Ok(plaintext)
    }
    
    /// Get peer identity
    pub fn peer_identity(&self) -> Option<&ed25519_dalek::VerifyingKey> {
        self.peer_identity.as_ref()
    }
}

/// Thread-safe session wrapper
pub type SecureSession = Arc<Mutex<Session>>;

/// Create a new secure session
pub fn create_session(
    shared_secret: [u8; 32],
    our_identity: ed25519_dalek::VerifyingKey,
    peer_identity: ed25519_dalek::VerifyingKey,
    is_initiator: bool,
) -> SecureSession {
    Arc::new(Mutex::new(Session::new(
        shared_secret,
        our_identity,
        peer_identity,
        is_initiator,
    )))
}

// ============================================================================
// Handshake Protocol
// ============================================================================

/// Handshake message types
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum HandshakeMessage {
    /// Initiator sends this first
    Hello {
        /// Our identity public key (Ed25519)
        identity: String,
        /// Our X25519 public key for ECDH
        public_key: String,
        /// Random nonce for freshness
        nonce: [u8; 32],
    },
    /// Responder acknowledges and sends their keys
    Ack {
        /// Our identity public key
        identity: String,
        /// Our X25519 public key
        public_key: String,
        /// Nonce from initiator (echoed)
        echo_nonce: [u8; 32],
        /// Our random nonce
        nonce: [u8; 32],
    },
    /// Initiator confirms (handshake complete)
    Confirm {
        /// Signature of the handshake transcript
        signature: String,
    },
    /// Responder final confirmation
    ConfirmAck {
        signature: String,
    },
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Perform handshake as initiator (client)
pub async fn handshake_initiator<IO>(
    io: &mut IO,
    keypair: &KeyPair,
    peer_public_identity: Option<&ed25519_dalek::VerifyingKey>,
    peer_x25519_public: Option<&x25519_dalek::PublicKey>,
) -> Result<SecureSession>
where
    IO: tokio::io::AsyncReadExt + tokio::io::AsyncWriteExt + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    
    let our_identity_b64 = BASE64.encode(keypair.verifying.as_bytes());
    let our_x25519_b64 = BASE64.encode(keypair.public_key().as_bytes());
    
    // Generate nonce
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    
    // Send Hello
    let hello = HandshakeMessage::Hello {
        identity: our_identity_b64.clone(),
        public_key: our_x25519_b64,
        nonce,
    };
    
    let hello_data = serde_json::to_vec(&hello)?;
    let len = (hello_data.len() as u32).to_le_bytes();
    io.write_all(&len).await?;
    io.write_all(&hello_data).await?;
    io.flush().await?;
    
    // Receive Ack
    let mut len_buf = [0u8; 4];
    io.read_exact(&mut len_buf).await?;
    let len = u32::from_le_bytes(len_buf) as usize;
    let mut ack_buf = vec![0u8; len];
    io.read_exact(&mut ack_buf).await?;
    
    let ack: HandshakeMessage = serde_json::from_slice(&ack_buf)
        .context("Invalid ack message")?;
    
    let HandshakeMessage::Ack { identity: peer_identity_b64, public_key: peer_x25519_b64, echo_nonce, nonce: peer_nonce } = ack else {
        anyhow::bail!("Expected Ack, got other message");
    };
    
    // Verify echoed nonce
    if echo_nonce != nonce {
        anyhow::bail!("Nonce mismatch - possible replay attack");
    }
    
    // Parse peer keys
    let peer_identity_bytes = BASE64.decode(&peer_identity_b64)
        .context("Invalid base64 in peer identity")?;
    let peer_identity_bytes: [u8; 32] = peer_identity_bytes.try_into().unwrap();
    let peer_identity = ed25519_dalek::VerifyingKey::from_bytes(&peer_identity_bytes)
        .context("Invalid peer identity")?;
    
    // Verify this matches what we expect (if we have it)
    if let Some(expected) = peer_public_identity {
        if &peer_identity != expected {
            anyhow::bail!("Peer identity mismatch!");
        }
    }
    
    let peer_x25519_bytes = BASE64.decode(&peer_x25519_b64)
        .context("Invalid base64 in peer X25519")?;
    let peer_x25519_bytes: [u8; 32] = peer_x25519_bytes.try_into().unwrap();
    let peer_x25519 = x25519_dalek::PublicKey::from(peer_x25519_bytes);
    
    // Derive shared secret
    let shared_secret = keypair.derive_shared_secret(&peer_x25519);
    
    // Build transcript for signing
    let transcript = format!(
        "{}\n{}\n{}\n{}\n{}\n{}\n",
        our_identity_b64,
        BASE64.encode(keypair.public_key().as_bytes()),
        bytes_to_hex(&nonce),
        peer_identity_b64,
        peer_x25519_b64,
        bytes_to_hex(&peer_nonce)
    );
    
    // Sign transcript
    let signature = keypair.sign(transcript.as_bytes());
    let signature_b64 = BASE64.encode(signature.to_bytes().as_slice());
    
    // Send Confirm
    let confirm = HandshakeMessage::Confirm { signature: signature_b64 };
    let confirm_data = serde_json::to_vec(&confirm)?;
    let len = (confirm_data.len() as u32).to_le_bytes();
    io.write_all(&len).await?;
    io.write_all(&confirm_data).await?;
    io.flush().await?;
    
    // Receive ConfirmAck
    let mut len_buf = [0u8; 4];
    io.read_exact(&mut len_buf).await?;
    let len = u32::from_le_bytes(len_buf) as usize;
    let mut confirm_buf = vec![0u8; len];
    io.read_exact(&mut confirm_buf).await?;
    
    let _confirm_ack: HandshakeMessage = serde_json::from_slice(&confirm_buf)
        .context("Invalid confirm ack")?;
    
    // Session established!
    tracing::info!("Handshake complete as initiator");
    
    Ok(create_session(shared_secret, *keypair.identity(), peer_identity, true))
}

/// Perform handshake as responder (server)
pub async fn handshake_responder<IO>(
    io: &mut IO,
    keypair: &KeyPair,
) -> Result<(SecureSession, ed25519_dalek::VerifyingKey)>
where
    IO: tokio::io::AsyncReadExt + tokio::io::AsyncWriteExt + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    
    // Receive Hello
    let mut len_buf = [0u8; 4];
    io.read_exact(&mut len_buf).await?;
    let len = u32::from_le_bytes(len_buf) as usize;
    let mut hello_buf = vec![0u8; len];
    io.read_exact(&mut hello_buf).await?;
    
    let hello: HandshakeMessage = serde_json::from_slice(&hello_buf)
        .context("Invalid hello message")?;
    
    let HandshakeMessage::Hello { identity: peer_identity_b64, public_key: peer_x25519_b64, nonce: peer_nonce } = hello else {
        anyhow::bail!("Expected Hello, got other message");
    };
    
    // Parse peer keys
    let peer_identity_bytes = BASE64.decode(&peer_identity_b64)
        .context("Invalid base64 in peer identity")?;
    let peer_identity_bytes: [u8; 32] = peer_identity_bytes.try_into().unwrap();
    let peer_identity = ed25519_dalek::VerifyingKey::from_bytes(&peer_identity_bytes)
        .context("Invalid peer identity")?;
    
    let peer_x25519_bytes = BASE64.decode(&peer_x25519_b64)
        .context("Invalid base64 in peer X25519")?;
    let peer_x25519_bytes: [u8; 32] = peer_x25519_bytes.try_into().unwrap();
    let peer_x25519 = x25519_dalek::PublicKey::from(peer_x25519_bytes);
    
    // Generate our nonce
    let mut our_nonce = [0u8; 32];
    OsRng.fill_bytes(&mut our_nonce);
    
    // Send Ack
    let our_identity_b64 = BASE64.encode(keypair.verifying.as_bytes());
    let our_x25519_b64 = BASE64.encode(keypair.public_key().as_bytes());
    
    let ack = HandshakeMessage::Ack {
        identity: our_identity_b64.clone(),
        public_key: our_x25519_b64.clone(),
        echo_nonce: peer_nonce,
        nonce: our_nonce,
    };
    
    let ack_data = serde_json::to_vec(&ack)?;
    let len = (ack_data.len() as u32).to_le_bytes();
    io.write_all(&len).await?;
    io.write_all(&ack_data).await?;
    io.flush().await?;
    
    // Derive shared secret
    let shared_secret = keypair.derive_shared_secret(&peer_x25519);
    
    // Wait for Confirm
    let mut len_buf = [0u8; 4];
    io.read_exact(&mut len_buf).await?;
    let len = u32::from_le_bytes(len_buf) as usize;
    let mut confirm_buf = vec![0u8; len];
    io.read_exact(&mut confirm_buf).await?;
    
    let _confirm: HandshakeMessage = serde_json::from_slice(&confirm_buf)
        .context("Invalid confirm message")?;
    
    // Build transcript and sign
    let transcript = format!(
        "{}\n{}\n{}\n{}\n{}\n{}\n",
        peer_identity_b64,
        peer_x25519_b64,
        bytes_to_hex(&peer_nonce),
        our_identity_b64,
        our_x25519_b64,
        bytes_to_hex(&our_nonce)
    );
    
    let signature = keypair.sign(transcript.as_bytes());
    let signature_b64 = BASE64.encode(signature.to_bytes().as_slice());
    
    // Send ConfirmAck
    let confirm_ack = HandshakeMessage::ConfirmAck { signature: signature_b64 };
    let confirm_ack_data = serde_json::to_vec(&confirm_ack)?;
    let len = (confirm_ack_data.len() as u32).to_le_bytes();
    io.write_all(&len).await?;
    io.write_all(&confirm_ack_data).await?;
    io.flush().await?;
    
    tracing::info!("Handshake complete as responder");
    
    Ok((create_session(shared_secret, *keypair.identity(), peer_identity, false), peer_identity))
}
