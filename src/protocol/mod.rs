//! Application protocol for file transfer

use {
    anyhow::{Context, Result},
    serde::{Deserialize, Serialize},
};

/// Protocol version
pub const PROTOCOL_VERSION: u16 = 1;

/// Magic bytes to identify dropctl protocol
pub const MAGIC: &[u8] = b"DROP";

/// Message types in the application protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum Message {
    /// Initial handshake after crypto handshake
    Handshake(Handshake),
    
    /// Request to send a file
    SendFile {
        name: String,
        size: u64,
        mime_type: Option<String>,
    },
    
    /// Accept file transfer
    Accept,
    
    /// Reject file transfer
    Reject {
        reason: String,
    },
    
    /// File chunk data
    Chunk {
        index: u32,
        data: Vec<u8>,
    },
    
    /// Transfer complete
    Done,
    
    /// Transfer aborted
    Abort {
        reason: String,
    },
    
    /// Ping for keepalive
    Ping,
    
    /// Pong response
    Pong,
    
    /// Acknowledgment for a chunk
    ChunkAck {
        index: u32,
    },
}

/// Initial handshake after TLS
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Handshake {
    pub version: u16,
    pub hostname: String,
}

impl Handshake {
    pub fn new(hostname: String) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            hostname,
        }
    }
}

/// Parse a message from bytes
pub fn parse_message(data: &[u8]) -> Result<Message> {
    serde_json::from_slice(data).context("Invalid message format")
}

/// Serialize a message to bytes
pub fn serialize_message(msg: &Message) -> Result<Vec<u8>> {
    serde_json::to_vec(msg).context("Failed to serialize message")
}

/// Read a length-prefixed message from stream
pub async fn read_message<IO>(io: &mut IO) -> Result<Message>
where
    IO: tokio::io::AsyncReadExt + Unpin,
{
    use tokio::io::AsyncReadExt;
    
    // Read 4-byte length prefix
    let mut len_buf = [0u8; 4];
    io.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    
    // Read message data
    let mut data = vec![0u8; len];
    io.read_exact(&mut data).await?;
    
    parse_message(&data)
}

/// Write a length-prefixed message to stream
pub async fn write_message<IO>(io: &mut IO, msg: &Message) -> Result<()>
where
    IO: tokio::io::AsyncWriteExt + Unpin,
{
    use tokio::io::AsyncWriteExt;
    
    let data = serialize_message(msg)?;
    let len = (data.len() as u32).to_be_bytes();
    
    io.write_all(&len).await?;
    io.write_all(&data).await?;
    io.flush().await?;
    
    Ok(())
}
