//! File transfer implementation with chunking and progress

use {
    anyhow::{Context, Result},
    std::path::Path,
    tokio::fs::File,
    tokio::io::{AsyncReadExt, AsyncWriteExt},
};

use crate::crypto::SecureSession;
use crate::protocol::{Message, read_message, write_message};

/// Chunk size for file transfer (64KB)
pub const CHUNK_SIZE: usize = 64 * 1024;

/// Progress callback
pub type ProgressCallback = Box<dyn Fn(TransferProgress) + Send + Sync>;

/// Transfer progress information
#[derive(Debug, Clone)]
pub struct TransferProgress {
    pub direction: TransferDirection,
    pub filename: String,
    pub total_bytes: u64,
    pub transferred_bytes: u64,
    pub chunk_index: u32,
}

#[derive(Debug, Clone, Copy)]
pub enum TransferDirection {
    Send,
    Receive,
}

/// Send a file to the peer
pub async fn send_file<IO>(
    io: &mut IO,
    session: &SecureSession,
    file_path: &Path,
    progress: Option<ProgressCallback>,
) -> Result<()>
where
    IO: tokio::io::AsyncReadExt + tokio::io::AsyncWriteExt + Unpin,
{
    // Open file
    let mut file = File::open(file_path).await.context("Failed to open file")?;
    let metadata = file.metadata().await?;
    let total_size = metadata.len();
    let filename = file_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string();
    
    tracing::info!("Sending file: {} ({} bytes)", filename, total_size);
    
    // Send file header
    let header = Message::SendFile {
        name: filename.clone(),
        size: total_size,
        mime_type: None,
    };
    write_message(io, &header).await?;
    
    // Wait for acceptance
    let response = read_message(io).await?;
    
    match response {
        Message::Accept => {}
        Message::Reject { reason } => anyhow::bail!("Transfer rejected: {}", reason),
        _ => anyhow::bail!("Unexpected response: {:?}", response),
    }
    
    // Send chunks
    let mut chunk_buf = vec![0u8; CHUNK_SIZE];
    let mut chunk_index = 0u32;
    let mut transferred = 0u64;
    
    loop {
        let bytes_read = file.read(&mut chunk_buf).await?;
        if bytes_read == 0 {
            break;
        }
        
        let chunk_data = chunk_buf[..bytes_read].to_vec();
        
        // Encrypt and send chunk
        let mut session_guard = session.lock().await;
        let encrypted = session_guard.encrypt(&chunk_data).context("Encryption failed")?;
        
        let chunk_msg = Message::Chunk {
            index: chunk_index,
            data: encrypted,
        };
        write_message(io, &chunk_msg).await?;
        
        // Yield to let receiver process
        tokio::task::yield_now().await;
        
        transferred += bytes_read as u64;
        chunk_index += 1;
        
        // Report progress
        if let Some(ref cb) = progress {
            cb(TransferProgress {
                direction: TransferDirection::Send,
                filename: filename.clone(),
                total_bytes: total_size,
                transferred_bytes: transferred,
                chunk_index,
            });
        }
    }
    
    // Send done message
    let done = Message::Done;
    write_message(io, &done).await?;
    
    tracing::info!("File sent successfully: {}", filename);
    Ok(())
}

/// Receive a file when header was already read
pub async fn receive_file_with_header<IO>(
    io: &mut IO,
    session: &SecureSession,
    output_dir: &Path,
    filename: &str,
    total_size: u64,
    progress: Option<ProgressCallback>,
) -> Result<String>
where
    IO: tokio::io::AsyncReadExt + tokio::io::AsyncWriteExt + Unpin,
{
    tracing::info!("Receiving file with header: {} ({} bytes)", filename, total_size);
    
    // Wait a bit for sender to start
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    
    // Create output file (use temp file to avoid truncation issues)
    let temp_path = output_dir.join(format!(".{}", filename));
    let final_path = output_dir.join(filename);
    let mut file = File::create(&temp_path).await.context("Failed to create file")?;
    
    // Receive chunks
    let mut transferred = 0u64;
    let mut expected_index = 0u32;
    let filename = filename.to_string();
    
    loop {
        let chunk_msg = read_message(io).await?;
        
        match chunk_msg {
            Message::Chunk { index, data } => {
                if index != expected_index {
                    // Skip missing chunks (they might come later due to TCP reordering)
                    tracing::warn!("Skipping chunk {} (expected {})", index, expected_index);
                    continue;
                }
                
                // Decrypt chunk
                let mut session_guard = session.lock().await;
                let plaintext = session_guard.decrypt(&data).context("Decryption failed")?;
                
                // Write to file
                file.write_all(&plaintext).await?;
                transferred += plaintext.len() as u64;
                expected_index += 1;
                
                // Report progress
                if let Some(ref cb) = progress {
                    cb(TransferProgress {
                        direction: TransferDirection::Receive,
                        filename: filename.clone(),
                        total_bytes: total_size,
                        transferred_bytes: transferred,
                        chunk_index: expected_index,
                    });
                }
            }
            Message::Done => {
                break;
            }
            Message::Abort { reason } => {
                anyhow::bail!("Transfer aborted by peer: {}", reason);
            }
            _ => {
                tracing::warn!("Unexpected message during transfer: {:?}", chunk_msg);
            }
        }
    }
    
    file.flush().await?;
    drop(file);
    
    // Rename temp file to final name
    tokio::fs::rename(&temp_path, &final_path).await.context("Failed to rename temp file")?;
    
    tracing::info!("File received successfully: {}", final_path.display());
    Ok(filename)
}

/// Receive a file from the peer (reads header automatically)
pub async fn receive_file<IO>(
    io: &mut IO,
    session: &SecureSession,
    output_dir: &Path,
    progress: Option<ProgressCallback>,
) -> Result<String>
where
    IO: tokio::io::AsyncReadExt + tokio::io::AsyncWriteExt + Unpin,
{
    // Read file header
    let header = read_message(io).await?;
    let (filename, total_size) = match header {
        Message::SendFile { name, size, .. } => (name, size),
        _ => anyhow::bail!("Expected SendFile header, got: {:?}", header),
    };
    
    tracing::info!("Receiving file: {} ({} bytes)", filename, total_size);
    
    // Accept transfer
    let accept = Message::Accept;
    write_message(io, &accept).await?;
    
    // Use the with_header version
    receive_file_with_header(io, session, output_dir, &filename, total_size, progress).await
}

/// Simple progress printer
pub fn print_progress(progress: TransferProgress) {
    let percent = if progress.total_bytes > 0 {
        (progress.transferred_bytes as f64 / progress.total_bytes as f64 * 100.0) as u32
    } else {
        0
    };
    
    println!(
        "{} [{}/{} bytes] {}%",
        progress.filename,
        progress.transferred_bytes,
        progress.total_bytes,
        percent
    );
}
