//! DropCtl - CLI application

use {
    anyhow::{Context, Result},
    clap::{Parser, Subcommand},
    std::path::PathBuf,
    tokio::net::{TcpListener, TcpStream},
    tokio::io::{AsyncReadExt, AsyncWriteExt},
    tracing::info,
};

use dropctl::{
    crypto::{KeyPair, load_or_generate_keypair, KnownHost},
    handshake_initiator, handshake_responder,
    protocol::{Message, Handshake, read_message, write_message},
    transfer::{send_file, receive_file, receive_file_with_header, print_progress},
    config::{key_path, known_hosts_path, load_known_hosts, save_known_hosts},
};

/// Simple CLI peer-to-peer file transfer
#[derive(Parser)]
#[command(name = "dropctl")]
#[command(about = "Secure peer-to-peer file transfer", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    
    /// Verbose output
    #[arg(short, long)]
    verbose: bool,
    
    /// Key file path (default: ~/.config/dropctl/identity.key)
    #[arg(long)]
    key_file: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start listening and receive a file
    Listen {
        /// Port to listen on
        #[arg(default_value = "7777")]
        port: u16,
        
        /// Output directory for received file
        #[arg(short, long)]
        output: Option<PathBuf>,
        
        /// Hostname to announce
        #[arg(long)]
        hostname: Option<String>,
    },
    
    /// Connect and send a file
    Send {
        /// Peer address (host:port)
        address: String,
        
        /// File to send
        file: PathBuf,
        
        /// Peer's public key (optional, for verification)
               peer_key: Option<String>,
        
        /// Hostname to announce
        #[arg(long)]
        hostname: Option<String>,
    },
    
    /// Show public key (for sharing with peers)
    ShowKey,
    
    /// Manage known hosts
    KnownHosts {
        #[command(subcommand)]
        action: KnownHostsAction,
    },
}

#[derive(Subcommand)]
enum KnownHostsAction {
    /// List known hosts
    List,
    /// Add a known host
    Add {
        /// Host name/alias
        name: String,
        
        /// Public key (use `dropctl show-key` on remote host)
        public_key: String,
    },
    /// Remove a known host
    Remove {
        /// Host name to remove
        name: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    let filter = if std::env::var("RUST_LOG").is_ok() {
        tracing_subscriber::EnvFilter::from_default_env()
    } else {
        tracing_subscriber::EnvFilter::new("info")
    };
    
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .init();
    
    let cli = Cli::parse();
    
    // Override key file if specified
    let key_path = cli.key_file.unwrap_or_else(key_path);
    
    // Load or generate keypair
    let keypair = load_or_generate_keypair(&key_path)
        .context("Failed to load keypair")?;
    
    match cli.command {
        Commands::ShowKey => {
            println!("Your public key:");
            println!("{}", keypair.serialize_public());
            println!("\nShare this with your peer so they can verify your identity.");
        }
        
        Commands::Listen { port, output, hostname } => {
            let hostname = hostname.unwrap_or_else(|| hostname::get()
                .map(|h| h.to_string_lossy().into_owned())
                .unwrap_or_else(|_| "unknown".to_string()));
            
            let output_dir = output.unwrap_or_else(|| PathBuf::from("."));
            
            info!("Listening on port {}", port);
            
            let listener = TcpListener::bind(("0.0.0.0", port)).await
                .context("Failed to bind port")?;
            
            info!("Waiting for incoming connection...");
            
            let (socket, addr) = listener.accept().await
                .context("Failed to accept connection")?;
            
            info!("Accepted connection from {}", addr);
            
            handle_listen(socket, keypair, hostname, output_dir).await?;
        }
        
        Commands::Send { address, file, peer_key, hostname } => {
            let hostname = hostname.unwrap_or_else(|| hostname::get()
                .map(|h| h.to_string_lossy().into_owned())
                .unwrap_or_else(|_| "unknown".to_string()));
            
            if !file.exists() {
                anyhow::bail!("File not found: {}", file.display());
            }
            
            info!("Connecting to {}", address);
            
            let socket = TcpStream::connect(&address).await
                .context("Failed to connect")?;
            
            info!("Connected to {}", address);
            
            handle_send(socket, keypair, hostname, file, peer_key).await?;
        }
        
        Commands::KnownHosts { action } => {
            let hosts_path = known_hosts_path();
            match action {
                KnownHostsAction::List => {
                    let hosts = load_known_hosts(&hosts_path)?;
                    if hosts.is_empty() {
                        println!("No known hosts.");
                    } else {
                        for host in hosts {
                            println!("{}: {}", host.name, host.identity);
                        }
                    }
                }
                KnownHostsAction::Add { name, public_key: _ } => {
                    let mut hosts = load_known_hosts(&hosts_path)?;
                    hosts.push(KnownHost::new(name, &keypair));
                    save_known_hosts(&hosts_path, &hosts)?;
                    println!("Host added.");
                }
                KnownHostsAction::Remove { name } => {
                    let mut hosts = load_known_hosts(&hosts_path)?;
                    hosts.retain(|h| h.name != name);
                    save_known_hosts(&hosts_path, &hosts)?;
                    println!("Host removed.");
                }
            }
        }
    }
    
    Ok(())
}

async fn handle_listen(
    mut socket: TcpStream,
    keypair: KeyPair,
    hostname: String,
    output_dir: PathBuf,
) -> Result<()> {
    // Perform crypto handshake as responder
    let (session, peer_identity) = handshake_responder(&mut socket, &keypair).await?;
    
    info!("Peer identity verified: {:?}", peer_identity);
    
    // Send our handshake
    let handshake = Handshake::new(hostname);
    write_message(&mut socket, &Message::Handshake(handshake)).await?;
    
    // Wait for peer's handshake
    let msg = read_message(&mut socket).await?;
    if let Message::Handshake(h) = msg {
        info!("Peer hostname: {}", h.hostname);
    }
    
    // Wait for incoming file with timeout
    let timeout = tokio::time::timeout(tokio::time::Duration::from_secs(60), async {
        loop {
            // Try to read a message (non-blocking feel)
            match tokio::time::timeout(tokio::time::Duration::from_millis(100), read_message(&mut socket)).await {
                Ok(Ok(msg)) => {
                    match msg {
                        Message::SendFile { name, size, .. } => {
                            info!("Incoming file: {} ({} bytes)", name, size);
                            
                            // Accept and receive - pass the already-read header
                            write_message(&mut socket, &Message::Accept).await?;
                            
                            // Receive file - header already consumed, skip reading
                            let filename = receive_file_with_header(
                                &mut socket,
                                &session,
                                &output_dir,
                                &name,
                                size,
                                Some(Box::new(print_progress)),
                            ).await?;
                            
                            println!("\n✓ Received: {}", filename);
                            return Ok(());
                        }
                        Message::Ping => {
                            write_message(&mut socket, &Message::Pong).await?;
                        }
                        _ => {}
                    }
                }
                _ => {
                    // Continue waiting
                }
            }
        }
    });
    
    match timeout.await {
        Ok(Ok(())) => {
            info!("Transfer completed successfully");
        }
        Ok(Err(e)) => {
            info!("Transfer error: {}", e);
            return Err(e);
        }
        Err(_) => anyhow::bail!("Timeout waiting for file"),
    }
    
    Ok(())
}

async fn handle_send(
    mut socket: TcpStream,
    keypair: KeyPair,
    hostname: String,
    file_path: PathBuf,
    peer_key: Option<String>,
) -> Result<()> {
    // Parse peer key if provided
    let (peer_identity, peer_x25519) = if let Some(key) = peer_key {
        let (id, x25519) = KeyPair::deserialize_public(&key)
            .context("Invalid peer key format")?;
        (Some(id), Some(x25519))
    } else {
        (None, None)
    };
    
    // Perform crypto handshake as initiator
    let session = handshake_initiator(
        &mut socket, 
        &keypair, 
        peer_identity.as_ref(), 
        peer_x25519.as_ref()
    ).await?;
    
    info!("Secure connection established");
    
    // Send our handshake
    let handshake = Handshake::new(hostname);
    write_message(&mut socket, &Message::Handshake(handshake)).await?;
    
    // Wait for peer's handshake
    let msg = read_message(&mut socket).await?;
    if let Message::Handshake(h) = msg {
        info!("Peer hostname: {}", h.hostname);
    }
    
    // Give receiver time to get ready
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    
    info!("Starting file transfer...");
    
    // Send the file
    send_file(
        &mut socket,
        &session,
        &file_path,
        Some(Box::new(print_progress)),
    ).await?;
    
    println!("\n✓ Sent: {}", file_path.file_name().unwrap_or_default().to_string_lossy());
    
    Ok(())
}
