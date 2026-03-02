//! Configuration management

use {
    anyhow::Result,
    std::path::{Path, PathBuf},
};

/// Default configuration directory
pub fn config_dir() -> PathBuf {
    #[cfg(windows)]
    {
        std::env::var("APPDATA")
            .map(|p| PathBuf::from(p).join("dropctl"))
            .unwrap_or_else(|_| PathBuf::from(".").join("dropctl"))
    }
    #[cfg(not(windows))]
    {
        std::env::var("HOME")
            .map(|h| PathBuf::from(h).join(".config").join("dropctl"))
            .unwrap_or_else(|_| PathBuf::from(".dropctl"))
    }
}

/// Default key file path
pub fn key_path() -> PathBuf {
    config_dir().join("identity.key")
}

/// Default known hosts file path
pub fn known_hosts_path() -> PathBuf {
    config_dir().join("known_hosts")
}

/// Load known hosts from file
pub fn load_known_hosts(path: &Path) -> Result<Vec<crate::crypto::KnownHost>> {
    if !path.exists() {
        return Ok(vec![]);
    }
    
    let content = std::fs::read_to_string(path)?;
    let hosts: Vec<crate::crypto::KnownHost> = serde_json::from_str(&content)?;
    Ok(hosts)
}

/// Save known hosts to file
pub fn save_known_hosts(path: &Path, hosts: &[crate::crypto::KnownHost]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    
    let content = serde_json::to_string_pretty(hosts)?;
    std::fs::write(path, content)?;
    Ok(())
}
