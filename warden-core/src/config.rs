#![forbid(unsafe_code)]

use crate::error::Error;
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub data_dir: PathBuf,
    pub db_filename: String,
    pub api: ApiConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    pub host: String,
    pub port: u16,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            data_dir: default_data_dir().unwrap_or_else(|_| {
                let fallback = std::env::temp_dir().join("warden");
                tracing::warn!(
                    path = %fallback.display(),
                    "Could not determine platform data directory; using ephemeral temp directory"
                );
                fallback
            }),
            db_filename: "warden.db".to_string(),
            api: ApiConfig::default(),
        }
    }
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 3000,
        }
    }
}

impl Config {
    pub fn new() -> Result<Self, Error> {
        Ok(Self {
            data_dir: default_data_dir()?,
            db_filename: "warden.db".to_string(),
            api: ApiConfig::default(),
        })
    }

    pub fn db_path(&self) -> PathBuf {
        self.data_dir.join(&self.db_filename)
    }

    pub fn with_data_dir(mut self, path: PathBuf) -> Self {
        self.data_dir = path;
        self
    }

    pub fn ensure_data_dir(&self) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.data_dir)
    }
}

fn default_data_dir() -> Result<PathBuf, Error> {
    ProjectDirs::from("io", "privkey", "warden")
        .map(|dirs| dirs.data_dir().to_path_buf())
        .ok_or_else(|| {
            Error::Config(
                "Could not determine platform data directory; \
                 please specify --data-dir or set $HOME"
                    .to_string(),
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.db_filename, "warden.db");
        assert_eq!(config.api.port, 3000);
    }

    #[test]
    fn test_db_path() {
        let config = Config::default().with_data_dir(PathBuf::from("/tmp/test"));
        assert_eq!(config.db_path(), PathBuf::from("/tmp/test/warden.db"));
    }
}
