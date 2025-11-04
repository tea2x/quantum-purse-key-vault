use std::fmt;
use std::io;

#[derive(Debug)]
pub enum KeyVaultDBError {
    SerializationError(String),
    DatabaseError(String),
    IoError(String),
}

impl fmt::Display for KeyVaultDBError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            KeyVaultDBError::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
            KeyVaultDBError::DatabaseError(msg) => write!(f, "Database error: {}", msg),
            KeyVaultDBError::IoError(msg) => write!(f, "IO error: {}", msg),
        }
    }
}

impl std::error::Error for KeyVaultDBError {}

impl From<io::Error> for KeyVaultDBError {
    fn from(e: io::Error) -> Self {
        KeyVaultDBError::IoError(e.to_string())
    }
}

impl From<serde_json::Error> for KeyVaultDBError {
    fn from(e: serde_json::Error) -> Self {
        KeyVaultDBError::SerializationError(e.to_string())
    }
}
