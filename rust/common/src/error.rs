use actix_web::{ResponseError, HttpResponse};
use std::net::AddrParseError;
use thiserror::Error;
use redis::RedisError;
use crate::encryption::error::EncryptionError;

pub type Result<T> = std::result::Result<T, DiscoveryError>;

#[derive(Error, Debug)]
pub enum DiscoveryError {
    #[error("Network error: {0}")]
    NetworkError(String),
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("Security error: {0}")]
    SecurityError(String),
    #[error("Registration error: {0}")]
    RegistrationError(String),
    #[error("Validation error: {0}")]
    ValidationError(String),
    #[error("Device not found: {0}")]
    DeviceNotFound(String),
    #[error("Internal error: {0}")]
    InternalError(String),
    #[error("Storage error: {0}")]
    StorageError(String),
    #[error("Encryption error: {0}")]
    EncryptionError(String),
}

impl From<std::io::Error> for DiscoveryError {
    fn from(err: std::io::Error) -> Self {
        DiscoveryError::NetworkError(err.to_string())
    }
}

impl From<serde_json::Error> for DiscoveryError {
    fn from(err: serde_json::Error) -> Self {
        DiscoveryError::SerializationError(err.to_string())
    }
}

impl From<AddrParseError> for DiscoveryError {
    fn from(err: AddrParseError) -> Self {
        DiscoveryError::NetworkError(err.to_string())
    }
}

impl From<RedisError> for DiscoveryError {
    fn from(err: RedisError) -> Self {
        DiscoveryError::StorageError(err.to_string())
    }
}

impl From<EncryptionError> for DiscoveryError {
    fn from(err: EncryptionError) -> Self {
        DiscoveryError::EncryptionError(err.to_string())
    }
}

impl ResponseError for DiscoveryError {
    fn error_response(&self) -> HttpResponse {
        match self {
            Self::DeviceNotFound(_) => HttpResponse::NotFound().json(self.to_string()),
            Self::SecurityError(_) => HttpResponse::Forbidden().json(self.to_string()),
            Self::ValidationError(_) => HttpResponse::BadRequest().json(self.to_string()),
            Self::NetworkError(_) | 
            Self::SerializationError(_) | 
            Self::RegistrationError(_) | 
            Self::InternalError(_) |
            Self::StorageError(_) |
            Self::EncryptionError(_) => {
                HttpResponse::InternalServerError().json(self.to_string())
            }
        }
    }
} 