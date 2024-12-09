//! Encryption module for securing medical data
//! 
//! This module provides functionality for encrypting and decrypting both payload data
//! and metadata using AES-GCM encryption.

pub mod keys;
pub mod payload;
pub mod metrics;
pub mod error;

use std::fmt;
use std::error::Error;
use rand::Rng;

pub use common::encryption::{wbaes::WbAES};
pub use self::keys::KeyPair;

#[derive(Debug)]
pub enum CryptoError {
    EncryptionError(String),
    DecryptionError(String),
    KeyGenerationError(String),
}

pub type Result<T> = std::result::Result<T, CryptoError>;

pub fn generate_nonce() -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut nonce = vec![0u8; 12];
    rng.fill(&mut nonce[..]);
    nonce
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::EncryptionError(msg) => write!(f, "Encryption error: {}", msg),
            CryptoError::DecryptionError(msg) => write!(f, "Decryption error: {}", msg),
            CryptoError::KeyGenerationError(msg) => write!(f, "Key generation error: {}", msg),
        }
    }
}

impl Error for CryptoError {} 