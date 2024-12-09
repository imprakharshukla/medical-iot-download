//! Payload encryption module
//! 
//! Handles encryption and decryption of medical sensor data payloads.

use super::{Result, CryptoError};
use common::encryption::wbaes::WbAES;

pub trait Encryption {
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>>;
    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>>;
}

pub struct Encryptor {
    cipher: WbAES,
}

impl Encryptor {
    pub fn new(cipher: WbAES) -> Self {
        Self { cipher }
    }
}

impl Encryption for Encryptor {
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        self.cipher.encrypt(data)
            .map_err(|e| CryptoError::EncryptionError(e.to_string()))
    }

    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        self.cipher.decrypt(data)
            .map_err(|e| CryptoError::DecryptionError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_roundtrip() {
        let cipher = WbAES::generate_key().unwrap();
        let encryptor = Encryptor::new(cipher);
        
        let data = b"test data";
        let encrypted = encryptor.encrypt(data).unwrap();
        let decrypted = encryptor.decrypt(&encrypted).unwrap();
        
        assert_eq!(data, &decrypted[..]);
    }
} 