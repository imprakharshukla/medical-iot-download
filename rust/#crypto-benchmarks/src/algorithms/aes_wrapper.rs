use aes::Aes256;
use cipher::{
    BlockEncrypt, BlockDecrypt, KeyInit,
    generic_array::GenericArray,
    block_padding::Pkcs7,
};
use rand::RngCore;
use crate::{Encryption, KeyGeneration, Result, CryptoError};

pub struct AESWrapper {
    key: Option<Vec<u8>>,
    iv: [u8; 16],
}

impl AESWrapper {
    pub fn new() -> Self {
        let mut iv = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut iv);
        Self {
            key: None,
            iv,
        }
    }

    pub fn set_key(&mut self, key: Vec<u8>) {
        self.key = Some(key);
    }
}

impl KeyGeneration for AESWrapper {
    fn generate_key(&self) -> Result<Vec<u8>> {
        let mut key = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        Ok(key)
    }
}

impl Encryption for AESWrapper {
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        let key = self.key.as_ref().ok_or_else(|| {
            CryptoError::EncryptionError("No key set".to_string())
        })?;

        let cipher = Aes256::new_from_slice(key)
            .map_err(|e| CryptoError::EncryptionError(e.to_string()))?;

        let mut buffer = data.to_vec();
        let blocks = buffer.chunks_mut(16);
        
        for block in blocks {
            let mut block_array = GenericArray::from_slice(block).clone();
            cipher.encrypt_block(&mut block_array);
            block[..].copy_from_slice(&block_array);
        }

        Ok(buffer)
    }

    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        let key = self.key.as_ref().ok_or_else(|| {
            CryptoError::DecryptionError("No key set".to_string())
        })?;

        let cipher = Aes256::new_from_slice(key)
            .map_err(|e| CryptoError::DecryptionError(e.to_string()))?;

        let mut buffer = data.to_vec();
        let blocks = buffer.chunks_mut(16);
        
        for block in blocks {
            let mut block_array = GenericArray::from_slice(block).clone();
            cipher.decrypt_block(&mut block_array);
            block[..].copy_from_slice(&block_array);
        }

        Ok(buffer)
    }
} 