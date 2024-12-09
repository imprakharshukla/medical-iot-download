use rsa::{
    RsaPrivateKey, RsaPublicKey, Pkcs1v15Encrypt,
    traits::PublicKeyParts,
};
use rand::rngs::OsRng;
use crate::{Encryption, KeyGeneration, Result, CryptoError};

pub struct RSAWrapper {
    private_key: Option<RsaPrivateKey>,
    public_key: Option<RsaPublicKey>,
}

impl RSAWrapper {
    pub fn new() -> Self {
        Self {
            private_key: None,
            public_key: None,
        }
    }

    pub fn set_key(&mut self, bits: usize) -> Result<()> {
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, bits)
            .map_err(|e| CryptoError::KeyGenerationError(e.to_string()))?;
        let public_key = RsaPublicKey::from(&private_key);
        
        self.private_key = Some(private_key);
        self.public_key = Some(public_key);
        Ok(())
    }
}

impl KeyGeneration for RSAWrapper {
    fn generate_key(&self) -> Result<Vec<u8>> {
        // RSA doesn't use a simple byte array as key
        // Instead, we'll return the modulus as the "key" for comparison
        if let Some(public_key) = &self.public_key {
            Ok(public_key.n().to_bytes_be())
        } else {
            Err(CryptoError::KeyGenerationError("No key pair generated".to_string()))
        }
    }
}

impl Encryption for RSAWrapper {
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        let public_key = self.public_key.as_ref().ok_or_else(|| {
            CryptoError::EncryptionError("No public key available".to_string())
        })?;

        let mut rng = OsRng;
        public_key.encrypt(&mut rng, Pkcs1v15Encrypt, data)
            .map_err(|e| CryptoError::EncryptionError(e.to_string()))
    }

    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        let private_key = self.private_key.as_ref().ok_or_else(|| {
            CryptoError::DecryptionError("No private key available".to_string())
        })?;

        private_key.decrypt(Pkcs1v15Encrypt, data)
            .map_err(|e| CryptoError::DecryptionError(e.to_string()))
    }
} 