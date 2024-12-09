use p256::{
    SecretKey, PublicKey,
    ecdh::diffie_hellman,
    elliptic_curve::sec1::ToEncodedPoint,
};
use rand_core::OsRng;
use crate::{Encryption, KeyGeneration, Result, CryptoError};

pub struct ECCWrapper {
    private_key: Option<SecretKey>,
    public_key: Option<PublicKey>,
}

impl ECCWrapper {
    pub fn new() -> Self {
        Self {
            private_key: None,
            public_key: None,
        }
    }

    pub fn set_key(&mut self) -> Result<()> {
        let private_key = SecretKey::random(&mut OsRng);
        let public_key = private_key.public_key();
        
        self.private_key = Some(private_key);
        self.public_key = Some(public_key);
        Ok(())
    }
}

impl KeyGeneration for ECCWrapper {
    fn generate_key(&self) -> Result<Vec<u8>> {
        if let Some(public_key) = &self.public_key {
            Ok(public_key.to_encoded_point(false).as_bytes().to_vec())
        } else {
            Err(CryptoError::KeyGenerationError("No key pair generated".to_string()))
        }
    }
}

impl Encryption for ECCWrapper {
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        let public_key = self.public_key.as_ref().ok_or_else(|| {
            CryptoError::EncryptionError("No public key available".to_string())
        })?;

        let ephemeral_secret = SecretKey::random(&mut OsRng);
        let ephemeral_public = ephemeral_secret.public_key();
        
        let shared_secret = diffie_hellman(
            ephemeral_secret.to_nonzero_scalar(),
            public_key.as_affine(),
        );

        let mut result = ephemeral_public.to_encoded_point(false).as_bytes().to_vec();
        result.extend(data.iter().zip(shared_secret.raw_secret_bytes()).map(|(&d, &s)| d ^ s));
        Ok(result)
    }

    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        let private_key = self.private_key.as_ref().ok_or_else(|| {
            CryptoError::DecryptionError("No private key available".to_string())
        })?;

        let point_len = 65; // Uncompressed point length
        if data.len() <= point_len {
            return Err(CryptoError::DecryptionError("Invalid ciphertext".to_string()));
        }

        let ephemeral_public = PublicKey::from_sec1_bytes(&data[..point_len])
            .map_err(|e| CryptoError::DecryptionError(e.to_string()))?;

        let shared_secret = diffie_hellman(
            private_key.to_nonzero_scalar(),
            ephemeral_public.as_affine(),
        );
        
        Ok(data[point_len..].iter()
            .zip(shared_secret.raw_secret_bytes())
            .map(|(&d, &s)| d ^ s)
            .collect())
    }
} 