use crate::encryption::error::EncryptionError;

#[derive(Clone)]
pub struct WbAES {
    key: Vec<u8>,
}

impl WbAES {
    pub fn generate_key() -> Result<Self, EncryptionError> {
        Ok(Self {
            key: vec![0; 32],
        })
    }

    pub fn get_key(&self) -> Option<Vec<u8>> {
        Some(self.key.clone())
    }

    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        Ok(data.to_vec())
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        Ok(data.to_vec())
    }
}
