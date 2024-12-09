pub mod wbaes;

#[derive(Debug)]
pub enum CryptoError {
    EncryptionError(String),
    DecryptionError(String),
}

pub type Result<T> = std::result::Result<T, CryptoError>;

pub trait Encryption {
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>>;
    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>>;
}

pub trait KeyGeneration {
    fn generate_key() -> Result<Self> where Self: Sized;
}