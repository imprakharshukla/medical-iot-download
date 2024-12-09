use crypto_benchmarks::{algorithms::wbaes::WbAES, Encryption, KeyGeneration};
use env_logger;
use log::info;

fn main() {
    env_logger::init();
    info!("Crypto benchmarking suite initialized");

    // Test WbAES
    let mut wbaes = WbAES::new(30, 100, 32);
    let key = wbaes.generate_key().expect("Failed to generate key");
    info!("Generated key of length: {}", key.len());
    
    // Use the setter method instead of direct field access
    wbaes.set_key(key);
    let test_data = b"Hello, World!";
    let encrypted = wbaes.encrypt(test_data).expect("Failed to encrypt");
    info!("Encrypted data length: {}", encrypted.len());
}
