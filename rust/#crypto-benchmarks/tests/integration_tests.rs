use crypto_benchmarks::{
    algorithms::wbaes::WbAES,
    Encryption,
    KeyGeneration,
};

#[test]
fn test_full_encryption_workflow() {
    // Initialize WbAES with parameters for AES-256 (32-byte key)
    let mut wbaes = WbAES::new(30, 100, 32);
    
    // Generate key
    let key = wbaes.generate_key().expect("Failed to generate key");
    assert_eq!(key.len(), 32, "Key length should be 32 bytes for AES-256");
    wbaes.set_key(key);
    
    // Test data (exactly 48 bytes - 3 AES blocks)
    let original_data = b"This is a test message for AES-256 encrypt!!!!!!";
    assert_eq!(original_data.len(), 48, "Test data should be 48 bytes");
    assert_eq!(original_data.len() % 16, 0, "Test data should be multiple of 16 bytes");
    
    // Encrypt
    let encrypted = wbaes.encrypt(original_data).expect("Failed to encrypt");
    
    // Verify encryption changed the data
    assert_ne!(encrypted, original_data);
    assert_eq!(encrypted.len() % 16, 0, "Encrypted data should be multiple of 16 bytes");
    
    // Decrypt
    let decrypted = wbaes.decrypt(&encrypted).expect("Failed to decrypt");
    
    // Verify decryption restored the original data
    assert_eq!(decrypted, original_data);
}

#[test]
fn test_multiple_keys() {
    let wbaes = WbAES::new(30, 100, 32);
    
    // Generate multiple keys and ensure they're different
    let key1 = wbaes.generate_key().expect("Failed to generate first key");
    let key2 = wbaes.generate_key().expect("Failed to generate second key");
    
    assert_eq!(key1.len(), 32, "First key should be 32 bytes");
    assert_eq!(key2.len(), 32, "Second key should be 32 bytes");
    assert_ne!(key1, key2, "Generated keys should be different");
}

#[test]
fn test_padding() {
    let mut wbaes = WbAES::new(30, 100, 32);
    let key = wbaes.generate_key().expect("Failed to generate key");
    wbaes.set_key(key);

    // Test various message lengths
    let test_cases = vec![
        b"1".to_vec(),                    // 1 byte
        b"12345678".to_vec(),             // 8 bytes
        b"1234567890123456".to_vec(),     // 16 bytes (block size)
        b"12345678901234567".to_vec(),    // 17 bytes
    ];

    for original_data in test_cases {
        let encrypted = wbaes.encrypt(&original_data).expect("Failed to encrypt");
        assert_eq!(encrypted.len() % 16, 0, "Encrypted data should be multiple of 16 bytes");
        
        let decrypted = wbaes.decrypt(&encrypted).expect("Failed to decrypt");
        assert_eq!(decrypted, original_data, "Decryption should match original");
    }
}

#[test]
fn test_large_data() {
    let mut wbaes = WbAES::new(30, 100, 32);
    let key = wbaes.generate_key().expect("Failed to generate key");
    wbaes.set_key(key);

    // Generate 1MB of random data
    let original_data: Vec<u8> = (0..1_048_576).map(|_| rand::random::<u8>()).collect();
    
    let encrypted = wbaes.encrypt(&original_data).expect("Failed to encrypt");
    assert_eq!(encrypted.len() % 16, 0, "Encrypted data should be multiple of 16 bytes");
    
    let decrypted = wbaes.decrypt(&encrypted).expect("Failed to decrypt");
    assert_eq!(decrypted, original_data, "Decryption should match original");
} 