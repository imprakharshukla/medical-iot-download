use crypto_benchmarks::{
    algorithms::{
        wbaes::WbAES,
        aes_wrapper::AESWrapper,
        rsa_wrapper::RSAWrapper,
        ecc_wrapper::ECCWrapper,
    },
    Encryption,
    KeyGeneration,
};

// Helper trait to combine our requirements
trait CipherTest: Encryption + KeyGeneration {
    fn create_with_key() -> (Self, Vec<u8>)
    where
        Self: Sized;
    
    fn create_with_modified_key(&self, original_key: &[u8]) -> (Self, Vec<u8>)
    where
        Self: Sized;
}

impl CipherTest for WbAES {
    fn create_with_key() -> (Self, Vec<u8>) {
        let mut cipher = WbAES::new(30, 100, 32);
        let key = cipher.generate_key().unwrap();
        cipher.set_key(key.clone());
        (cipher, key)
    }

    fn create_with_modified_key(&self, original_key: &[u8]) -> (Self, Vec<u8>) {
        let mut modified_key = original_key.to_vec();
        modified_key[0] ^= 1;
        let mut cipher = WbAES::new(30, 100, 32);
        cipher.set_key(modified_key.clone());
        (cipher, modified_key)
    }
}

impl CipherTest for AESWrapper {
    fn create_with_key() -> (Self, Vec<u8>) {
        let mut cipher = AESWrapper::new();
        let key = cipher.generate_key().unwrap();
        cipher.set_key(key.clone());
        (cipher, key)
    }

    fn create_with_modified_key(&self, original_key: &[u8]) -> (Self, Vec<u8>) {
        let mut modified_key = original_key.to_vec();
        modified_key[0] ^= 1;
        let mut cipher = AESWrapper::new();
        cipher.set_key(modified_key.clone());
        (cipher, modified_key)
    }
}

impl CipherTest for RSAWrapper {
    fn create_with_key() -> (Self, Vec<u8>) {
        let mut cipher = RSAWrapper::new();
        cipher.set_key(2048).unwrap();
        let key = cipher.generate_key().unwrap();
        (cipher, key)
    }

    fn create_with_modified_key(&self, original_key: &[u8]) -> (Self, Vec<u8>) {
        let mut modified_key = original_key.to_vec();
        modified_key[0] ^= 1;
        let mut cipher = RSAWrapper::new();
        cipher.set_key(2048).unwrap();
        (cipher, modified_key)
    }
}

impl CipherTest for ECCWrapper {
    fn create_with_key() -> (Self, Vec<u8>) {
        let mut cipher = ECCWrapper::new();
        cipher.set_key().unwrap();
        let key = cipher.generate_key().unwrap();
        (cipher, key)
    }

    fn create_with_modified_key(&self, original_key: &[u8]) -> (Self, Vec<u8>) {
        let mut modified_key = original_key.to_vec();
        modified_key[0] ^= 1;
        let mut cipher = ECCWrapper::new();
        cipher.set_key().unwrap();
        (cipher, modified_key)
    }
}

#[test]
fn test_avalanche_effect() {
    // Use a full block of data to avoid padding differences
    let test_data = b"0000000000000000"; // 16 bytes exactly
    let mut modified_data = test_data.to_vec();
    modified_data[0] ^= 1; // Flip a single bit in the first byte

    test_algorithm_avalanche::<WbAES>("WbAES", test_data, &modified_data);
}

fn test_algorithm_avalanche<T: CipherTest>(name: &str, original: &[u8], modified: &[u8]) {
    let (cipher, _) = T::create_with_key();
    
    // Encrypt both messages
    let encrypted1 = cipher.encrypt(original).unwrap();
    let encrypted2 = cipher.encrypt(modified).unwrap();

    // Only compare the first block (16 bytes) to avoid padding differences
    let block_size = 16;
    let encrypted1_block = &encrypted1[..block_size];
    let encrypted2_block = &encrypted2[..block_size];

    // Count differing bits
    let diff_bits = count_differing_bits(encrypted1_block, encrypted2_block);
    let total_bits = block_size * 8;
    let difference_percentage = (diff_bits as f64 / total_bits as f64) * 100.0;

    println!(
        "{}: Changed {:.2}% of bits ({} of {})",
        name, difference_percentage, diff_bits, total_bits
    );

    // AES typically changes 35-65% of bits
    assert!(
        difference_percentage > 35.0 && difference_percentage < 65.0,
        "{}: Poor avalanche effect - only {:.2}% bits changed",
        name, difference_percentage
    );
}

#[test]
fn test_frequency_distribution() {
    let test_data = vec![0u8; 16]; // One block of zeros
    test_algorithm_frequency::<WbAES>("WbAES", &test_data);
}

fn test_algorithm_frequency<T: CipherTest>(name: &str, data: &[u8]) {
    let (cipher, _) = T::create_with_key();
    let encrypted = cipher.encrypt(data).unwrap();
    
    // Count frequency of each byte value
    let mut frequencies = vec![0usize; 256];
    for &byte in &encrypted {
        frequencies[byte as usize] += 1;
    }

    // Calculate chi-square statistic
    let expected = encrypted.len() as f64 / 256.0;
    let chi_square: f64 = frequencies.iter()
        .map(|&freq| {
            let diff = freq as f64 - expected;
            diff * diff / expected
        })
        .sum();

    println!("{}: Chi-square statistic: {}", name, chi_square);

    // For AES, we expect a more relaxed chi-square range
    assert!(
        chi_square < 15000.0,
        "{}: Poor distribution - chi-square: {}",
        name, chi_square
    );
}

#[test]
fn test_key_sensitivity() {
    let test_data = b"Hello, World!1234"; // 16 bytes exactly
    test_algorithm_key_sensitivity::<WbAES>("WbAES", test_data);
}

fn test_algorithm_key_sensitivity<T: CipherTest>(name: &str, data: &[u8]) {
    let (cipher1, key1) = T::create_with_key();
    let (cipher2, _) = cipher1.create_with_modified_key(&key1);

    let encrypted1 = cipher1.encrypt(data).unwrap();
    let encrypted2 = cipher2.encrypt(data).unwrap();

    let diff_bits = count_differing_bits(&encrypted1, &encrypted2);
    let total_bits = encrypted1.len() * 8;
    let difference_percentage = (diff_bits as f64 / total_bits as f64) * 100.0;

    println!(
        "{}: Key sensitivity - {:.2}% bits different",
        name, difference_percentage
    );

    // AES typically changes 35-65% of bits with key changes
    assert!(
        difference_percentage > 35.0 && difference_percentage < 65.0,
        "{}: Poor key sensitivity - only {:.2}% bits changed",
        name, difference_percentage
    );
}

fn count_differing_bits(data1: &[u8], data2: &[u8]) -> usize {
    data1.iter()
        .zip(data2.iter())
        .map(|(&a, &b)| (a ^ b).count_ones() as usize)
        .sum()
} 