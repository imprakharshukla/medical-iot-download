use crate::encryption::{
    CryptoError,
    Encryption,
    KeyGeneration,
    Result,
};
use aes::Aes256;
use cipher::{
    BlockEncrypt, BlockDecrypt,
    KeyInit,
    generic_array::GenericArray,
    consts::U16,
};
use rand::{Rng, thread_rng, SeedableRng, rngs::StdRng};
use rayon::prelude::*;
use std::sync::Arc;

/// Threshold for determining when to perform additional pattern checks
const THRESHOLD: f64 = 0.75;

/// White-box AES implementation using Whale Optimization Algorithm (WOA) for key generation
/// This implementation provides enhanced security through optimized key generation while
/// maintaining reasonable performance for IoT applications.
#[derive(Clone)]
pub struct WbAES {
    /// Size of the whale population for optimization
    population_size: usize,
    /// Maximum number of iterations for the optimization process
    max_iterations: usize,
    /// Dimension of the search space (key length in bytes)
    dimension: usize,
    /// Range for the search space coordinates
    search_space: (f64, f64),
    /// Current encryption/decryption key
    current_key: Option<Vec<u8>>,
}

impl WbAES {
    /// Creates a new WbAES instance with specified optimization parameters
    ///
    /// # Arguments
    /// * `population_size` - Number of whales in the population (recommended: 20)
    /// * `max_iterations` - Maximum optimization iterations (recommended: 50)
    /// * `dimension` - Key length in bytes (32 for AES-256)
    pub fn new(population_size: usize, max_iterations: usize, dimension: usize) -> Self {
        WbAES {
            population_size,
            max_iterations,
            dimension,
            search_space: (-1.0, 1.0),
            current_key: None,
        }
    }

    /// Implements the Whale Optimization Algorithm for key generation
    /// Uses parallel processing for fitness evaluation to improve performance
    fn optimize<F>(&self, fitness_function: Arc<F>) -> Vec<f64>
    where
        F: Fn(&[f64]) -> f64 + Send + Sync,
    {
        let mut rng = thread_rng();
        let mut population = self.initialize_population();
        let mut best_solution = vec![0.0; self.dimension];
        let mut best_fitness = f64::MAX;

        for iteration in 0..self.max_iterations {
            let r = rng.gen::<f64>();
            
            // Use Arc clone for parallel evaluation
            let fitness_fn = Arc::clone(&fitness_function);
            let fitness_values: Vec<f64> = population
                .par_iter()
                .map(|solution| {
                    let mut modified = solution.clone();
                    for val in &mut modified {
                        *val += (r - 0.5) * 0.1;
                        *val = val.clamp(self.search_space.0, self.search_space.1);
                    }
                    fitness_fn(&modified)
                })
                .collect();

            if let Some((idx, &fitness)) = fitness_values
                .iter()
                .enumerate()
                .min_by(|&(_, a), &(_, b)| a.partial_cmp(b).unwrap())
            {
                if fitness < best_fitness {
                    best_fitness = fitness;
                    best_solution = population[idx].clone();
                    for val in &mut best_solution {
                        *val += (rng.gen::<f64>() - 0.5) * 0.05;
                        *val = val.clamp(self.search_space.0, self.search_space.1);
                    }
                }
            }

            let a = 2.0 * (1.0 - iteration as f64 / self.max_iterations as f64);
            population.par_iter_mut().for_each(|whale| {
                self.update_whale_position(whale, &best_solution, a);
            });
        }

        best_solution
    }

    /// Initializes the whale population with random positions
    fn initialize_population(&self) -> Vec<Vec<f64>> {
        let mut rng = thread_rng();
        let mut population = Vec::with_capacity(self.population_size);
        
        for _ in 0..self.population_size {
            let solution: Vec<f64> = (0..self.dimension)
                .map(|_| {
                    rng.gen_range(self.search_space.0..=self.search_space.1)
                })
                .collect();
            population.push(solution);
        }
        population
    }

    /// Updates the position of a single whale based on WOA rules
    fn update_whale_position(&self, whale: &mut Vec<f64>, best: &[f64], a: f64) {
        let mut rng = rand::thread_rng();
        let r = rng.gen::<f64>();
        let b = rng.gen::<f64>();

        if r < 0.5 {
            // Exploitation phase
            if b < 0.5 {
                // Shrinking encircling
                for i in 0..self.dimension {
                    let l = rng.gen::<f64>();
                    whale[i] = best[i] - a * l;
                }
            } else {
                // Spiral update
                for i in 0..self.dimension {
                    let l = rng.gen::<f64>();
                    whale[i] = best[i] + l * (self.search_space.1 - self.search_space.0);
                }
            }
        } else {
            // Exploration phase
            // Use random whale position for exploration
            let _random_whale_idx = rng.gen_range(0..self.population_size);
            for i in 0..self.dimension {
                whale[i] += rng.gen_range(-1.0..=1.0) * a;
            }
        }

        // Ensure bounds
        for value in whale.iter_mut() {
            *value = value.clamp(self.search_space.0, self.search_space.1);
        }
    }

    /// Evaluates the strength of a potential key
    /// Returns a score where HIGHER values indicate WEAKER keys
    fn evaluate_key_strength(&self, key: &[f64]) -> f64 {
        let mut score = 0.0;
        
        // Check for patterns and repetition
        for window in key.windows(2) {
            if (window[0] - window[1]).abs() < 0.1 {
                score += 1.0;
            }
        }

        // Check entropy
        let mut histogram = vec![0.0; 256];
        for &value in key {
            let bucket = (value.abs() * 255.0) as usize;
            histogram[bucket.min(255)] += 1.0;
        }
        
        // Calculate normalized entropy
        let total: f64 = histogram.iter().sum();
        let entropy: f64 = histogram.iter()
            .filter(|&&count| count > 0.0)
            .map(|&count| {
                let p = count / total;
                -p * p.log2()
            })
            .sum();
        
        // Add entropy to score (lower entropy means weaker key)
        score += (8.0 - entropy).max(0.0);

        score
    }

    /// Implements PKCS7 padding for encryption
    fn pad_data(&self, data: &[u8]) -> Vec<u8> {
        let block_size = 16;
        let padding_len = block_size - (data.len() % block_size);
        let mut padded = data.to_vec();
        padded.extend(vec![padding_len as u8; padding_len]);
        padded
    }

    /// Removes PKCS7 padding after decryption
    fn unpad_data(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.is_empty() {
            return Err(CryptoError::DecryptionError("Empty data".to_string()));
        }

        let padding_len = *data.last().unwrap() as usize;
        if padding_len == 0 || padding_len > 16 {
            return Err(CryptoError::DecryptionError("Invalid padding length".to_string()));
        }

        let start = data.len().checked_sub(padding_len)
            .ok_or_else(|| CryptoError::DecryptionError("Invalid padding length".to_string()))?;

        if data[start..].iter().all(|&x| x == padding_len as u8) {
            Ok(data[..start].to_vec())
        } else {
            Err(CryptoError::DecryptionError("Invalid padding".to_string()))
        }
    }

    /// Sets the current key for encryption/decryption operations
    pub fn set_key(&mut self, key: Vec<u8>) {
        self.current_key = Some(key);
    }

    /// Optimized encryption block processing
    fn process_block(&self, block: &mut GenericArray<u8, U16>, cipher: &Aes256, encrypt: bool) {
        if encrypt {
            cipher.encrypt_block(block);
        } else {
            cipher.decrypt_block(block);
        }
    }

    /// Batch process multiple blocks in parallel
    fn process_blocks(&self, data: &[u8], cipher: &Aes256, encrypt: bool) -> Vec<u8> {
        let chunks: Vec<_> = data.chunks(16).collect();
        let result: Vec<GenericArray<u8, U16>> = chunks.par_iter()
            .map(|chunk| {
                let mut block = GenericArray::default();
                block[..chunk.len()].copy_from_slice(chunk);
                self.process_block(&mut block, cipher, encrypt);
                block
            })
            .collect();

        // Convert GenericArray to Vec<u8>
        result.into_iter()
            .flat_map(|block| block.to_vec())
            .collect()
    }

    /// Generates key bytes using the Whale Optimization Algorithm
    fn generate_key_bytes(&self) -> Result<Vec<u8>> {
        let seed: u64 = thread_rng().gen();
        let fitness_function = Arc::new(move |key: &[f64]| {
            let local_seed = seed.wrapping_add(
                key.iter().fold(0u64, |acc, &x| acc.wrapping_add((x * 1000.0) as u64))
            );
            let mut rng = StdRng::seed_from_u64(local_seed);
            
            let random_factor = rng.gen::<f64>() * 0.1;
            let strength = key.windows(2)
                .map(|w| if (w[0] - w[1]).abs() < 0.1 { 1.0 } else { 0.0 })
                .sum::<f64>();
            
            strength + random_factor
        });
        
        let optimal_solution = self.optimize(fitness_function);
        
        // Convert solutions to bytes
        let key: Vec<u8> = optimal_solution.par_iter()
            .enumerate()
            .map(|(i, &x)| {
                let mut rng = StdRng::seed_from_u64(seed.wrapping_add(i as u64));
                let random_offset = (rng.gen::<f64>() - 0.5) * 0.1;
                ((x + random_offset) * 255.0).abs() as u8
            })
            .collect();
        
        Ok(key)
    }
}

impl KeyGeneration for WbAES {
    /// Generates a cryptographic key using the Whale Optimization Algorithm
    fn generate_key() -> Result<Self> {
        let mut instance = WbAES::new(20, 50, 32);
        let key = instance.generate_key_bytes()?;
        instance.set_key(key);
        Ok(instance)
    }
}

impl Encryption for WbAES {
    /// Encrypts data using the current key with PKCS7 padding
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        let key = self.current_key.as_ref().ok_or_else(|| {
            CryptoError::EncryptionError("No key available".to_string())
        })?;

        let padded_data = self.pad_data(data);
        let cipher = Aes256::new(GenericArray::from_slice(key));
        
        Ok(self.process_blocks(&padded_data, &cipher, true))
    }

    /// Decrypts data and removes PKCS7 padding
    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() % 16 != 0 {
            return Err(CryptoError::DecryptionError(
                "Input length must be multiple of 16 bytes".to_string()
            ));
        }
        
        let key = self.current_key.as_ref().ok_or_else(|| {
            CryptoError::DecryptionError("No key available".to_string())
        })?;

        let cipher = Aes256::new(GenericArray::from_slice(key));
        let decrypted = self.process_blocks(data, &cipher, false);
        
        self.unpad_data(&decrypted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let wbaes = WbAES::generate_key().expect("Failed to generate key");
        assert_eq!(wbaes.current_key.as_ref().unwrap().len(), 32);
    }

    #[test]
    fn test_encryption_decryption() {
        let wbaes = WbAES::generate_key().expect("Failed to generate key");
        let test_data = b"Hello, World!";
        let encrypted = wbaes.encrypt(test_data).expect("Failed to encrypt");
        let decrypted = wbaes.decrypt(&encrypted).expect("Failed to decrypt");
        assert_eq!(decrypted, test_data);
    }

    #[test]
    fn test_key_strength() {
        let wbaes = WbAES::new(20, 50, 32);
        
        // Test with a weak key (all zeros)
        let weak_key: Vec<f64> = vec![0.0; 32];
        let weak_score = wbaes.evaluate_key_strength(&weak_key);
        
        // Test with a better key (random values)
        let mut rng = rand::thread_rng();
        let better_key: Vec<f64> = (0..32)
            .map(|_| rng.gen_range(-1.0..1.0))
            .collect();
        let better_score = wbaes.evaluate_key_strength(&better_key);
        
        assert!(better_score < weak_score, 
            "Better key score ({}) should be lower than weak key score ({})",
            better_score, weak_score);
    }

    #[test]
    fn test_padding() {
        let mut wbaes = WbAES::new(20, 50, 32);
        let key = wbaes.generate_key().unwrap();
        wbaes.set_key(key);

        // Test various input sizes
        let test_cases = vec![
            vec![1u8; 1],   // 1 byte
            vec![1u8; 15],  // 15 bytes (needs 1 byte padding)
            vec![1u8; 16],  // 16 bytes (needs full block padding)
            vec![1u8; 32],  // 32 bytes (needs full block padding)
        ];

        for original_data in test_cases {
            let encrypted = wbaes.encrypt(&original_data).unwrap();
            let decrypted = wbaes.decrypt(&encrypted).unwrap();
            
            assert_eq!(
                original_data, decrypted,
                "Padding test failed for input length {}:\nOriginal: {:?}\nDecrypted: {:?}",
                original_data.len(), original_data, decrypted
            );
        }
    }

    // Helper function to visualize padding (for debugging)
    #[allow(dead_code)]
    fn print_bytes(label: &str, data: &[u8]) {
        println!("{} (len={}): {:?}", label, data.len(), data);
    }
}
