use crate::encryption::error::EncryptionError;
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

const THRESHOLD: f64 = 0.75;

#[derive(Clone)]
pub struct WbAES {
    population_size: usize,
    max_iterations: usize,
    dimension: usize,
    search_space: (f64, f64),
    current_key: Option<Vec<u8>>,
}

impl WbAES {
    pub fn new(key: Vec<u8>) -> Result<Self, EncryptionError> {
        if key.len() != 32 {
            return Err(EncryptionError::InvalidKey(format!(
                "Key must be 32 bytes for AES-256, got {}", key.len()
            )));
        }

        let mut wbaes = WbAES {
            population_size: 20,
            max_iterations: 50,
            dimension: 32,
            search_space: (-1.0, 1.0),
            current_key: None,
        };
        wbaes.set_key(key);
        Ok(wbaes)
    }

    pub fn generate_key() -> Result<Self, EncryptionError> {
        let mut wbaes = WbAES {
            population_size: 20,
            max_iterations: 50,
            dimension: 32,
            search_space: (-1.0, 1.0),
            current_key: None,
        };
        
        let key = wbaes.generate_key_internal()?;
        if key.len() != 32 {
            return Err(EncryptionError::KeyGenerationError(
                "Generated key has incorrect length".to_string()
            ));
        }
        wbaes.set_key(key);
        Ok(wbaes)
    }

    fn generate_key_internal(&self) -> Result<Vec<u8>, EncryptionError> {
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
        
        let final_seed = seed.wrapping_add(
            optimal_solution.iter()
                .fold(0u64, |acc, &x| acc.wrapping_add((x * 1000.0) as u64))
        );
        
        Ok(optimal_solution.par_iter()
            .enumerate()
            .map(|(i, &x)| {
                let mut rng = StdRng::seed_from_u64(final_seed.wrapping_add(i as u64));
                let random_offset = (rng.gen::<f64>() - 0.5) * 0.1;
                ((x + random_offset) * 255.0).abs() as u8
            })
            .collect())
    }

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
            
            let fitness_fn = Arc::clone(&fitness_function);
            let fitness_values: Vec<f64> = population
                .par_iter()
                .map(|solution| {
                    let mut modified = solution.clone();
                    for val in &mut modified {
                        *val += (r - 0.5) * 0.1;
                        *val = (*val).max(self.search_space.0).min(self.search_space.1);
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
                        *val = (*val).max(self.search_space.0).min(self.search_space.1);
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

    fn initialize_population(&self) -> Vec<Vec<f64>> {
        let mut rng = thread_rng();
        let mut population = Vec::with_capacity(self.population_size);
        
        for _ in 0..self.population_size {
            let solution: Vec<f64> = (0..self.dimension)
                .map(|_| rng.gen_range(self.search_space.0..=self.search_space.1))
                .collect();
            population.push(solution);
        }
        population
    }

    fn update_whale_position(&self, whale: &mut Vec<f64>, best: &[f64], a: f64) {
        let mut rng = thread_rng();
        let r = rng.gen::<f64>();
        let b = rng.gen::<f64>();

        if r < 0.5 {
            if b < 0.5 {
                for i in 0..self.dimension {
                    let l = rng.gen::<f64>();
                    whale[i] = best[i] - a * l;
                }
            } else {
                for i in 0..self.dimension {
                    let l = rng.gen::<f64>();
                    whale[i] = best[i] + l * (self.search_space.1 - self.search_space.0);
                }
            }
        } else {
            let _random_whale_idx = rng.gen_range(0..self.population_size);
            for i in 0..self.dimension {
                whale[i] += rng.gen_range(-1.0..=1.0) * a;
            }
        }

        for value in whale.iter_mut() {
            *value = (*value).max(self.search_space.0).min(self.search_space.1);
        }
    }

    pub fn set_key(&mut self, key: Vec<u8>) {
        self.current_key = Some(key);
    }

    pub fn get_key(&self) -> Option<Vec<u8>> {
        self.current_key.clone()
    }

    fn pad_data(&self, data: &[u8]) -> Vec<u8> {
        let block_size = 16;
        let padding_len = block_size - (data.len() % block_size);
        let mut padded = data.to_vec();
        padded.extend(vec![padding_len as u8; padding_len]);
        padded
    }

    fn unpad_data(&self, data: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        if data.is_empty() {
            return Err(EncryptionError::DecryptionError("Empty data".to_string()));
        }

        let padding_len = *data.last().unwrap() as usize;
        if padding_len == 0 || padding_len > 16 {
            return Err(EncryptionError::DecryptionError("Invalid padding length".to_string()));
        }

        let start = data.len().checked_sub(padding_len)
            .ok_or_else(|| EncryptionError::DecryptionError("Invalid padding length".to_string()))?;

        if data[start..].iter().all(|&x| x == padding_len as u8) {
            Ok(data[..start].to_vec())
        } else {
            Err(EncryptionError::DecryptionError("Invalid padding".to_string()))
        }
    }

    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        let key = self.current_key.as_ref()
            .ok_or_else(|| EncryptionError::EncryptionError("No key available".to_string()))?;

        let block_size = 16;  // AES block size
        let padding_len = block_size - (data.len() % block_size);
        let mut padded_data = data.to_vec();
        padded_data.extend(vec![padding_len as u8; padding_len]);

        let cipher = Aes256::new(GenericArray::from_slice(key));
        
        Ok(self.process_blocks(&padded_data, &cipher, true))
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        if data.len() % 16 != 0 {
            return Err(EncryptionError::DecryptionError(
                "Input length must be multiple of 16 bytes".to_string()
            ));
        }
        
        let key = self.current_key.as_ref()
            .ok_or_else(|| EncryptionError::DecryptionError("No key available".to_string()))?;

        let cipher = Aes256::new(GenericArray::from_slice(key));
        let decrypted = self.process_blocks(data, &cipher, false);
        
        let padding_len = *decrypted.last().ok_or_else(|| 
            EncryptionError::DecryptionError("Empty decrypted data".to_string())
        )? as usize;

        if padding_len == 0 || padding_len > 16 {
            return Err(EncryptionError::DecryptionError("Invalid padding length".to_string()));
        }

        let start = decrypted.len().checked_sub(padding_len)
            .ok_or_else(|| EncryptionError::DecryptionError("Invalid padding length".to_string()))?;

        if !decrypted[start..].iter().all(|&x| x == padding_len as u8) {
            return Err(EncryptionError::DecryptionError("Invalid padding".to_string()));
        }

        Ok(decrypted[..start].to_vec())
    }

    fn process_blocks(&self, data: &[u8], cipher: &Aes256, encrypt: bool) -> Vec<u8> {
        let chunks: Vec<_> = data.chunks(16).collect();
        let result: Vec<GenericArray<u8, U16>> = chunks.par_iter()
            .map(|chunk| {
                let mut block = GenericArray::default();
                block[..chunk.len()].copy_from_slice(chunk);
                if encrypt {
                    cipher.encrypt_block(&mut block);
                } else {
                    cipher.decrypt_block(&mut block);
                }
                block
            })
            .collect();

        result.into_iter()
            .flat_map(|block| block.to_vec())
            .collect()
    }
} 