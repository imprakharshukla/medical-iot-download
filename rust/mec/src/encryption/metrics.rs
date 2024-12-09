use std::time::Instant;
use super::CryptoError;

pub struct EncryptionMetrics {
    pub execution_time: std::time::Duration,
    pub throughput: f64,
    pub data_size: usize,
}

impl EncryptionMetrics {
    pub fn measure_encryption<F>(data_size: usize, encrypt_fn: F) -> Self 
    where 
        F: FnOnce() -> Result<Vec<u8>, CryptoError>
    {
        let start = Instant::now();
        let _result = encrypt_fn();
        let duration = start.elapsed();
        
        let throughput = data_size as f64 / duration.as_secs_f64();
        
        Self {
            execution_time: duration,
            throughput,
            data_size,
        }
    }
} 