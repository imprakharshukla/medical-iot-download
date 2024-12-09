use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use crypto_benchmarks::{
    algorithms::{
        wbaes::WbAES,
        aes_wrapper::AESWrapper,
    },
    Encryption,
    KeyGeneration,
};
use std::time::Duration;

fn quick_bench_key_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("Quick Key Generation");
    group.sample_size(10)
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(1));
    
    group.bench_function("WbAES", |b| {
        let wbaes = WbAES::new(20, 50, 32);
        b.iter(|| wbaes.generate_key().unwrap())
    });

    group.bench_function("AES-256", |b| {
        let aes = AESWrapper::new();
        b.iter(|| aes.generate_key().unwrap())
    });

    group.finish();
}

fn quick_bench_encryption(c: &mut Criterion) {
    let data_sizes = vec![32, 64];
    let mut group = c.benchmark_group("Quick Encryption");
    group.sample_size(10)
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(1));

    for size in data_sizes {
        let test_data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
        group.throughput(Throughput::Bytes(size as u64));

        // WbAES
        {
            let mut wbaes = WbAES::new(20, 50, 32);
            let key = wbaes.generate_key().unwrap();
            wbaes.set_key(key);
            group.bench_with_input(BenchmarkId::new("WbAES", size), &test_data, |b, data| {
                b.iter(|| wbaes.encrypt(data).unwrap())
            });
        }

        // AES
        {
            let mut aes = AESWrapper::new();
            let key = aes.generate_key().unwrap();
            aes.set_key(key);
            group.bench_with_input(BenchmarkId::new("AES-256", size), &test_data, |b, data| {
                b.iter(|| aes.encrypt(data).unwrap())
            });
        }
    }

    group.finish();
}

fn quick_bench_decryption(c: &mut Criterion) {
    let data_sizes = vec![32, 64];
    let mut group = c.benchmark_group("Quick Decryption");
    group.sample_size(10)
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(1));

    for size in data_sizes {
        // Create test data that's a multiple of the block size (16 bytes)
        let test_data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();

        // WbAES
        {
            let mut wbaes = WbAES::new(20, 50, 32);
            let key = wbaes.generate_key().unwrap();
            wbaes.set_key(key);
            // Ensure proper padding
            let padded_data = pad_pkcs7(&test_data, 16);
            let encrypted = wbaes.encrypt(&padded_data).unwrap();
            group.bench_with_input(BenchmarkId::new("WbAES", size), &encrypted, |b, data| {
                b.iter(|| {
                    let data = data.clone();
                    wbaes.decrypt(&data).unwrap()
                })
            });
        }

        // AES
        {
            let mut aes = AESWrapper::new();
            let key = aes.generate_key().unwrap();
            aes.set_key(key);
            let padded_data = pad_pkcs7(&test_data, 16);
            let encrypted = aes.encrypt(&padded_data).unwrap();
            group.bench_with_input(BenchmarkId::new("AES-256", size), &encrypted, |b, data| {
                b.iter(|| {
                    let data = data.clone();
                    aes.decrypt(&data).unwrap()
                })
            });
        }
    }

    group.finish();
}

// Helper function to apply PKCS7 padding
fn pad_pkcs7(data: &[u8], block_size: usize) -> Vec<u8> {
    let padding_len = block_size - (data.len() % block_size);
    let mut padded_data = data.to_vec();
    padded_data.extend(vec![padding_len as u8; padding_len]);
    padded_data
}

criterion_group!(
    name = quick_benches;
    config = Criterion::default()
        .without_plots()
        .sample_size(10);
    targets = quick_bench_key_generation, quick_bench_encryption, quick_bench_decryption
);

criterion_main!(quick_benches); 