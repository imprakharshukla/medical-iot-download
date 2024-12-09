use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
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

fn bench_key_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("Key Generation");
    
    // WbAES
    group.bench_function("WbAES", |b| {
        let wbaes = WbAES::new(30, 100, 32);
        b.iter(|| wbaes.generate_key())
    });

    // AES
    group.bench_function("AES-256", |b| {
        let aes = AESWrapper::new();
        b.iter(|| aes.generate_key())
    });

    // RSA
    group.bench_function("RSA-2048", |b| {
        let mut rsa = RSAWrapper::new();
        b.iter(|| {
            rsa.set_key(2048).unwrap();
            rsa.generate_key()
        })
    });

    // ECC
    group.bench_function("ECC-P256", |b| {
        let mut ecc = ECCWrapper::new();
        b.iter(|| {
            ecc.set_key().unwrap();
            ecc.generate_key()
        })
    });

    group.finish();
}

fn bench_encryption(c: &mut Criterion) {
    // Use sizes that are multiples of AES block size (16 bytes)
    let data_sizes = vec![32, 64, 128, 176]; // Changed 190 to 176 (11 * 16)
    let mut group = c.benchmark_group("Encryption");

    for size in data_sizes {
        let test_data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();

        // WbAES
        {
            let mut wbaes = WbAES::new(30, 100, 32);
            let key = wbaes.generate_key().unwrap();
            wbaes.set_key(key);
            group.bench_with_input(BenchmarkId::new("WbAES", size), &test_data, |b, data| {
                b.iter(|| wbaes.encrypt(black_box(data)))
            });
        }

        // AES
        {
            let mut aes = AESWrapper::new();
            let key = aes.generate_key().unwrap();
            aes.set_key(key);
            group.bench_with_input(BenchmarkId::new("AES-256", size), &test_data, |b, data| {
                b.iter(|| aes.encrypt(black_box(data)))
            });
        }

        // RSA
        {
            let mut rsa = RSAWrapper::new();
            rsa.set_key(2048).unwrap();
            group.bench_with_input(BenchmarkId::new("RSA-2048", size), &test_data, |b, data| {
                b.iter(|| rsa.encrypt(black_box(data)))
            });
        }

        // ECC
        {
            let mut ecc = ECCWrapper::new();
            ecc.set_key().unwrap();
            group.bench_with_input(BenchmarkId::new("ECC-P256", size), &test_data, |b, data| {
                b.iter(|| ecc.encrypt(black_box(data)))
            });
        }
    }

    group.finish();
}

fn bench_decryption(c: &mut Criterion) {
    // Use the same block-aligned sizes
    let data_sizes = vec![32, 64, 128, 176]; // Changed 190 to 176
    let mut group = c.benchmark_group("Decryption");

    for size in data_sizes {
        let test_data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();

        // WbAES
        {
            let mut wbaes = WbAES::new(30, 100, 32);
            let key = wbaes.generate_key().unwrap();
            wbaes.set_key(key);
            let encrypted = wbaes.encrypt(&test_data).unwrap();
            group.bench_with_input(BenchmarkId::new("WbAES", size), &encrypted, |b, data| {
                b.iter(|| wbaes.decrypt(black_box(data)))
            });
        }

        // AES
        {
            let mut aes = AESWrapper::new();
            let key = aes.generate_key().unwrap();
            aes.set_key(key);
            let encrypted = aes.encrypt(&test_data).unwrap();
            group.bench_with_input(BenchmarkId::new("AES-256", size), &encrypted, |b, data| {
                b.iter(|| aes.decrypt(black_box(data)))
            });
        }

        // RSA
        {
            let mut rsa = RSAWrapper::new();
            rsa.set_key(2048).unwrap();
            let encrypted = rsa.encrypt(&test_data).unwrap();
            group.bench_with_input(BenchmarkId::new("RSA-2048", size), &encrypted, |b, data| {
                b.iter(|| rsa.decrypt(black_box(data)))
            });
        }

        // ECC
        {
            let mut ecc = ECCWrapper::new();
            ecc.set_key().unwrap();
            let encrypted = ecc.encrypt(&test_data).unwrap();
            group.bench_with_input(BenchmarkId::new("ECC-P256", size), &encrypted, |b, data| {
                b.iter(|| ecc.decrypt(black_box(data)))
            });
        }
    }

    group.finish();
}

criterion_group!(benches, bench_key_generation, bench_encryption, bench_decryption);
criterion_main!(benches); 