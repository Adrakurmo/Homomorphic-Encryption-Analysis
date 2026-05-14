use std::hint::black_box;
use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};
use homomorphic_encryption_analysis::{
    KEY_SIZE,
    classic_crypto::{
        decrypt_aes_gcm, decrypt_hybrid, decrypt_measurements_aes_gcm,
        decrypt_measurements_hybrid_batch, decrypt_measurements_rsa_oaep, decrypt_rsa_oaep,
        encrypt_aes_gcm, encrypt_hybrid, encrypt_measurements_aes_gcm,
        encrypt_measurements_hybrid_batch, encrypt_measurements_rsa_oaep, encrypt_rsa_oaep,
        generate_aes256_key, generate_rsa_oaep_keys, measurement_to_bytes, sum_measurements,
    },
    iot_energy::build_monthly_energy_readings,
    paillier_pure::PaillierKeys,
};
use num_bigint::BigUint;

const SCENARIO_RESIDENTS: usize = 20;
const SCENARIO_DAYS: usize = 5;
const SCENARIO_MEASUREMENT: u64 = 8_750;

struct ComparisonContext {
    rsa_private_key: rsa_ext::RsaPrivateKey,
    rsa_public_key: rsa_ext::RsaPublicKey,
    paillier_keys: PaillierKeys,
    aes_key: [u8; 32],
    measurements: Vec<u64>,
}

fn comparison_context() -> ComparisonContext {
    let (rsa_private_key, rsa_public_key) = generate_rsa_oaep_keys(KEY_SIZE);
    let primes = rsa_private_key.primes();

    assert_eq!(primes.len(), 2);

    let paillier_keys = PaillierKeys::new(
        &BigUint::from_bytes_be(&primes[0].to_bytes_be()),
        &BigUint::from_bytes_be(&primes[1].to_bytes_be()),
    );
    let aes_key = generate_aes256_key();
    let measurements = build_monthly_energy_readings(SCENARIO_RESIDENTS, SCENARIO_DAYS)
        .into_iter()
        .map(u64::from)
        .collect();

    ComparisonContext {
        rsa_private_key,
        rsa_public_key,
        paillier_keys,
        aes_key,
        measurements,
    }
}

fn benchmark_encryption_time(c: &mut Criterion) {
    let context = comparison_context();
    let payload = measurement_to_bytes(SCENARIO_MEASUREMENT);
    let mut group = c.benchmark_group("Comparison/encryption time");

    group.bench_function("Paillier", |b| {
        b.iter(|| {
            context
                .paillier_keys
                .encrypt_checked(BigUint::from(black_box(SCENARIO_MEASUREMENT)))
                .unwrap()
        })
    });

    group.bench_function("AES-GCM", |b| {
        b.iter(|| encrypt_aes_gcm(black_box(&context.aes_key), black_box(&payload)))
    });

    group.bench_function("RSA-OAEP", |b| {
        b.iter(|| encrypt_rsa_oaep(black_box(&context.rsa_public_key), black_box(&payload)))
    });

    group.bench_function("Hybrid AES+RSA", |b| {
        b.iter(|| encrypt_hybrid(black_box(&context.rsa_public_key), black_box(&payload)))
    });

    group.finish();
}

fn benchmark_decryption_time(c: &mut Criterion) {
    let context = comparison_context();
    let payload = measurement_to_bytes(SCENARIO_MEASUREMENT);
    let paillier_ciphertext = context
        .paillier_keys
        .encrypt_checked(BigUint::from(SCENARIO_MEASUREMENT))
        .unwrap();
    let aes_ciphertext = encrypt_aes_gcm(&context.aes_key, &payload);
    let rsa_ciphertext = encrypt_rsa_oaep(&context.rsa_public_key, &payload);
    let hybrid_ciphertext = encrypt_hybrid(&context.rsa_public_key, &payload);
    let mut group = c.benchmark_group("Comparison/decryption time");

    group.bench_function("Paillier", |b| {
        b.iter(|| {
            context
                .paillier_keys
                .decrypt(black_box(paillier_ciphertext.clone()))
        })
    });

    group.bench_function("AES-GCM", |b| {
        b.iter(|| decrypt_aes_gcm(black_box(&context.aes_key), black_box(&aes_ciphertext)))
    });

    group.bench_function("RSA-OAEP", |b| {
        b.iter(|| {
            decrypt_rsa_oaep(
                black_box(&context.rsa_private_key),
                black_box(&rsa_ciphertext),
            )
        })
    });

    group.bench_function("Hybrid AES+RSA", |b| {
        b.iter(|| {
            decrypt_hybrid(
                black_box(&context.rsa_private_key),
                black_box(&hybrid_ciphertext),
            )
        })
    });

    group.finish();
}

fn benchmark_encrypted_data_operations(c: &mut Criterion) {
    let context = comparison_context();
    let paillier_ciphertexts: Vec<BigUint> = context
        .measurements
        .iter()
        .map(|measurement| {
            context
                .paillier_keys
                .encrypt_checked(BigUint::from(*measurement))
                .unwrap()
        })
        .collect();
    let aes_ciphertexts = encrypt_measurements_aes_gcm(&context.aes_key, &context.measurements);
    let rsa_ciphertexts =
        encrypt_measurements_rsa_oaep(&context.rsa_public_key, &context.measurements);
    let hybrid_ciphertexts =
        encrypt_measurements_hybrid_batch(&context.rsa_public_key, &context.measurements);
    let mut group = c.benchmark_group("Comparison/operations on encrypted data");

    group.bench_function("Paillier homomorphic sum", |b| {
        b.iter(|| {
            paillier_ciphertexts
                .iter()
                .fold(BigUint::from(1u8), |acc, ciphertext| {
                    (acc * ciphertext) % &context.paillier_keys.n2
                })
        })
    });

    group.bench_function("AES-GCM decrypt then sum", |b| {
        b.iter(|| {
            sum_measurements(&decrypt_measurements_aes_gcm(
                black_box(&context.aes_key),
                black_box(&aes_ciphertexts),
            ))
        })
    });

    group.bench_function("RSA-OAEP decrypt then sum", |b| {
        b.iter(|| {
            sum_measurements(&decrypt_measurements_rsa_oaep(
                black_box(&context.rsa_private_key),
                black_box(&rsa_ciphertexts),
            ))
        })
    });

    group.bench_function("Hybrid AES+RSA decrypt then sum", |b| {
        b.iter(|| {
            sum_measurements(&decrypt_measurements_hybrid_batch(
                black_box(&context.rsa_private_key),
                black_box(&hybrid_ciphertexts),
            ))
        })
    });

    group.finish();
}

fn benchmark_simplified_application_scenario(c: &mut Criterion) {
    let context = comparison_context();
    let mut group = c.benchmark_group("Comparison/simplified application scenario");

    group.bench_function("Paillier energy total", |b| {
        b.iter(|| {
            let encrypted_measurements: Vec<BigUint> = context
                .measurements
                .iter()
                .map(|measurement| {
                    context
                        .paillier_keys
                        .encrypt_checked(BigUint::from(*measurement))
                        .unwrap()
                })
                .collect();

            let encrypted_total = encrypted_measurements
                .iter()
                .fold(BigUint::from(1u8), |acc, ciphertext| {
                    (acc * ciphertext) % &context.paillier_keys.n2
                });

            context.paillier_keys.decrypt(encrypted_total)
        })
    });

    group.bench_function("AES-GCM energy total", |b| {
        b.iter(|| {
            let ciphertexts = encrypt_measurements_aes_gcm(
                black_box(&context.aes_key),
                black_box(&context.measurements),
            );
            sum_measurements(&decrypt_measurements_aes_gcm(
                black_box(&context.aes_key),
                black_box(&ciphertexts),
            ))
        })
    });

    group.bench_function("RSA-OAEP energy total", |b| {
        b.iter(|| {
            let ciphertexts = encrypt_measurements_rsa_oaep(
                black_box(&context.rsa_public_key),
                black_box(&context.measurements),
            );
            sum_measurements(&decrypt_measurements_rsa_oaep(
                black_box(&context.rsa_private_key),
                black_box(&ciphertexts),
            ))
        })
    });

    group.bench_function("Hybrid AES+RSA energy total", |b| {
        b.iter(|| {
            let ciphertexts = encrypt_measurements_hybrid_batch(
                black_box(&context.rsa_public_key),
                black_box(&context.measurements),
            );
            sum_measurements(&decrypt_measurements_hybrid_batch(
                black_box(&context.rsa_private_key),
                black_box(&ciphertexts),
            ))
        })
    });

    group.finish();
}

fn comparison_benchmarks(c: &mut Criterion) {
    benchmark_encryption_time(c);
    benchmark_decryption_time(c);
    benchmark_encrypted_data_operations(c);
    benchmark_simplified_application_scenario(c);
}

fn criterion_config() -> Criterion {
    Criterion::default()
        .sample_size(10)
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(1))
}

criterion_group! {
    name = benches;
    config = criterion_config();
    targets = comparison_benchmarks
}
criterion_main!(benches);
