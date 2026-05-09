use std::{collections::BTreeMap, hint::black_box, time::Duration};

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use homomorphic_encryption_analysis::{
    KEY_SIZE,
    iot_energy::{
        SIMULATION_DAYS, TOTAL_MEASUREMENTS, TOWN_RESIDENTS, average_consumption_wh,
        build_default_monthly_energy_readings, decrypt_total_consumption, default_paillier_keys,
        encrypt_energy_reading, plaintext_total_consumption, sum_encrypted_readings,
    },
};
use num_bigint::BigUint;

fn build_benchmark_ciphertexts(
    keys: &homomorphic_encryption_analysis::paillier_pure::PaillierKeys,
    readings: &[u32],
) -> Vec<BigUint> {
    let mut templates = BTreeMap::new();

    for &reading_wh in readings {
        // Reuse one randomized ciphertext per plaintext bucket during benchmark setup so the measured
        // homomorphic aggregation still processes 150000 ciphertext slots without paying full encryption cost first.
        templates.entry(reading_wh).or_insert_with(|| {
            encrypt_energy_reading(keys, reading_wh)
                .expect("monthly IoT benchmark reading should fit into Paillier modulus")
        });
    }

    readings
        .iter()
        .map(|reading_wh| {
            templates
                .get(reading_wh)
                .expect("template ciphertext should exist")
                .clone()
        })
        .collect()
}

fn print_monthly_summary() {
    let keys = default_paillier_keys();
    let readings = build_default_monthly_energy_readings();
    let encrypted_measurements = build_benchmark_ciphertexts(&keys, &readings);
    let encrypted_total = sum_encrypted_readings(&keys, &encrypted_measurements);
    let decrypted_total = decrypt_total_consumption(&keys, &encrypted_total);
    let average_wh = average_consumption_wh(&decrypted_total, readings.len());
    let total_storage = readings.len() * keys.ciphertext_len_bytes();

    println!("Paillier IoT monthly aggregation summary:");
    println!("  residents: {TOWN_RESIDENTS}");
    println!("  days: {SIMULATION_DAYS}");
    println!("  measurements: {TOTAL_MEASUREMENTS}");
    println!(
        "  plaintext monthly total: {} Wh",
        plaintext_total_consumption(&readings)
    );
    println!("  decrypted monthly total: {} Wh", decrypted_total);
    println!("  average measurement: {:.2} Wh", average_wh);
    println!(
        "  ciphertext storage: {} bytes ({} bytes per measurement)",
        total_storage,
        keys.ciphertext_len_bytes()
    );
}

fn benchmark_single_measurement_encryption(c: &mut Criterion) {
    let keys = default_paillier_keys();

    c.bench_function("Paillier IoT/encrypt single measurement", |b| {
        b.iter(|| encrypt_energy_reading(black_box(&keys), black_box(8_750u32)).unwrap())
    });
}

fn benchmark_monthly_homomorphic_sum(c: &mut Criterion) {
    let keys = default_paillier_keys();
    let readings = build_default_monthly_energy_readings();
    let encrypted_measurements = build_benchmark_ciphertexts(&keys, &readings);
    let mut group = c.benchmark_group("Paillier IoT/homomorphic monthly sum");

    group.throughput(Throughput::Elements(TOTAL_MEASUREMENTS as u64));
    group.bench_function("150000 measurements", |b| {
        b.iter(|| sum_encrypted_readings(black_box(&keys), black_box(&encrypted_measurements)))
    });

    group.finish();
}

fn benchmark_monthly_total_decryption(c: &mut Criterion) {
    let keys = default_paillier_keys();
    let readings = build_default_monthly_energy_readings();
    let encrypted_measurements = build_benchmark_ciphertexts(&keys, &readings);
    let encrypted_total = sum_encrypted_readings(&keys, &encrypted_measurements);
    let mut group = c.benchmark_group("Paillier IoT/decrypt monthly total");

    group.throughput(Throughput::Elements(TOTAL_MEASUREMENTS as u64));
    group.bench_function("150000 measurements", |b| {
        b.iter(|| decrypt_total_consumption(black_box(&keys), black_box(&encrypted_total)))
    });

    group.finish();
}

fn iot_energy_benchmarks(c: &mut Criterion) {
    assert_eq!(KEY_SIZE, 2048);
    print_monthly_summary();
    benchmark_single_measurement_encryption(c);
    benchmark_monthly_homomorphic_sum(c);
    benchmark_monthly_total_decryption(c);
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
    targets = iot_energy_benchmarks
}
criterion_main!(benches);
