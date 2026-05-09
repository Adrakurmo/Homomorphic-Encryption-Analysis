use std::{hint::black_box, time::Duration};

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use homomorphic_encryption_analysis::{
    KEY_SIZE,
    voting::{
        ciphertext_storage_bytes, decrypt_tally, default_paillier_keys, encrypt_vote,
        encrypt_votes, run_voting_simulation, sum_encrypted_votes,
    },
};

const VOTER_COUNTS: [usize; 4] = [10, 100, 1000, 10000];

fn build_votes(voter_count: usize) -> Vec<u8> {
    (0..voter_count)
        .map(|index| if index % 3 == 0 { 1 } else { 0 })
        .collect()
}

fn print_storage_summary() {
    let keys = default_paillier_keys();

    println!("Paillier voting ciphertext storage summary:");
    for voter_count in VOTER_COUNTS {
        let votes = build_votes(voter_count);
        let encrypted_votes = encrypt_votes(&keys, &votes).unwrap();
        let total_storage = ciphertext_storage_bytes(&keys, &encrypted_votes);

        println!(
            "  {voter_count} votes -> {} ciphertexts, {} bytes total ({} bytes per ciphertext)",
            encrypted_votes.len(),
            total_storage,
            keys.ciphertext_len_bytes()
        );
    }
}

fn benchmark_single_vote_encryption(c: &mut Criterion) {
    let keys = default_paillier_keys();

    c.bench_function("Paillier voting/encrypt single vote", |b| {
        b.iter(|| encrypt_vote(black_box(&keys), black_box(1u8)).unwrap())
    });
}

fn benchmark_homomorphic_sum(c: &mut Criterion) {
    let keys = default_paillier_keys();
    let mut group = c.benchmark_group("Paillier voting/homomorphic sum");

    for voter_count in VOTER_COUNTS {
        let votes = build_votes(voter_count);
        let encrypted_votes = encrypt_votes(&keys, &votes).unwrap();

        group.throughput(Throughput::Elements(voter_count as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(voter_count),
            &encrypted_votes,
            |b, encrypted_votes| {
                b.iter(|| sum_encrypted_votes(black_box(&keys), black_box(encrypted_votes)))
            },
        );
    }

    group.finish();
}

fn benchmark_result_decryption(c: &mut Criterion) {
    let keys = default_paillier_keys();
    let mut group = c.benchmark_group("Paillier voting/decrypt final tally");

    for voter_count in VOTER_COUNTS {
        let votes = build_votes(voter_count);
        let encrypted_votes = encrypt_votes(&keys, &votes).unwrap();
        let encrypted_tally = sum_encrypted_votes(&keys, &encrypted_votes);

        group.throughput(Throughput::Elements(voter_count as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(voter_count),
            &encrypted_tally,
            |b, encrypted_tally| {
                b.iter(|| decrypt_tally(black_box(&keys), black_box(encrypted_tally)))
            },
        );
    }

    group.finish();
}

fn benchmark_end_to_end_voting(c: &mut Criterion) {
    let keys = default_paillier_keys();
    let mut group = c.benchmark_group("Paillier voting/end to end");

    for voter_count in VOTER_COUNTS {
        let votes = build_votes(voter_count);

        group.throughput(Throughput::Elements(voter_count as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(voter_count),
            &votes,
            |b, votes| {
                b.iter(|| run_voting_simulation(black_box(&keys), black_box(votes)).unwrap())
            },
        );
    }

    group.finish();
}

fn voting_benchmarks(c: &mut Criterion) {
    assert_eq!(KEY_SIZE, 2048);
    print_storage_summary();
    benchmark_single_vote_encryption(c);
    benchmark_homomorphic_sum(c);
    benchmark_result_decryption(c);
    benchmark_end_to_end_voting(c);
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
    targets = voting_benchmarks
}
criterion_main!(benches);
