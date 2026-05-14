use std::{fs, path::PathBuf};

use homomorphic_encryption_analysis::{
    KEY_SIZE,
    classic_crypto::{
        HybridBatchCiphertexts, decrypt_measurements_hybrid_batch, encrypt_aes_gcm, encrypt_hybrid,
        encrypt_measurements_aes_gcm, encrypt_measurements_hybrid_batch,
        encrypt_measurements_rsa_oaep, encrypt_rsa_oaep, generate_aes256_key,
        generate_rsa_oaep_keys, measurement_to_bytes,
    },
    iot_energy::build_monthly_energy_readings,
    paillier_pure::PaillierKeys,
};
use num_bigint::BigUint;

const SCENARIO_RESIDENTS: usize = 20;
const SCENARIO_DAYS: usize = 5;
const SINGLE_MEASUREMENT: u64 = 8_750;

struct ReportRow<'a> {
    method: &'a str,
    single_plaintext_bytes: usize,
    single_ciphertext_bytes: usize,
    dataset_measurements: usize,
    dataset_ciphertext_bytes: usize,
}

fn comparison_keys() -> (rsa_ext::RsaPrivateKey, rsa_ext::RsaPublicKey, PaillierKeys) {
    let (private_key, public_key) = generate_rsa_oaep_keys(KEY_SIZE);
    let primes = private_key.primes();

    assert_eq!(primes.len(), 2);

    let paillier_keys = PaillierKeys::new(
        &BigUint::from_bytes_be(&primes[0].to_bytes_be()),
        &BigUint::from_bytes_be(&primes[1].to_bytes_be()),
    );

    (private_key, public_key, paillier_keys)
}

fn dataset_measurements() -> Vec<u64> {
    build_monthly_energy_readings(SCENARIO_RESIDENTS, SCENARIO_DAYS)
        .into_iter()
        .map(u64::from)
        .collect()
}

fn dataset_hybrid_len(batch: &HybridBatchCiphertexts) -> usize {
    batch.serialized_len()
}

fn rows() -> Vec<ReportRow<'static>> {
    let (private_key, public_key, paillier_keys) = comparison_keys();
    let dataset = dataset_measurements();
    let aes_key = generate_aes256_key();
    let payload = measurement_to_bytes(SINGLE_MEASUREMENT);

    let paillier_single = paillier_keys
        .encrypt_checked(BigUint::from(SINGLE_MEASUREMENT))
        .unwrap();
    let aes_single = encrypt_aes_gcm(&aes_key, &payload);
    let rsa_single = encrypt_rsa_oaep(&public_key, &payload);
    let hybrid_single = encrypt_hybrid(&public_key, &payload);

    let paillier_dataset: Vec<BigUint> = dataset
        .iter()
        .map(|measurement| {
            paillier_keys
                .encrypt_checked(BigUint::from(*measurement))
                .unwrap()
        })
        .collect();
    let aes_dataset = encrypt_measurements_aes_gcm(&aes_key, &dataset);
    let rsa_dataset = encrypt_measurements_rsa_oaep(&public_key, &dataset);
    let hybrid_dataset = encrypt_measurements_hybrid_batch(&public_key, &dataset);

    assert_eq!(
        decrypt_measurements_hybrid_batch(&private_key, &hybrid_dataset).len(),
        dataset.len()
    );

    vec![
        ReportRow {
            method: "Paillier",
            single_plaintext_bytes: payload.len(),
            single_ciphertext_bytes: paillier_keys
                .ciphertext_len_bytes()
                .max(paillier_single.to_bytes_be().len()),
            dataset_measurements: dataset.len(),
            dataset_ciphertext_bytes: paillier_dataset.len() * paillier_keys.ciphertext_len_bytes(),
        },
        ReportRow {
            method: "AES-GCM",
            single_plaintext_bytes: payload.len(),
            single_ciphertext_bytes: aes_single.serialized_len(),
            dataset_measurements: dataset.len(),
            dataset_ciphertext_bytes: aes_dataset
                .iter()
                .map(|ciphertext| ciphertext.serialized_len())
                .sum(),
        },
        ReportRow {
            method: "RSA-OAEP",
            single_plaintext_bytes: payload.len(),
            single_ciphertext_bytes: rsa_single.len(),
            dataset_measurements: dataset.len(),
            dataset_ciphertext_bytes: rsa_dataset.iter().map(Vec::len).sum(),
        },
        ReportRow {
            method: "Hybrid AES+RSA",
            single_plaintext_bytes: payload.len(),
            single_ciphertext_bytes: hybrid_single.serialized_len(),
            dataset_measurements: dataset.len(),
            dataset_ciphertext_bytes: dataset_hybrid_len(&hybrid_dataset),
        },
    ]
}

fn overhead_ratio(ciphertext_bytes: usize, plaintext_bytes: usize) -> f64 {
    ciphertext_bytes as f64 / plaintext_bytes as f64
}

fn print_markdown_table(rows: &[ReportRow<'_>]) {
    println!(
        "| Method | Plaintext bytes | Ciphertext bytes | Overhead | Dataset measurements | Dataset ciphertext bytes | Dataset overhead |"
    );
    println!("| --- | ---: | ---: | ---: | ---: | ---: | ---: |");

    for row in rows {
        let dataset_plaintext_bytes = row.single_plaintext_bytes * row.dataset_measurements;
        println!(
            "| {} | {} | {} | {:.3}x | {} | {} | {:.3}x |",
            row.method,
            row.single_plaintext_bytes,
            row.single_ciphertext_bytes,
            overhead_ratio(row.single_ciphertext_bytes, row.single_plaintext_bytes),
            row.dataset_measurements,
            row.dataset_ciphertext_bytes,
            overhead_ratio(row.dataset_ciphertext_bytes, dataset_plaintext_bytes),
        );
    }
}

fn write_csv(rows: &[ReportRow<'_>]) {
    let mut csv = String::from(
        "method,single_plaintext_bytes,single_ciphertext_bytes,single_overhead_ratio,dataset_measurements,dataset_ciphertext_bytes,dataset_overhead_ratio\n",
    );

    for row in rows {
        let dataset_plaintext_bytes = row.single_plaintext_bytes * row.dataset_measurements;
        csv.push_str(&format!(
            "{},{},{},{:.6},{},{},{:.6}\n",
            row.method,
            row.single_plaintext_bytes,
            row.single_ciphertext_bytes,
            overhead_ratio(row.single_ciphertext_bytes, row.single_plaintext_bytes),
            row.dataset_measurements,
            row.dataset_ciphertext_bytes,
            overhead_ratio(row.dataset_ciphertext_bytes, dataset_plaintext_bytes),
        ));
    }

    let results_dir = PathBuf::from("results");
    fs::create_dir_all(&results_dir).expect("failed to create results directory");
    fs::write(results_dir.join("comparison_methods.csv"), csv)
        .expect("failed to write comparison_methods.csv");
}

fn main() {
    let rows = rows();
    print_markdown_table(&rows);
    write_csv(&rows);
}
