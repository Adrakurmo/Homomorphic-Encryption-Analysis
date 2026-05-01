use std::{fs, path::PathBuf};

use homomorphic_encryption_analysis::{
    KEY_SIZE,
    paillier_pure::PaillierKeys,
    rsa_pure::RsaKeys,
};
use num_bigint::BigUint;
use rand::thread_rng;
use rsa_ext::RsaPrivateKey;

const INPUT_SIZES: [usize; 4] = [1024, 10 * 1024, 100 * 1024, 1024 * 1024];

struct OverheadRow<'a> {
    algorithm: &'a str,
    input_len: usize,
    chunk_size: usize,
    chunk_count: usize,
    ciphertext_len: usize,
}

fn generate_keys() -> (RsaKeys, PaillierKeys) {
    let mut rng = thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, KEY_SIZE)
        .expect("failed to generate RSA key for memory-overhead report");
    let primes = private_key.primes();

    assert_eq!(primes.len(), 2);

    let p = BigUint::from_bytes_be(&primes[0].to_bytes_be());
    let q = BigUint::from_bytes_be(&primes[1].to_bytes_be());

    (
        RsaKeys::new(p.clone(), q.clone()),
        PaillierKeys::new(&p, &q),
    )
}

fn div_ceil(value: usize, divisor: usize) -> usize {
    value.div_ceil(divisor)
}

fn format_size(bytes: usize) -> String {
    match bytes {
        1024 => "1 KB".to_string(),
        10_240 => "10 KB".to_string(),
        102_400 => "100 KB".to_string(),
        1_048_576 => "1 MB".to_string(),
        _ => format!("{bytes} B"),
    }
}

fn overhead_ratio(ciphertext_len: usize, input_len: usize) -> f64 {
    ciphertext_len as f64 / input_len as f64
}

fn rsa_rows(keys: &RsaKeys) -> Vec<OverheadRow<'static>> {
    let chunk_size = keys.modulus_len_bytes() - 1;
    let ciphertext_block_size = keys.modulus_len_bytes();

    INPUT_SIZES
        .into_iter()
        .map(|input_len| {
            let chunk_count = div_ceil(input_len, chunk_size);
            OverheadRow {
                algorithm: "RSA",
                input_len,
                chunk_size,
                chunk_count,
                ciphertext_len: chunk_count * ciphertext_block_size,
            }
        })
        .collect()
}

fn paillier_rows(keys: &PaillierKeys) -> Vec<OverheadRow<'static>> {
    let chunk_size = (KEY_SIZE - 8) / 8;
    let ciphertext_block_size = keys.ciphertext_len_bytes();

    INPUT_SIZES
        .into_iter()
        .map(|input_len| {
            let chunk_count = div_ceil(input_len, chunk_size);
            OverheadRow {
                algorithm: "Paillier",
                input_len,
                chunk_size,
                chunk_count,
                ciphertext_len: chunk_count * ciphertext_block_size,
            }
        })
        .collect()
}

fn print_markdown_table(rows: &[OverheadRow<'_>]) {
    println!("| Algorytm | Wejscie | Rozmiar bloku PT | Liczba blokow | Szyfrogram | Narzut |");
    println!("| --- | ---: | ---: | ---: | ---: | ---: |");

    for row in rows {
        println!(
            "| {} | {} | {} B | {} | {} B | {:.3}x |",
            row.algorithm,
            format_size(row.input_len),
            row.chunk_size,
            row.chunk_count,
            row.ciphertext_len,
            overhead_ratio(row.ciphertext_len, row.input_len),
        );
    }
}

fn write_csv(rows: &[OverheadRow<'_>]) {
    let mut csv = String::from(
        "algorithm,input_bytes,input_label,plaintext_chunk_bytes,chunk_count,ciphertext_bytes,overhead_ratio\n",
    );

    for row in rows {
        csv.push_str(&format!(
            "{},{},{},{},{},{},{:.6}\n",
            row.algorithm,
            row.input_len,
            format_size(row.input_len),
            row.chunk_size,
            row.chunk_count,
            row.ciphertext_len,
            overhead_ratio(row.ciphertext_len, row.input_len),
        ));
    }

    let results_dir = PathBuf::from("results");
    fs::create_dir_all(&results_dir).expect("failed to create results directory");
    fs::write(results_dir.join("memory_overhead.csv"), csv)
        .expect("failed to write memory_overhead.csv");
}

fn main() {
    let (rsa_keys, paillier_keys) = generate_keys();
    let mut rows = rsa_rows(&rsa_keys);
    rows.extend(paillier_rows(&paillier_keys));

    print_markdown_table(&rows);
    write_csv(&rows);
}
