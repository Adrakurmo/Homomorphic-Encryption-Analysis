use homomorphic_encryption_analysis::{
    KEY_SIZE,
    paillier_pure::PaillierKeys,
    rsa_pure::RsaKeys,
};
use num_bigint::BigUint;
use rand::thread_rng;
use rsa_ext::RsaPrivateKey;

const INPUT_SIZES: [usize; 4] = [1024, 10 * 1024, 100 * 1024, 1024 * 1024];

#[derive(Debug, Clone, PartialEq, Eq)]
struct OverheadRow {
    input_len: usize,
    chunk_size: usize,
    chunk_count: usize,
    ciphertext_len: usize,
}

fn generate_keys() -> (RsaKeys, PaillierKeys) {
    let mut rng = thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, KEY_SIZE)
        .expect("failed to generate RSA key for memory-overhead tests");
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

fn rsa_overhead_row(input_len: usize, keys: &RsaKeys) -> OverheadRow {
    let chunk_size = keys.modulus_len_bytes() - 1;
    let chunk_count = div_ceil(input_len, chunk_size);
    let ciphertext_len = chunk_count * keys.modulus_len_bytes();

    OverheadRow {
        input_len,
        chunk_size,
        chunk_count,
        ciphertext_len,
    }
}

fn paillier_overhead_row(input_len: usize, keys: &PaillierKeys) -> OverheadRow {
    let chunk_size = (KEY_SIZE - 8) / 8;
    let chunk_count = div_ceil(input_len, chunk_size);
    let ciphertext_len = chunk_count * keys.ciphertext_len_bytes();

    OverheadRow {
        input_len,
        chunk_size,
        chunk_count,
        ciphertext_len,
    }
}

fn left_pad(bytes: Vec<u8>, target_len: usize) -> Vec<u8> {
    if bytes.len() >= target_len {
        return bytes;
    }

    let mut padded = vec![0u8; target_len - bytes.len()];
    padded.extend(bytes);
    padded
}

#[test]
fn rsa_memory_overhead_matches_expected_sizes() {
    let (rsa_keys, _) = generate_keys();

    assert_eq!(rsa_keys.modulus_len_bytes(), KEY_SIZE / 8);

    for input_len in INPUT_SIZES {
        let row = rsa_overhead_row(input_len, &rsa_keys);
        let expected_chunks = div_ceil(input_len, (KEY_SIZE / 8) - 1);

        assert_eq!(row.chunk_size, (KEY_SIZE / 8) - 1);
        assert_eq!(row.chunk_count, expected_chunks);
        assert_eq!(row.ciphertext_len, expected_chunks * (KEY_SIZE / 8));
        assert!(row.ciphertext_len > row.input_len);
    }
}

#[test]
fn paillier_memory_overhead_matches_expected_sizes() {
    let (_, paillier_keys) = generate_keys();

    assert_eq!(paillier_keys.modulus_len_bytes(), KEY_SIZE / 8);
    assert_eq!(paillier_keys.ciphertext_len_bytes(), KEY_SIZE / 4);

    for input_len in INPUT_SIZES {
        let row = paillier_overhead_row(input_len, &paillier_keys);
        let expected_chunks = div_ceil(input_len, (KEY_SIZE - 8) / 8);

        assert_eq!(row.chunk_size, (KEY_SIZE - 8) / 8);
        assert_eq!(row.chunk_count, expected_chunks);
        assert_eq!(row.ciphertext_len, expected_chunks * (KEY_SIZE / 4));
        assert!(row.ciphertext_len > row.input_len);
    }
}

#[test]
fn serialized_single_block_lengths_match_algorithm_block_sizes() {
    let (rsa_keys, paillier_keys) = generate_keys();

    let rsa_ciphertext = rsa_keys.encrypt_checked(b"memory overhead").unwrap();
    let rsa_bytes = left_pad(rsa_ciphertext.to_bytes_be(), rsa_keys.modulus_len_bytes());
    assert_eq!(rsa_bytes.len(), KEY_SIZE / 8);

    let paillier_plaintext = BigUint::from_bytes_be(b"memory overhead");
    let paillier_ciphertext = paillier_keys.encrypt_checked(paillier_plaintext).unwrap();
    let paillier_bytes = left_pad(
        paillier_ciphertext.to_bytes_be(),
        paillier_keys.ciphertext_len_bytes(),
    );
    assert_eq!(paillier_bytes.len(), KEY_SIZE / 4);
}
