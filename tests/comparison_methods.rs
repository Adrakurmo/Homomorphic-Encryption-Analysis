use num_bigint::BigUint;

use homomorphic_encryption_analysis::{
    KEY_SIZE,
    classic_crypto::{
        COMPARISON_MEASUREMENT_BYTES, decrypt_hybrid, decrypt_measurements_aes_gcm,
        decrypt_measurements_hybrid_batch, decrypt_measurements_rsa_oaep, encrypt_aes_gcm,
        encrypt_hybrid, encrypt_measurements_aes_gcm, encrypt_measurements_hybrid_batch,
        encrypt_measurements_rsa_oaep, encrypt_rsa_oaep, generate_aes256_key,
        generate_rsa_oaep_keys, measurement_to_bytes, sum_measurements,
    },
    iot_energy::build_monthly_energy_readings,
    paillier_pure::PaillierKeys,
};

fn comparison_measurements() -> Vec<u64> {
    build_monthly_energy_readings(20, 5)
        .into_iter()
        .map(u64::from)
        .collect()
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

#[test]
fn classical_methods_round_trip_single_measurement() {
    let (private_key, public_key, _) = comparison_keys();
    let aes_key = generate_aes256_key();
    let payload = measurement_to_bytes(8_750u64);

    let aes_ciphertext = encrypt_aes_gcm(&aes_key, &payload);
    let rsa_ciphertext = encrypt_rsa_oaep(&public_key, &payload);
    let hybrid_ciphertext = encrypt_hybrid(&public_key, &payload);

    assert_eq!(
        homomorphic_encryption_analysis::classic_crypto::decrypt_aes_gcm(&aes_key, &aes_ciphertext),
        payload
    );
    assert_eq!(
        homomorphic_encryption_analysis::classic_crypto::decrypt_rsa_oaep(
            &private_key,
            &rsa_ciphertext
        ),
        payload
    );
    assert_eq!(decrypt_hybrid(&private_key, &hybrid_ciphertext), payload);
    assert_eq!(payload.len(), COMPARISON_MEASUREMENT_BYTES);
}

#[test]
fn simplified_aggregation_matches_plaintext_total_for_all_methods() {
    let (private_key, public_key, paillier_keys) = comparison_keys();
    let measurements = comparison_measurements();
    let expected_total = sum_measurements(&measurements);

    let paillier_ciphertexts: Vec<BigUint> = measurements
        .iter()
        .map(|measurement| {
            paillier_keys
                .encrypt_checked(BigUint::from(*measurement))
                .unwrap()
        })
        .collect();
    let paillier_total = paillier_ciphertexts
        .iter()
        .fold(BigUint::from(1u8), |acc, ciphertext| {
            (acc * ciphertext) % &paillier_keys.n2
        });

    let aes_key = generate_aes256_key();
    let aes_ciphertexts = encrypt_measurements_aes_gcm(&aes_key, &measurements);
    let rsa_ciphertexts = encrypt_measurements_rsa_oaep(&public_key, &measurements);
    let hybrid_ciphertexts = encrypt_measurements_hybrid_batch(&public_key, &measurements);

    assert_eq!(
        paillier_keys.decrypt(paillier_total),
        BigUint::from(expected_total)
    );
    assert_eq!(
        sum_measurements(&decrypt_measurements_aes_gcm(&aes_key, &aes_ciphertexts)),
        expected_total
    );
    assert_eq!(
        sum_measurements(&decrypt_measurements_rsa_oaep(
            &private_key,
            &rsa_ciphertexts
        )),
        expected_total
    );
    assert_eq!(
        sum_measurements(&decrypt_measurements_hybrid_batch(
            &private_key,
            &hybrid_ciphertexts
        )),
        expected_total
    );
}
