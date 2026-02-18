use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use homomorphic_encryption_analysis::{KEY_SIZE, paillier_pure::PaillierKeys, rsa_pure::{Ciphertext, RsaKeys}};
use num_bigint::BigUint;
use rsa_ext::RsaPrivateKey;

fn _native_rsa(keys: &RsaKeys) -> BigUint {
    let start = BigUint::from(1u8);
    let mut result: BigUint = BigUint::from(1u8);
    let mut ciphertext = keys.encrypt(start);
    for i in 0..100u32 - 1  {
        let mut plaintext = keys.decrypt(&ciphertext);
        plaintext *= BigUint::from(i + 1u32);  // RIP FOR ++i++ ...
        result = plaintext.clone();
        ciphertext = keys.encrypt(plaintext);
    }
    result
}

fn homomorphic_rsa(keys: &RsaKeys, precomputed_cts: &Vec<Ciphertext>) -> BigUint {
    let mut c1 = precomputed_cts.get(0).unwrap().clone();

    for ct in precomputed_cts.iter() {
        c1 = c1 * ct;
    }

    let decrypted = keys.decrypt(&c1.value);
    // println!("RSA: {}", decrypted);
    decrypted
}

fn homomorphic_paillier(keys: &PaillierKeys, precomputed_cts: &Vec<BigUint>) -> BigUint {
    let mut c1 = precomputed_cts.get(0).unwrap().clone();
    for ct in precomputed_cts.iter() {
        c1 = c1 * ct;
    }
    let decrypted = keys.decrypt(c1);
    // println!("PAILLIER: {}", decrypted);
    decrypted 
    
}

fn get_ciphertexts(keys: &RsaKeys) -> Vec<Ciphertext> {
    let mut result: Vec<Ciphertext> = vec![];
    let c1 = Ciphertext::new(
        keys.encrypt(BigUint::from(1u8)),
        &keys.n
    );
    result.push(c1);
    

    for i in 0..100u32 - 1 {
        let c2 = Ciphertext::new(
            keys.encrypt(BigUint::from(i + 1u32)), 
            &keys.n
        );
        result.push(c2);
    }

    result
}

fn get_ciphertexts_paillier(keys: &PaillierKeys) -> Vec<BigUint> {
    let mut res: Vec<BigUint> = vec![];
    for i in 0..100u32 - 1 {
        res.push(keys.encrypt(BigUint::from(i + 1u32)));
    }
    res
}

fn criterion_benchmark(c: &mut Criterion) {
    // Creating random key of const size
    let mut rng = rand::thread_rng();
    let bits = KEY_SIZE;

    let private_key = RsaPrivateKey::new(&mut rng, bits)
        .expect("Failed to generate RSA key");

    let primes = private_key.primes();
    assert_eq!(primes.len(), 2);
    let p_bytes = primes[0].to_bytes_be();
    let q_bytes = primes[1].to_bytes_be();

    // For HE I am using my native RSA implementation, though key gen
    // is borrowd from ext_rsa
    let rsa_pure_keys = RsaKeys::new(
        BigUint::from_bytes_be(&p_bytes).clone(), 
        BigUint::from_bytes_be(&q_bytes).clone()
    );

    let paillier_pure_keys = PaillierKeys::new(
        &BigUint::from_bytes_be(&p_bytes),
        &BigUint::from_bytes_be(&q_bytes)
    );

    let cts_he_rsa = get_ciphertexts(&rsa_pure_keys);
    let cts_he_paillier = get_ciphertexts_paillier(&paillier_pure_keys);

    let mut group = c.benchmark_group("Encryption time Comparison");

    // group.bench_function("Native RSA", |b| {
    //     b.iter(|| native_rsa(black_box(&rsa_pure_keys)))
    // });

    group.bench_function("Homomorphic Paillier", |b| {
        b.iter(|| homomorphic_paillier(black_box(&paillier_pure_keys), black_box(&cts_he_paillier)))
    });

    group.bench_function("Homomorphic RSA", |b| {
        b.iter(|| homomorphic_rsa(black_box(&rsa_pure_keys),black_box( &cts_he_rsa)))
    });

    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);