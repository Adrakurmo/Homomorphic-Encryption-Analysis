use base64::{Engine, prelude::BASE64_STANDARD};
use homomorphic_encryption_analysis::{KEY_SIZE, paillier_pure::PaillierKeys, rsa_pure::RsaKeys, voting::{ciphertext_storage_bytes, default_paillier_keys, plaintext_vote_sum, run_voting_simulation}};
use num_bigint::BigUint;
use rand::RngCore;
use rsa_ext::{RsaPrivateKey};


fn main() {

    
    // ################################################################################################################
    // # KEY GEN
    // ################################################################################################################
    let mut rng = rand::thread_rng();
    let bits = KEY_SIZE;

    let private_key = RsaPrivateKey::new(&mut rng, bits)
        .expect("Failed to generate RSA key");
    // let public_key = RsaPublicKey::from(&private_key);

    let primes = private_key.primes();
    assert_eq!(primes.len(), 2);
    let p_bytes = primes[0].to_bytes_be();
    let q_bytes = primes[1].to_bytes_be();

    // PURE RSA KEYS
    let _pure_keys = RsaKeys::new(
        BigUint::from_bytes_be(&p_bytes).clone(), 
        BigUint::from_bytes_be(&q_bytes).clone()
    );

    // PURE PAILLIER KEYS
    let _paillier_keys = PaillierKeys::new(
        &BigUint::from_bytes_be(&p_bytes), 
        &BigUint::from_bytes_be(&q_bytes)
    );
    // ################################################################################################################
    // # TESTING
    // ################################################################################################################
    // RSA
    


    // let m1 = BigUint::from(2u8);
    // let m2 = BigUint::from(3u8);

    // let ct1 = Ciphertext::new(pure_keys.encrypt(m1), &pure_keys.n);
    // let ct2 = Ciphertext::new(pure_keys.encrypt(m2), &pure_keys.n);

    // let result = ct1.value * ct2.value;

    // // println!("{}", ct.value);
    // println!("{}", pure_keys.decrypt(&result));

    // PAILLIER
    // let m1 = BigUint::from(2u8);
    // let m2 = BigUint::from(33u8);
    // let mut m2000_1 = vec![0u8; 1024*1024];    // 2000 bits
    // rng.fill_bytes(&mut m2000_1);
    
    // let num_1 = BigUint::from_bytes_be(&m2000_1);
    // println!("BAS: {}\n", BASE64_STANDARD.encode(&m2000_1));
    // let encrypted = _paillier_keys.block_encrypt(m2000_1.clone());
    // println!("PAILLIER ENC: {}\n", BASE64_STANDARD.encode(&encrypted));
    // let decrypted = _paillier_keys.block_decrypt(encrypted);
    // println!("PAILLIER DEC: {}\n", BASE64_STANDARD.encode(&decrypted));
    // println!();
    // println!("{}\n\n", BigUint::from_bytes_be(&m2000_1));
    // println!("{}", BigUint::from_bytes_be(&decrypted));
    // let ecnrypted_2 = _pure_keys.encrypt(num_1.clone());
    // println!("RSA ENC: {}\n", ecnrypted_2);
    // let decrypted_2 = _pure_keys.decrypt(&ecnrypted_2);
    // println!("RSA DEC: {}\n", decrypted_2);





    // let encrypted = _paillier_keys.encrypt(m1);
    // let encrypted_2 = _paillier_keys.encrypt(m2);
    // let connected = encrypted * encrypted_2;
    // println!("ENC: {}", connected);
    // let decrypted = _paillier_keys.decrypt(connected);
    // println!("DEC: {}", decrypted); 

    // let to_encrypt = b"Hello world!";
    // println!("PTX: {}", BASE64_STANDARD.encode(&to_encrypt[..]));
    // let encrypted_msg = pure_keys.encrypt(&to_encrypt[..]);
    // show_message_b64(&encrypted_msg, "ENC:");
    // let decypted_msg = pure_keys.decrypt(&encrypted_msg);
    // show_message_b64(&decypted_msg, "DEC:");
    // show_message(&decypted_msg);

    // let data = b"hello world";
    // let padding = PaddingScheme::new_oaep::<sha2::Sha256>();
    // let enc_data = public_key.encrypt(&mut rng, padding, &data[..]).expect("Failed to encrypt");

    // println!("{}",BASE64_STANDARD.encode(&enc_data));

    // let padding = PaddingScheme::new_oaep::<sha2::Sha256>();
    // let dec_data = private_key.decrypt(padding, &enc_data).expect("bla bla");

    // println!("{}", String::from_utf8(dec_data).expect("ds"));
    // let private_pem = private_key
    //     .to_pkcs1_pem(LineEnding::CRLF) // LF jest bardziej uniwersalne (Linux/Unix)
    //     .expect("Couldn't convert private key to pem");

    // let public_pem = public_key
    //     .to_pkcs1_pem(LineEnding::CRLF)
    //     .expect("Couldn't convert public key to pem");

    // println!("{}", *private_pem);
    // println!("{}", public_pem);

    let keys = default_paillier_keys();

    let votes: Vec<u8> = (0..100)
        .map(|index| if index % 3 == 0 { 1 } else { 0 })
        .collect();

    let result = run_voting_simulation(&keys, &votes).unwrap();
    let expected_tally = plaintext_vote_sum(&votes);
    let storage_bytes = ciphertext_storage_bytes(&keys, &result.encrypted_votes);

    println!("Voting simulation for 100 voters");
    println!("Votes count: {}", votes.len());
    println!("Expected tally: {}", expected_tally);
    println!("Decrypted tally: {}", result.decrypted_tally);
    println!("Encrypted votes stored: {}", result.encrypted_votes.len());
    println!("Ciphertext size per vote: {} bytes", keys.ciphertext_len_bytes());
    println!("Total ciphertext storage: {} bytes", storage_bytes);
    println!("Encrypted tally (bits): {}", result.encrypted_tally.bits());
    println!("First 5 votes: {:?}", &votes[..5]);
}



