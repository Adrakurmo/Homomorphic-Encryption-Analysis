use homomorphic_encryption_analysis::{KEY_SIZE, paillier_pure::PaillierKeys, rsa_pure::{RsaKeys}};
use num_bigint::BigUint;
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
    let m1 = BigUint::from(2u8);
    let m2 = BigUint::from(33u8);
    let encrypted = _paillier_keys.encrypt(m1);
    let encrypted_2 = _paillier_keys.encrypt(m2);
    let connected = encrypted * encrypted_2;
    println!("ENC: {}", connected);
    let decrypted = _paillier_keys.decrypt(connected);
    println!("DEC: {}", decrypted); 

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
}



