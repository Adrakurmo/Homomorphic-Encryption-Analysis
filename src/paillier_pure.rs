use std::fmt;

use num_bigint::{BigUint, RandBigInt};
use num_integer::Integer;
use rand::thread_rng;

use crate::{KEY_SIZE, traits::ToBigUint};

pub struct PaillierKeys {
    pub p: BigUint,
    pub q: BigUint,
    pub n: BigUint,
    pub n2: BigUint,
    pub lambda: BigUint,
    pub g: BigUint,
    pub mi: BigUint,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaillierEncryptError {
    MessageTooLarge {
        message_bits: u64,
        modulus_bits: u64,
    },
}

impl fmt::Display for PaillierEncryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MessageTooLarge {
                message_bits,
                modulus_bits,
            } => write!(
                f,
                "plaintext representative is too large for Paillier modulus (message: {} bits, modulus: {} bits)",
                message_bits, modulus_bits
            ),
        }
    }
}

impl std::error::Error for PaillierEncryptError {}

impl PaillierKeys {
    pub fn new(_p: &BigUint, _q: &BigUint) -> Self {
        let _n = _p * _q;
        let _n2 = &_n * &_n;
        let one = BigUint::from(1u8);
        let p1 = _p - &one;
        let q1 = _q - &one;
        let _lambda = p1.lcm(&q1);
        let _g = &_n + &one;
        let u = _g.modpow(&_lambda, &_n2);
        let l_u = (u - 1u32) / &_n;
        let _mi = l_u.modinv(&_n).unwrap();
        Self { 
            p: _p.clone(), 
            q: _q.clone(), 
            n: _n.clone(), 
            n2:_n2.clone(), 
            lambda: _lambda,
            g: _g,
            mi: _mi,
        }
    }

    pub fn modulus_len_bytes(&self) -> usize {
        self.n.to_bytes_be().len()
    }

    pub fn ciphertext_len_bytes(&self) -> usize {
        self.n2.to_bytes_be().len()
    }

    pub fn block_encrypt(&self, data: Vec<u8>) -> Vec<u8> {
        let mut calculated_chunks: Vec<Vec<u8>> = Vec::new();

        for chunk in data.chunks((KEY_SIZE - 8) / 8) {
            println!("{}", chunk.len());
            let r = get_coprime(&self.n, None); 
            let data_num = BigUint::from_bytes_be(chunk);
            let gm = self.g.modpow(&data_num, &self.n2);
            let rn = r.modpow(&self.n, &self.n2);
            let encrypted_chunk = (gm * rn) % &self.n2;
            let mut encrypted_bytes = encrypted_chunk.to_bytes_be();
            if encrypted_bytes.len() < (KEY_SIZE / 4) {
                let missing_zeros = (KEY_SIZE / 4) - encrypted_bytes.len();
                let mut padded = vec![0u8; missing_zeros];
                padded.append(&mut encrypted_bytes);
                encrypted_bytes = padded;
            }
            calculated_chunks.push(encrypted_bytes);
        }

        println!("{}", calculated_chunks.concat().len());
        calculated_chunks.concat()
    }

    pub fn block_decrypt(&self, data: Vec<u8>) -> Vec<u8> {
        let mut result: Vec<Vec<u8>> = Vec::new();
        for chunk in data.chunks((KEY_SIZE) / 4) {
            println!("{}", chunk.len());
            let data_num = BigUint::from_bytes_be(chunk);
            result.push((self.l(&data_num.modpow(&self.lambda, &self.n2)) * &self.mi % &self.n).to_bytes_be());
        }
        result.concat()
    }

    pub fn encrypt_checked<T: ToBigUint>(&self, data: T) -> Result<BigUint, PaillierEncryptError> {
        let data = data.to_biguint();
        if data >= self.n {
            return Err(PaillierEncryptError::MessageTooLarge {
                message_bits: data.bits(),
                modulus_bits: self.n.bits(),
            });
        }

        let r = get_coprime(&self.n, None); 
        // c = g^m * r^n mod n^2
        
        // g^m
        let gm = self.g.modpow(&data, &self.n2);
        // r^n mod n^2
        let rn = r.modpow(&self.n, &self.n2);

        Ok((gm * rn) % &self.n2)
    }

    pub fn encrypt(&self, data: BigUint) -> BigUint {
        self.encrypt_checked(data)
            .expect("plaintext representative must be smaller than Paillier modulus")
    }

    pub fn decrypt(&self, data: BigUint) -> BigUint {
        // m = L(c^lambda mod n^2) * mi mod n
        self.l(&data.modpow(&self.lambda, &self.n2)) * &self.mi % &self.n
    }

    // L(x)
    pub fn l(&self, x: &BigUint) -> BigUint {
        (x - 1u32) / &self.n
    }

}




fn get_coprime(xn: &BigUint, ct: Option<u8>) -> BigUint {
    let ct = ct.unwrap_or(64);
    let mut rng = thread_rng();
    let one = BigUint::from(1u8);
    let two = BigUint::from(2u8);
    
    for _ in 0..ct {
        let cand = rng.gen_biguint_range(&two,xn);
        let valid = cand.gcd(xn) == one;
        if valid {
            return cand
        }
    }

    panic!("we should have found coprime")
}

#[cfg(test)]
mod tests {
    use std::sync::OnceLock;

    use num_bigint::BigUint;
    use rand::thread_rng;
    use rsa_ext::RsaPrivateKey;

    use crate::KEY_SIZE;

    use super::{PaillierEncryptError, PaillierKeys};

    fn test_keys() -> &'static PaillierKeys {
        static KEYS: OnceLock<PaillierKeys> = OnceLock::new();

        KEYS.get_or_init(|| {
            let mut rng = thread_rng();
            let private_key = RsaPrivateKey::new(&mut rng, KEY_SIZE)
                .expect("failed to generate RSA key for tests");
            let primes = private_key.primes();

            assert_eq!(primes.len(), 2);

            PaillierKeys::new(
                &BigUint::from_bytes_be(&primes[0].to_bytes_be()),
                &BigUint::from_bytes_be(&primes[1].to_bytes_be()),
            )
        })
    }

    fn serialize_ciphertext(ciphertext: &BigUint, ciphertext_len_bytes: usize) -> Vec<u8> {
        let mut bytes = ciphertext.to_bytes_be();
        if bytes.len() < ciphertext_len_bytes {
            let mut padded = vec![0u8; ciphertext_len_bytes - bytes.len()];
            padded.append(&mut bytes);
            return padded;
        }

        bytes
    }

    #[test]
    fn small_value_ciphertext_has_n_squared_length() {
        let keys = test_keys();
        let ciphertext = keys.encrypt_checked(BigUint::from(42u8)).unwrap();
        let serialized = serialize_ciphertext(&ciphertext, keys.ciphertext_len_bytes());

        assert_eq!(keys.modulus_len_bytes(), KEY_SIZE / 8);
        assert_eq!(keys.ciphertext_len_bytes(), KEY_SIZE / 4);
        assert_eq!(serialized.len(), KEY_SIZE / 4);
    }

    #[test]
    fn near_modulus_value_ciphertext_has_n_squared_length() {
        let keys = test_keys();
        let plaintext = &keys.n - BigUint::from(1u8);
        let ciphertext = keys.encrypt_checked(plaintext.clone()).unwrap();
        let serialized = serialize_ciphertext(&ciphertext, keys.ciphertext_len_bytes());

        assert_eq!(serialized.len(), KEY_SIZE / 4);
        assert_eq!(keys.decrypt(ciphertext), plaintext);
    }

    #[test]
    fn value_greater_than_or_equal_to_n_is_rejected() {
        let keys = test_keys();
        let err = keys.encrypt_checked(keys.n.clone()).unwrap_err();

        assert_eq!(
            err,
            PaillierEncryptError::MessageTooLarge {
                message_bits: keys.n.bits(),
                modulus_bits: keys.n.bits(),
            }
        );
    }

    #[test]
    fn homomorphic_paillier_operation_preserves_ciphertext_length() {
        let keys = test_keys();
        let a = BigUint::from(10u8);
        let b = BigUint::from(20u8);

        let enc_a = keys.encrypt_checked(a.clone()).unwrap();
        let enc_b = keys.encrypt_checked(b.clone()).unwrap();
        let combined = (&enc_a * &enc_b) % &keys.n2;

        let enc_a_bytes = serialize_ciphertext(&enc_a, keys.ciphertext_len_bytes());
        let enc_b_bytes = serialize_ciphertext(&enc_b, keys.ciphertext_len_bytes());
        let combined_bytes = serialize_ciphertext(&combined, keys.ciphertext_len_bytes());

        assert_eq!(enc_a_bytes.len(), KEY_SIZE / 4);
        assert_eq!(enc_b_bytes.len(), KEY_SIZE / 4);
        assert_eq!(combined_bytes.len(), KEY_SIZE / 4);
        assert_eq!(keys.decrypt(combined), a + b);
    }
}
