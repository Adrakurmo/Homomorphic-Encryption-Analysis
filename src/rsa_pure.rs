use std::{fmt, ops::Mul};

use base64::{Engine, prelude::BASE64_STANDARD};
use num_bigint::{BigUint};

use crate::{DEFAULT_E, traits::ToBigUint};

pub struct RsaKeys {
    pub p: BigUint,
    pub q: BigUint,
    pub n: BigUint,
    pub e: BigUint,
    pub d: BigUint,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RsaEncryptError {
    MessageTooLarge {
        message_bits: u64,
        modulus_bits: u64,
    },
}

impl fmt::Display for RsaEncryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MessageTooLarge {
                message_bits,
                modulus_bits,
            } => write!(
                f,
                "plaintext representative is too large for RSA modulus (message: {} bits, modulus: {} bits)",
                message_bits, modulus_bits
            ),
        }
    }
}

impl std::error::Error for RsaEncryptError {}

#[derive(Clone)]
pub struct Ciphertext {
    pub value: BigUint,
    pub n: BigUint
}

impl Ciphertext {
    pub fn new(_value: BigUint, _n: &BigUint) -> Self {
        Ciphertext { 
            value: _value, 
            n: _n.clone() 
        }
    }
}

impl Mul for Ciphertext {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self {
        Ciphertext { 
            value: (self.value * rhs.value) % &self.n, 
            n: self.n }
    }
}

impl Mul<&Ciphertext> for Ciphertext {
    type Output = Self;
    fn mul(self, rhs: &Ciphertext) -> Self::Output {
        Self {
            value: (self.value * &rhs.value) % &self.n,
            n: self.n,
        }
    }
}

impl RsaKeys {
    pub fn new(_p: BigUint, _q: BigUint) -> Self {
        // n = p * q
        let _n: BigUint = &_p * &_q;
        // const e
        let _e = BigUint::from(DEFAULT_E);
        // fi = (p - 1)(q - 1)
        let b_one = BigUint::from(1u8);
        let fi = (&_p - &b_one) * (&_q - &b_one);

        // d = e.modinv(fi)
        let _d = _e
            .modinv(&fi)
            .expect("Is 'e' and 'fi' coprime?");

        Self {
            p: _p,
            q: _q,
            n: _n,
            e: _e,
            d: _d
        }
    }

    pub fn modulus_len_bytes(&self) -> usize {
        self.n.to_bytes_be().len()
    }

    pub fn encrypt_checked<T: ToBigUint>(&self, data: T) -> Result<BigUint, RsaEncryptError> {
        let m: BigUint = data.to_biguint();
        if m >= self.n {
            return Err(RsaEncryptError::MessageTooLarge {
                message_bits: m.bits(),
                modulus_bits: self.n.bits(),
            });
        }

        Ok(m.modpow(&self.e, &self.n))
    }

    pub fn encrypt <T: ToBigUint>(&self, data: T) -> BigUint {
        self.encrypt_checked(data)
            .expect("plaintext representative must be smaller than RSA modulus")
    }

    pub fn decrypt(&self, enc_msg: &BigUint) -> BigUint {
        enc_msg.modpow(&self.d, &self.n)
    }
}


pub fn show_message_b64(msg: &BigUint, prefix: &str) {
    println!("{} {}",prefix.to_string(), BASE64_STANDARD.encode(msg.to_bytes_be()));
}

pub fn show_message(msg: &BigUint) {
    let bytes = msg.to_bytes_be();
    let text = String::from_utf8(bytes)
        .expect("Not valid plaintext :c");
    println!("PT: {}", text);
}

#[cfg(test)]
mod tests {
    use std::sync::OnceLock;

    use num_bigint::BigUint;
    use rand::thread_rng;
    use rsa_ext::RsaPrivateKey;

    use crate::KEY_SIZE;

    use super::{RsaEncryptError, RsaKeys};

    fn test_keys() -> &'static RsaKeys {
        static KEYS: OnceLock<RsaKeys> = OnceLock::new();

        KEYS.get_or_init(|| {
            let mut rng = thread_rng();
            let private_key = RsaPrivateKey::new(&mut rng, KEY_SIZE)
                .expect("failed to generate RSA key for tests");
            let primes = private_key.primes();

            assert_eq!(primes.len(), 2);

            RsaKeys::new(
                BigUint::from_bytes_be(&primes[0].to_bytes_be()),
                BigUint::from_bytes_be(&primes[1].to_bytes_be()),
            )
        })
    }

    fn serialize_ciphertext(ciphertext: &BigUint, modulus_len_bytes: usize) -> Vec<u8> {
        let mut bytes = ciphertext.to_bytes_be();
        if bytes.len() < modulus_len_bytes {
            let mut padded = vec![0u8; modulus_len_bytes - bytes.len()];
            padded.append(&mut bytes);
            return padded;
        }

        bytes
    }

    #[test]
    fn short_message_ciphertext_has_modulus_length() {
        let keys = test_keys();
        let ciphertext = keys.encrypt_checked(b"hello").unwrap();
        let serialized = serialize_ciphertext(&ciphertext, keys.modulus_len_bytes());

        assert_eq!(keys.modulus_len_bytes(), KEY_SIZE / 8);
        assert_eq!(serialized.len(), KEY_SIZE / 8);
    }

    #[test]
    fn near_maximum_message_ciphertext_has_modulus_length() {
        let keys = test_keys();
        let plaintext = &keys.n - BigUint::from(1u8);
        let ciphertext = keys.encrypt_checked(plaintext.clone()).unwrap();
        let serialized = serialize_ciphertext(&ciphertext, keys.modulus_len_bytes());

        assert_eq!(serialized.len(), KEY_SIZE / 8);
        assert_eq!(keys.decrypt(&ciphertext), plaintext);
    }

    #[test]
    fn too_long_message_is_rejected() {
        let keys = test_keys();
        let err = keys.encrypt_checked(keys.n.clone()).unwrap_err();

        assert_eq!(
            err,
            RsaEncryptError::MessageTooLarge {
                message_bits: keys.n.bits(),
                modulus_bits: keys.n.bits(),
            }
        );
    }
}
