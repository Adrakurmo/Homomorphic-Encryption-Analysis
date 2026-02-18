use std::ops::Mul;

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

    pub fn encrypt <T: ToBigUint>(&self, data: T) -> BigUint {
        let m: BigUint = data.to_biguint();
        m.modpow(&self.e, &self.n)
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
