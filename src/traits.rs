use num_bigint::BigUint;

pub trait ToBigUint {
    fn to_biguint(&self) -> BigUint;
}

impl ToBigUint for BigUint {
    fn to_biguint(&self) -> BigUint {
        self.clone()
    }
}

impl ToBigUint for &[u8] {
    fn to_biguint(&self) -> BigUint {
        BigUint::from_bytes_be(&self)
    }
}