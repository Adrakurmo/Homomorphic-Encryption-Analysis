use num_bigint::{BigUint, RandBigInt};
use num_integer::Integer;
use rand::thread_rng;

pub struct PaillierKeys {
    pub p: BigUint,
    pub q: BigUint,
    pub n: BigUint,
    pub n2: BigUint,
    pub lambda: BigUint,
    pub g: BigUint,
    pub mi: BigUint,
}

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

    pub fn encrypt(&self, data: BigUint) -> BigUint {
        let r = get_coprime(&self.n, None); 
        // c = g^m * r^n mod n^2
        
        // g^m
        let gm = self.g.modpow(&data, &self.n2);
        // r^n mod n^2
        let rn = r.modpow(&self.n, &self.n2);

        (gm * rn) % &self.n2
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