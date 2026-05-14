pub mod classic_crypto;
pub mod iot_energy;
pub mod paillier_pure;
pub mod rsa_oaep;
pub mod rsa_pure;
pub mod traits;
pub mod voting;

pub const KEY_SIZE: usize = 2048;
pub const DEFAULT_E: u32 = 65537;
