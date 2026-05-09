use std::fmt;

use num_bigint::BigUint;
use num_traits::ToPrimitive;
use rsa_ext::RsaPrivateKey;

use crate::{
    KEY_SIZE,
    paillier_pure::{PaillierEncryptError, PaillierKeys},
};

pub const TOWN_RESIDENTS: usize = 5_000;
pub const SIMULATION_DAYS: usize = 30;
pub const TOTAL_MEASUREMENTS: usize = TOWN_RESIDENTS * SIMULATION_DAYS;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnergyAggregationError {
    Encryption(PaillierEncryptError),
}

impl fmt::Display for EnergyAggregationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encryption(err) => err.fmt(f),
        }
    }
}

impl std::error::Error for EnergyAggregationError {}

impl From<PaillierEncryptError> for EnergyAggregationError {
    fn from(value: PaillierEncryptError) -> Self {
        Self::Encryption(value)
    }
}

#[derive(Debug, Clone)]
pub struct EnergyAggregationResult {
    pub encrypted_measurements: Vec<BigUint>,
    pub encrypted_total: BigUint,
    pub decrypted_total: BigUint,
    pub average_consumption_wh: f64,
}

pub fn generate_paillier_keys(bits: usize) -> PaillierKeys {
    let mut rng = rand::thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, bits)
        .expect("failed to generate Paillier IoT aggregation key");
    let primes = private_key.primes();

    assert_eq!(primes.len(), 2);

    let p = BigUint::from_bytes_be(&primes[0].to_bytes_be());
    let q = BigUint::from_bytes_be(&primes[1].to_bytes_be());

    PaillierKeys::new(&p, &q)
}

pub fn default_paillier_keys() -> PaillierKeys {
    generate_paillier_keys(KEY_SIZE)
}

pub fn total_measurement_count(resident_count: usize, days: usize) -> usize {
    resident_count * days
}

fn deterministic_daily_consumption_wh(resident_index: usize, day_index: usize) -> u32 {
    let resident_band = (resident_index % 20) as u32 * 145;
    let weekly_band = (day_index % 7) as u32 * 210;
    let district_band = ((resident_index / 250) % 5) as u32 * 85;
    let occupancy_band = ((resident_index + day_index * 11) % 6) as u32 * 60;

    7_200 + resident_band + weekly_band + district_band + occupancy_band
}

pub fn build_monthly_energy_readings(resident_count: usize, days: usize) -> Vec<u32> {
    let mut readings = Vec::with_capacity(total_measurement_count(resident_count, days));

    for day_index in 0..days {
        for resident_index in 0..resident_count {
            readings.push(deterministic_daily_consumption_wh(
                resident_index,
                day_index,
            ));
        }
    }

    readings
}

pub fn build_default_monthly_energy_readings() -> Vec<u32> {
    build_monthly_energy_readings(TOWN_RESIDENTS, SIMULATION_DAYS)
}

pub fn encrypt_energy_reading(
    keys: &PaillierKeys,
    reading_wh: u32,
) -> Result<BigUint, EnergyAggregationError> {
    Ok(keys.encrypt_checked(BigUint::from(reading_wh))?)
}

pub fn encrypt_energy_readings(
    keys: &PaillierKeys,
    readings: &[u32],
) -> Result<Vec<BigUint>, EnergyAggregationError> {
    readings
        .iter()
        .copied()
        .map(|reading_wh| encrypt_energy_reading(keys, reading_wh))
        .collect()
}

pub fn sum_encrypted_readings(keys: &PaillierKeys, encrypted_readings: &[BigUint]) -> BigUint {
    encrypted_readings
        .iter()
        .fold(BigUint::from(1u8), |acc, ciphertext| {
            (acc * ciphertext) % &keys.n2
        })
}

pub fn decrypt_total_consumption(keys: &PaillierKeys, encrypted_total: &BigUint) -> BigUint {
    keys.decrypt(encrypted_total.clone())
}

pub fn serialize_ciphertext(keys: &PaillierKeys, ciphertext: &BigUint) -> Vec<u8> {
    let mut bytes = ciphertext.to_bytes_be();
    let target_len = keys.ciphertext_len_bytes();

    if bytes.len() < target_len {
        let mut padded = vec![0u8; target_len - bytes.len()];
        padded.append(&mut bytes);
        return padded;
    }

    bytes
}

pub fn ciphertext_storage_bytes(keys: &PaillierKeys, encrypted_readings: &[BigUint]) -> usize {
    encrypted_readings
        .iter()
        .map(|ciphertext| serialize_ciphertext(keys, ciphertext).len())
        .sum()
}

pub fn plaintext_total_consumption(readings: &[u32]) -> u64 {
    readings
        .iter()
        .map(|&reading_wh| u64::from(reading_wh))
        .sum()
}

pub fn average_consumption_wh(total_consumption_wh: &BigUint, measurement_count: usize) -> f64 {
    let total = total_consumption_wh
        .to_f64()
        .expect("monthly total consumption should fit into f64");
    total / measurement_count as f64
}

pub fn run_energy_aggregation_for_readings(
    keys: &PaillierKeys,
    readings: &[u32],
) -> Result<EnergyAggregationResult, EnergyAggregationError> {
    let encrypted_measurements = encrypt_energy_readings(keys, readings)?;
    let encrypted_total = sum_encrypted_readings(keys, &encrypted_measurements);
    let decrypted_total = decrypt_total_consumption(keys, &encrypted_total);
    let average_consumption_wh =
        average_consumption_wh(&decrypted_total, encrypted_measurements.len());

    Ok(EnergyAggregationResult {
        encrypted_measurements,
        encrypted_total,
        decrypted_total,
        average_consumption_wh,
    })
}

pub fn run_monthly_energy_aggregation(
    keys: &PaillierKeys,
    resident_count: usize,
    days: usize,
) -> Result<EnergyAggregationResult, EnergyAggregationError> {
    let readings = build_monthly_energy_readings(resident_count, days);
    run_energy_aggregation_for_readings(keys, &readings)
}
