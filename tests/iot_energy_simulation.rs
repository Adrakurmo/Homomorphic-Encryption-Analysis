use std::sync::OnceLock;

use num_bigint::BigUint;

use homomorphic_encryption_analysis::{
    KEY_SIZE,
    iot_energy::{
        SIMULATION_DAYS, TOTAL_MEASUREMENTS, TOWN_RESIDENTS, average_consumption_wh,
        build_default_monthly_energy_readings, build_monthly_energy_readings,
        ciphertext_storage_bytes, default_paillier_keys, plaintext_total_consumption,
        run_energy_aggregation_for_readings, serialize_ciphertext, total_measurement_count,
    },
};

fn test_keys() -> &'static homomorphic_encryption_analysis::paillier_pure::PaillierKeys {
    static KEYS: OnceLock<homomorphic_encryption_analysis::paillier_pure::PaillierKeys> =
        OnceLock::new();

    KEYS.get_or_init(default_paillier_keys)
}

#[test]
fn default_iot_energy_dataset_has_expected_size_and_variation() {
    let readings = build_default_monthly_energy_readings();

    assert_eq!(
        total_measurement_count(TOWN_RESIDENTS, SIMULATION_DAYS),
        TOTAL_MEASUREMENTS
    );
    assert_eq!(readings.len(), TOTAL_MEASUREMENTS);
    assert_ne!(readings[0], readings[1]);
    assert_ne!(readings[0], readings[TOWN_RESIDENTS]);
}

#[test]
fn energy_aggregation_recovers_total_and_average() {
    let keys = test_keys();
    let readings = build_monthly_energy_readings(8, 4);

    let result = run_energy_aggregation_for_readings(keys, &readings).unwrap();
    let expected_total = plaintext_total_consumption(&readings);
    let expected_average = expected_total as f64 / readings.len() as f64;

    assert_eq!(result.decrypted_total, BigUint::from(expected_total));
    assert_eq!(result.encrypted_measurements.len(), readings.len());
    assert_eq!(
        result.average_consumption_wh,
        average_consumption_wh(&BigUint::from(expected_total), readings.len())
    );
    assert_eq!(result.average_consumption_wh, expected_average);
}

#[test]
fn energy_aggregation_reports_expected_ciphertext_storage() {
    let keys = test_keys();
    let readings = build_monthly_energy_readings(5, 3);

    let result = run_energy_aggregation_for_readings(keys, &readings).unwrap();
    let total_storage = ciphertext_storage_bytes(keys, &result.encrypted_measurements);
    let aggregate_storage = serialize_ciphertext(keys, &result.encrypted_total).len();

    assert_eq!(keys.ciphertext_len_bytes(), KEY_SIZE / 4);
    assert_eq!(total_storage, readings.len() * (KEY_SIZE / 4));
    assert_eq!(aggregate_storage, KEY_SIZE / 4);
}
