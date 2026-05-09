use std::sync::OnceLock;

use homomorphic_encryption_analysis::{
    KEY_SIZE,
    voting::{
        VotingError, ciphertext_storage_bytes, default_paillier_keys, plaintext_vote_sum,
        run_voting_simulation, serialize_ciphertext,
    },
};

fn test_keys() -> &'static homomorphic_encryption_analysis::paillier_pure::PaillierKeys {
    static KEYS: OnceLock<homomorphic_encryption_analysis::paillier_pure::PaillierKeys> =
        OnceLock::new();

    KEYS.get_or_init(default_paillier_keys)
}

#[test]
fn voting_simulation_counts_binary_votes_correctly() {
    let keys = test_keys();
    let votes = [1u8, 0, 1, 1, 0, 1, 0, 1];

    let result = run_voting_simulation(keys, &votes).unwrap();

    assert_eq!(result.decrypted_tally, plaintext_vote_sum(&votes).into());
    assert_eq!(result.encrypted_votes.len(), votes.len());
}

#[test]
fn voting_simulation_rejects_invalid_votes() {
    let keys = test_keys();
    let err = run_voting_simulation(keys, &[1u8, 2, 0]).unwrap_err();

    assert_eq!(err, VotingError::InvalidVote(2));
}

#[test]
fn voting_simulation_reports_expected_ciphertext_storage() {
    let keys = test_keys();
    let votes = [1u8, 0, 1, 0, 1];

    let result = run_voting_simulation(keys, &votes).unwrap();
    let total_storage = ciphertext_storage_bytes(keys, &result.encrypted_votes);
    let tally_storage = serialize_ciphertext(keys, &result.encrypted_tally).len();

    assert_eq!(keys.ciphertext_len_bytes(), KEY_SIZE / 4);
    assert_eq!(total_storage, votes.len() * (KEY_SIZE / 4));
    assert_eq!(tally_storage, KEY_SIZE / 4);
}
