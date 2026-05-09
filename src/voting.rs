use std::fmt;

use num_bigint::BigUint;
use rsa_ext::RsaPrivateKey;

use crate::{
    KEY_SIZE,
    paillier_pure::{PaillierEncryptError, PaillierKeys},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VotingError {
    InvalidVote(u8),
    Encryption(PaillierEncryptError),
}

impl fmt::Display for VotingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidVote(vote) => write!(f, "vote must be binary (0 or 1), got {vote}"),
            Self::Encryption(err) => err.fmt(f),
        }
    }
}

impl std::error::Error for VotingError {}

impl From<PaillierEncryptError> for VotingError {
    fn from(value: PaillierEncryptError) -> Self {
        Self::Encryption(value)
    }
}

#[derive(Debug, Clone)]
pub struct VotingSimulationResult {
    pub encrypted_votes: Vec<BigUint>,
    pub encrypted_tally: BigUint,
    pub decrypted_tally: BigUint,
}

pub fn generate_paillier_keys(bits: usize) -> PaillierKeys {
    let mut rng = rand::thread_rng();
    let private_key =
        RsaPrivateKey::new(&mut rng, bits).expect("failed to generate Paillier simulation key");
    let primes = private_key.primes();

    assert_eq!(primes.len(), 2);

    let p = BigUint::from_bytes_be(&primes[0].to_bytes_be());
    let q = BigUint::from_bytes_be(&primes[1].to_bytes_be());

    PaillierKeys::new(&p, &q)
}

pub fn validate_vote(vote: u8) -> Result<(), VotingError> {
    match vote {
        0 | 1 => Ok(()),
        _ => Err(VotingError::InvalidVote(vote)),
    }
}

pub fn encrypt_vote(keys: &PaillierKeys, vote: u8) -> Result<BigUint, VotingError> {
    validate_vote(vote)?;
    Ok(keys.encrypt_checked(BigUint::from(vote))?)
}

pub fn encrypt_votes(keys: &PaillierKeys, votes: &[u8]) -> Result<Vec<BigUint>, VotingError> {
    votes
        .iter()
        .copied()
        .map(|vote| encrypt_vote(keys, vote))
        .collect()
}

pub fn sum_encrypted_votes(keys: &PaillierKeys, encrypted_votes: &[BigUint]) -> BigUint {
    encrypted_votes
        .iter()
        .fold(BigUint::from(1u8), |acc, ciphertext| {
            (acc * ciphertext) % &keys.n2
        })
}

pub fn decrypt_tally(keys: &PaillierKeys, encrypted_tally: &BigUint) -> BigUint {
    keys.decrypt(encrypted_tally.clone())
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

pub fn ciphertext_storage_bytes(keys: &PaillierKeys, encrypted_votes: &[BigUint]) -> usize {
    encrypted_votes
        .iter()
        .map(|ciphertext| serialize_ciphertext(keys, ciphertext).len())
        .sum()
}

pub fn plaintext_vote_sum(votes: &[u8]) -> u64 {
    votes.iter().map(|&vote| u64::from(vote)).sum()
}

pub fn run_voting_simulation(
    keys: &PaillierKeys,
    votes: &[u8],
) -> Result<VotingSimulationResult, VotingError> {
    let encrypted_votes = encrypt_votes(keys, votes)?;
    let encrypted_tally = sum_encrypted_votes(keys, &encrypted_votes);
    let decrypted_tally = decrypt_tally(keys, &encrypted_tally);

    Ok(VotingSimulationResult {
        encrypted_votes,
        encrypted_tally,
        decrypted_tally,
    })
}

pub fn default_paillier_keys() -> PaillierKeys {
    generate_paillier_keys(KEY_SIZE)
}
