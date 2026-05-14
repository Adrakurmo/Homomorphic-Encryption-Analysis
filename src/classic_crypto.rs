use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use rand::RngCore;
use rsa_ext::{PaddingScheme, PublicKey, RsaPrivateKey, RsaPublicKey};

pub const AES_KEY_BYTES: usize = 32;
pub const AES_NONCE_BYTES: usize = 12;
pub const COMPARISON_MEASUREMENT_BYTES: usize = 8;

#[derive(Debug, Clone)]
pub struct AesCiphertext {
    pub nonce: [u8; AES_NONCE_BYTES],
    pub ciphertext: Vec<u8>,
}

impl AesCiphertext {
    pub fn serialized_len(&self) -> usize {
        self.nonce.len() + self.ciphertext.len()
    }
}

#[derive(Debug, Clone)]
pub struct HybridCiphertext {
    pub encrypted_key: Vec<u8>,
    pub payload: AesCiphertext,
}

impl HybridCiphertext {
    pub fn serialized_len(&self) -> usize {
        self.encrypted_key.len() + self.payload.serialized_len()
    }
}

#[derive(Debug, Clone)]
pub struct HybridBatchCiphertexts {
    pub encrypted_key: Vec<u8>,
    pub payloads: Vec<AesCiphertext>,
}

impl HybridBatchCiphertexts {
    pub fn serialized_len(&self) -> usize {
        self.encrypted_key.len()
            + self
                .payloads
                .iter()
                .map(AesCiphertext::serialized_len)
                .sum::<usize>()
    }
}

pub fn generate_rsa_oaep_keys(bits: usize) -> (RsaPrivateKey, RsaPublicKey) {
    let mut rng = rand::thread_rng();
    let private_key =
        RsaPrivateKey::new(&mut rng, bits).expect("failed to generate RSA-OAEP comparison key");
    let public_key = RsaPublicKey::from(&private_key);

    (private_key, public_key)
}

pub fn generate_aes256_key() -> [u8; AES_KEY_BYTES] {
    let mut key = [0u8; AES_KEY_BYTES];
    rand::thread_rng().fill_bytes(&mut key);
    key
}

pub fn measurement_to_bytes(measurement: u64) -> [u8; COMPARISON_MEASUREMENT_BYTES] {
    measurement.to_be_bytes()
}

pub fn measurement_from_bytes(payload: &[u8]) -> u64 {
    let bytes: [u8; COMPARISON_MEASUREMENT_BYTES] = payload
        .try_into()
        .expect("comparison measurement payload must be exactly 8 bytes");
    u64::from_be_bytes(bytes)
}

pub fn encrypt_aes_gcm(key: &[u8; AES_KEY_BYTES], payload: &[u8]) -> AesCiphertext {
    let cipher = Aes256Gcm::new_from_slice(key).expect("AES-256 key must be 32 bytes");
    let mut nonce = [0u8; AES_NONCE_BYTES];
    rand::thread_rng().fill_bytes(&mut nonce);

    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), payload)
        .expect("AES-GCM encryption should succeed");

    AesCiphertext { nonce, ciphertext }
}

pub fn decrypt_aes_gcm(key: &[u8; AES_KEY_BYTES], ciphertext: &AesCiphertext) -> Vec<u8> {
    let cipher = Aes256Gcm::new_from_slice(key).expect("AES-256 key must be 32 bytes");
    cipher
        .decrypt(
            Nonce::from_slice(&ciphertext.nonce),
            ciphertext.ciphertext.as_ref(),
        )
        .expect("AES-GCM decryption should succeed")
}

pub fn encrypt_rsa_oaep(public_key: &RsaPublicKey, payload: &[u8]) -> Vec<u8> {
    let padding = PaddingScheme::new_oaep::<sha2::Sha256>();
    public_key
        .encrypt(&mut rand::thread_rng(), padding, payload)
        .expect("RSA-OAEP encryption should succeed")
}

pub fn decrypt_rsa_oaep(private_key: &RsaPrivateKey, ciphertext: &[u8]) -> Vec<u8> {
    let padding = PaddingScheme::new_oaep::<sha2::Sha256>();
    private_key
        .decrypt(padding, ciphertext)
        .expect("RSA-OAEP decryption should succeed")
}

pub fn encrypt_hybrid(public_key: &RsaPublicKey, payload: &[u8]) -> HybridCiphertext {
    let aes_key = generate_aes256_key();
    let encrypted_key = encrypt_rsa_oaep(public_key, &aes_key);
    let payload = encrypt_aes_gcm(&aes_key, payload);

    HybridCiphertext {
        encrypted_key,
        payload,
    }
}

pub fn decrypt_hybrid(private_key: &RsaPrivateKey, ciphertext: &HybridCiphertext) -> Vec<u8> {
    let aes_key = decrypt_rsa_oaep(private_key, &ciphertext.encrypted_key);
    let aes_key: [u8; AES_KEY_BYTES] = aes_key
        .try_into()
        .expect("hybrid AES key must decode to 32 bytes");

    decrypt_aes_gcm(&aes_key, &ciphertext.payload)
}

pub fn encrypt_measurements_aes_gcm(
    key: &[u8; AES_KEY_BYTES],
    measurements: &[u64],
) -> Vec<AesCiphertext> {
    measurements
        .iter()
        .map(|measurement| encrypt_aes_gcm(key, &measurement_to_bytes(*measurement)))
        .collect()
}

pub fn decrypt_measurements_aes_gcm(
    key: &[u8; AES_KEY_BYTES],
    ciphertexts: &[AesCiphertext],
) -> Vec<u64> {
    ciphertexts
        .iter()
        .map(|ciphertext| measurement_from_bytes(&decrypt_aes_gcm(key, ciphertext)))
        .collect()
}

pub fn encrypt_measurements_rsa_oaep(
    public_key: &RsaPublicKey,
    measurements: &[u64],
) -> Vec<Vec<u8>> {
    measurements
        .iter()
        .map(|measurement| encrypt_rsa_oaep(public_key, &measurement_to_bytes(*measurement)))
        .collect()
}

pub fn decrypt_measurements_rsa_oaep(
    private_key: &RsaPrivateKey,
    ciphertexts: &[Vec<u8>],
) -> Vec<u64> {
    ciphertexts
        .iter()
        .map(|ciphertext| measurement_from_bytes(&decrypt_rsa_oaep(private_key, ciphertext)))
        .collect()
}

pub fn encrypt_measurements_hybrid_batch(
    public_key: &RsaPublicKey,
    measurements: &[u64],
) -> HybridBatchCiphertexts {
    let aes_key = generate_aes256_key();
    let encrypted_key = encrypt_rsa_oaep(public_key, &aes_key);
    let payloads = measurements
        .iter()
        .map(|measurement| encrypt_aes_gcm(&aes_key, &measurement_to_bytes(*measurement)))
        .collect();

    HybridBatchCiphertexts {
        encrypted_key,
        payloads,
    }
}

pub fn decrypt_measurements_hybrid_batch(
    private_key: &RsaPrivateKey,
    ciphertexts: &HybridBatchCiphertexts,
) -> Vec<u64> {
    let aes_key = decrypt_rsa_oaep(private_key, &ciphertexts.encrypted_key);
    let aes_key: [u8; AES_KEY_BYTES] = aes_key
        .try_into()
        .expect("hybrid AES key must decode to 32 bytes");

    ciphertexts
        .payloads
        .iter()
        .map(|ciphertext| measurement_from_bytes(&decrypt_aes_gcm(&aes_key, ciphertext)))
        .collect()
}

pub fn sum_measurements(measurements: &[u64]) -> u64 {
    measurements.iter().sum()
}
