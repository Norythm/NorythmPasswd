use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, AesGcm,
};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine as _;
use ed25519_dalek::{Signature, VerifyingKey};
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use sha2::{Digest, Sha256};
use typenum::U16;
use zeroize::Zeroizing;

type Aes256Gcm16 = AesGcm<aes::Aes256, U16, U16>;

const SECURITY_PEPPER: &str = "MasterVault_Security_Pepper_2026";
pub const VAULT_VERSION_V2: u8 = 0x02;

pub const PUBLIC_KEY_BYTES: [u8; 32] = [
    0x16, 0xee, 0xb0, 0x5b, 0x50, 0x1a, 0x19, 0x3e, 0x7e, 0x40, 0x05, 0xf3, 0xdb, 0x4a, 0x31, 0x9d,
    0xa0, 0xcb, 0xb5, 0x96, 0xc6, 0x1b, 0x07, 0x20, 0xb4, 0x38, 0x09, 0x36, 0x75, 0x79, 0xff, 0x02,
];

pub const PBKDF2_ITERATIONS: u32 = 100_000;
pub const KEY_LEN: usize = 32;
pub const SALT_LEN: usize = 16;
pub const IV_LEN: usize = 16;
pub const TAG_LEN: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    InvalidKeyLength(usize),
    InvalidDataLength(usize),
    EncryptionFailed,
    DecryptionFailed,
    Argon2Error(String),
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidKeyLength(n) => write!(f, "invalid key length: {n} (expected {KEY_LEN})"),
            Self::InvalidDataLength(n) => write!(f, "data too short: {n} bytes"),
            Self::EncryptionFailed => write!(f, "encryption failed"),
            Self::DecryptionFailed => write!(f, "decryption failed"),
            Self::Argon2Error(e) => write!(f, "argon2 error: {e}"),
        }
    }
}

impl std::error::Error for CryptoError {}

impl From<argon2::Error> for CryptoError {
    fn from(e: argon2::Error) -> Self {
        CryptoError::Argon2Error(e.to_string())
    }
}

pub fn verify_license_key(key: &str) -> Option<String> {
    let (payload_b64, sig_b64) = key.split_once('.')?;
    let payload = base64::engine::general_purpose::STANDARD
        .decode(payload_b64.trim())
        .ok()?;
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(sig_b64.trim())
        .ok()?;
    if sig_bytes.len() != 64 {
        return None;
    }
    let sig_array: [u8; 64] = sig_bytes.as_slice().try_into().ok()?;
    let signature = Signature::from_bytes(&sig_array);
    let verifying_key = VerifyingKey::from_bytes(&PUBLIC_KEY_BYTES).ok()?;
    verifying_key.verify_strict(&payload, &signature).ok()?;
    String::from_utf8(payload).ok()
}

pub fn sign_license_key_ed25519(
    private_key_hex: &str,
    payload: &str,
) -> Result<String, String> {
    use ed25519_dalek::{Signer, SigningKey};

    let priv_bytes = hex::decode(private_key_hex.trim()).map_err(|e| format!("Invalid hex: {e}"))?;
    let key_bytes: [u8; 32] = priv_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "Private key must be 32 bytes".to_string())?;
    let signing_key = SigningKey::from_bytes(&key_bytes);
    let sig = signing_key.sign(payload.as_bytes());
    let payload_b64 = base64::engine::general_purpose::STANDARD.encode(payload);
    let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());
    Ok(format!("{payload_b64}.{sig_b64}"))
}

fn normalize_argon2_salt(salt: &[u8]) -> Vec<u8> {
    if salt.len() >= 8 {
        salt.to_vec()
    } else {
        let mut hasher = Sha256::new();
        hasher.update(b"MasterPasswd_Argon2_Salt_Pad:");
        hasher.update(salt);
        hasher.finalize().to_vec()
    }
}

pub fn derive_key_argon2id(password: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    let norm_salt = normalize_argon2_salt(salt);
    let params = Params::new(65536, 3, 4, Some(32))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    argon
        .hash_password_into(password, &norm_salt, key.as_mut())
        .map_err(|e| CryptoError::Argon2Error(e.to_string()))?;
    Ok(key)
}

pub fn derive_key_pbkdf2(password: &[u8], salt: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    pbkdf2_hmac::<Sha256>(password, salt, PBKDF2_ITERATIONS, key.as_mut());
    key
}

pub fn derive_key(password: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    derive_key_argon2id(password, salt)
}

pub fn generate_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

pub fn encrypt_vault_data(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if key.len() != KEY_LEN {
        return Err(CryptoError::InvalidKeyLength(key.len()));
    }
    let mut iv = [0u8; IV_LEN];
    rand::thread_rng().fill_bytes(&mut iv);

    let cipher = Aes256Gcm16::new_from_slice(key).map_err(|_| CryptoError::InvalidKeyLength(key.len()))?;
    let ct_and_tag = cipher
        .encrypt(aes_gcm::Nonce::<U16>::from_slice(&iv), plaintext)
        .map_err(|_| CryptoError::EncryptionFailed)?;
    let (ct, tag) = ct_and_tag.split_at(ct_and_tag.len() - TAG_LEN);

    let mut out = Vec::with_capacity(1 + IV_LEN + TAG_LEN + ct.len());
    out.push(VAULT_VERSION_V2);
    out.extend_from_slice(&iv);
    out.extend_from_slice(tag);
    out.extend_from_slice(ct);
    Ok(out)
}

pub fn decrypt_vault_data(key: &[u8], data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if key.len() != KEY_LEN {
        return Err(CryptoError::InvalidKeyLength(key.len()));
    }
    let raw = if data.first() == Some(&VAULT_VERSION_V2) {
        &data[1..]
    } else {
        data
    };

    if raw.len() < IV_LEN + TAG_LEN {
        return Err(CryptoError::InvalidDataLength(raw.len()));
    }
    let iv = &raw[..IV_LEN];
    let tag = &raw[IV_LEN..IV_LEN + TAG_LEN];
    let ct = &raw[IV_LEN + TAG_LEN..];

    let mut payload = Vec::with_capacity(ct.len() + TAG_LEN);
    payload.extend_from_slice(ct);
    payload.extend_from_slice(tag);

    let cipher = Aes256Gcm16::new_from_slice(key).map_err(|_| CryptoError::InvalidKeyLength(key.len()))?;
    cipher
        .decrypt(aes_gcm::Nonce::<U16>::from_slice(iv), payload.as_ref())
        .map_err(|_| CryptoError::DecryptionFailed)
}

pub fn decrypt_vault_dual_kdf(
    password: &[u8],
    salt: &[u8],
    data: &[u8],
) -> Result<(Vec<u8>, Zeroizing<[u8; KEY_LEN]>, bool), CryptoError> {
    if data.first() == Some(&VAULT_VERSION_V2) {
        let argon_key = derive_key_argon2id(password, salt)?;
        let plain = decrypt_vault_data(argon_key.as_ref(), data)?;
        Ok((plain, argon_key, false))
    } else {
        let pbkdf2_key = derive_key_pbkdf2(password, salt);
        if let Ok(plain) = decrypt_vault_data(pbkdf2_key.as_ref(), data) {
            let target_argon_key = derive_key_argon2id(password, salt)?;
            return Ok((plain, target_argon_key, true));
        }

        let argon_key = derive_key_argon2id(password, salt)?;
        if let Ok(plain) = decrypt_vault_data(argon_key.as_ref(), data) {
            return Ok((plain, argon_key, true));
        }

        Err(CryptoError::DecryptionFailed)
    }
}

pub fn decode_sys_config(b64: &str) -> Option<serde_json::Value> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .ok()?;
    if raw.len() >= 28 {
        let (iv, rest) = raw.split_at(12);
        let (tag, ct) = rest.split_at(16);
        let pepper = Sha256::digest(SECURITY_PEPPER.as_bytes());
        if let Ok(cipher) = Aes256Gcm::new_from_slice(&pepper) {
            let mut payload = Vec::with_capacity(ct.len() + tag.len());
            payload.extend_from_slice(ct);
            payload.extend_from_slice(tag);
            if let Ok(plain) = cipher.decrypt(aes_gcm::Nonce::from_slice(iv), payload.as_ref()) {
                return serde_json::from_slice(&plain).ok();
            }
        }
    }
    serde_json::from_slice(&raw).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_mock_string() {
        let key = derive_key(b"correct horse battery staple", b"some-salt-value").expect("derive");
        let plaintext = b"{\"vault\": {\"example\": \"secret-data-123\"}}";
        let enc = encrypt_vault_data(key.as_ref(), plaintext).expect("encrypt");
        assert_eq!(enc[0], VAULT_VERSION_V2);
        assert_eq!(enc.len(), 1 + IV_LEN + TAG_LEN + plaintext.len());
        let dec = decrypt_vault_data(key.as_ref(), &enc).expect("decrypt");
        assert_eq!(dec, plaintext);
    }

    #[test]
    fn wrong_key_fails() {
        let key = derive_key(b"password-one", b"salt").expect("derive");
        let wrong = derive_key(b"password-two", b"salt").expect("derive");
        let enc = encrypt_vault_data(key.as_ref(), b"mock secret").expect("encrypt");
        assert!(decrypt_vault_data(wrong.as_ref(), &enc).is_err());
    }

    #[test]
    fn bad_key_len_rejected() {
        assert!(encrypt_vault_data(&[0u8; 16], b"x").is_err());
        assert!(decrypt_vault_data(&[0u8; 16], &[0u8; 64]).is_err());
    }

    #[test]
    fn truncated_data_rejected() {
        let key = derive_key(b"pw", b"salt").expect("derive");
        assert!(decrypt_vault_data(key.as_ref(), &[0u8; 10]).is_err());
    }

    #[test]
    fn dual_kdf_v2_header_and_pbkdf2_fallback() {
        let password = b"my-secure-password";
        let salt = b"sixteen_byte_salt_123";
        let secret = b"my-sensitive-credentials";

        let pbkdf2_key = derive_key_pbkdf2(password, salt);
        let iv = [0u8; IV_LEN];
        let cipher = Aes256Gcm16::new_from_slice(pbkdf2_key.as_ref()).unwrap();
        let ct_tag = cipher.encrypt(aes_gcm::Nonce::<U16>::from_slice(&iv), secret.as_ref()).unwrap();
        let (ct, tag) = ct_tag.split_at(ct_tag.len() - TAG_LEN);
        let mut v1_enc = Vec::new();
        v1_enc.extend_from_slice(&iv);
        v1_enc.extend_from_slice(tag);
        v1_enc.extend_from_slice(ct);

        let (dec1, argon_target_key, upgraded) =
            decrypt_vault_dual_kdf(password, salt, &v1_enc).expect("dual kdf pbkdf2");
        assert_eq!(dec1, secret);
        assert!(upgraded);

        let enc_v2 = encrypt_vault_data(argon_target_key.as_ref(), secret).expect("argon enc");
        assert_eq!(enc_v2[0], VAULT_VERSION_V2);

        let (dec2, _, upgraded2) =
            decrypt_vault_dual_kdf(password, salt, &enc_v2).expect("dual kdf argon");
        assert_eq!(dec2, secret);
        assert!(!upgraded2);
    }

    #[test]
    fn ed25519_strict_license_verification() {
        let priv_hex = "60140b1c73ee9a0ff67bd34dcabf1008c9bb64178682b423b30c45d9db184039";
        let license = sign_license_key_ed25519(priv_hex, "LIF-user_xyz_123")
            .expect("sign license");

        assert!(license.contains('.'));
        assert_eq!(verify_license_key(&license), Some("LIF-user_xyz_123".to_string()));

        let tampered = format!("tampered.{}", license.split('.').nth(1).unwrap());
        assert_eq!(verify_license_key(&tampered), None);
    }
}
