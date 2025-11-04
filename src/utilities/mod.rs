use super::constants::{ENC_SCRYPT, IV_LENGTH, SALT_LENGTH};
use super::types::{CipherPayload, ScryptParam};
use crate::secure_vec::SecureVec;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
    AeadInPlace
};
use hex::{decode, encode};
use scrypt::{scrypt, Params};
#[cfg(test)]
mod tests;

/// Generates random bytes for cryptographic use.
///
/// **Parameters**:
/// - `length: usize` - The number of random bytes to generate.
///
/// **Returns**:
/// - `Result<SecureVec, String>` - A Secure vector of random bytes on success, or an error message on failure.
pub fn get_random_bytes(length: usize) -> Result<SecureVec, getrandom::Error> {
    let mut buffer = SecureVec::new_with_length(length);
    getrandom::getrandom(&mut buffer)?;
    Ok(buffer)
}

/// This function is used for both hashing and key derivation.
///
/// **Parameters**:
/// - `input: &[u8]` - The input from which the scrypt key is derived.
/// - `salt: &Vec<u8>` - Salt.
///
/// **Returns**:
/// - `Result<SecureVec, String>` - Scrypt key on success, or an error message on failure.
///
/// Warning: Proper zeroization of the input is the responsibility of the caller.
pub fn derive_scrypt_key(
    input: &[u8],
    salt: &Vec<u8>,
    param: &ScryptParam,
) -> Result<SecureVec, String> {
    let mut scrypt_key = SecureVec::new_with_length(param.len);
    let scrypt_param = Params::new(param.log_n, param.r, param.p, param.len).unwrap();
    scrypt(input, &salt, &scrypt_param, &mut scrypt_key)
        .map_err(|e| format!("Scrypt error: {:?}", e))?;
    Ok(scrypt_key)
}

/// Encrypts data using AES-GCM with a password-derived key.
///
/// **Parameters**:
/// - `password: &[u8]` - The password used to derive the encryption key.
/// - `input: &[u8]` - The plaintext data to encrypt.
///
/// **Returns**:
/// - `Result<CipherPayload, String>` - A `CipherPayload` containing the encrypted data, salt, and IV on success, or an error message on failure.
///
/// Warning: Proper zeroization of the password and input is the responsibility of the caller.
pub fn encrypt(password: &[u8], input: &[u8]) -> Result<CipherPayload, String> {
    let mut salt = vec![0u8; SALT_LENGTH];
    let mut iv = vec![0u8; IV_LENGTH];
    let random_bytes = get_random_bytes(SALT_LENGTH + IV_LENGTH).map_err(|e| e.to_string())?;
    salt.copy_from_slice(&random_bytes[0..SALT_LENGTH]);
    iv.copy_from_slice(&random_bytes[SALT_LENGTH..]);

    let hashed_password = derive_scrypt_key(password, &salt, &ENC_SCRYPT)?;
    let aes_key: &Key<Aes256Gcm> = Key::<Aes256Gcm>::from_slice(&hashed_password);
    let cipher = Aes256Gcm::new(aes_key);
    let nonce = Nonce::from_slice(&iv);
    let cipher_text = cipher
        .encrypt(nonce, input)
        .map_err(|e| format!("Encryption error: {:?}", e))?;

    Ok(CipherPayload {
        salt: encode(salt),
        iv: encode(iv),
        cipher_text: encode(cipher_text),
    })
}

/// Decrypts data using AES-GCM with a password-derived key.
///
/// **Parameters**:
/// - `password: &[u8]` - The password used to derive the decryption key.
/// - `payload: CipherPayload` - The encrypted data payload containing salt, IV, and ciphertext.
///
/// **Returns**:
/// - `Result<Vec<u8>, String>` - The decrypted plaintext on success, or an error message on failure.
///
/// Warning: Proper zeroization of the password and input is the responsibility of the caller.
pub fn decrypt(password: &[u8], payload: CipherPayload) -> Result<SecureVec, String> {
    let salt = decode(payload.salt).map_err(|e| format!("Salt decode error: {:?}", e))?;
    let iv = decode(payload.iv).map_err(|e| format!("IV decode error: {:?}", e))?;
    let cipher_text =
        decode(payload.cipher_text).map_err(|e| format!("Ciphertext decode error: {:?}", e))?;

    let hashed_password = derive_scrypt_key(password, &salt, &ENC_SCRYPT)?;
    let aes_key: &Key<Aes256Gcm> = Key::<Aes256Gcm>::from_slice(&hashed_password);
    let cipher = Aes256Gcm::new(aes_key);
    let nonce = Nonce::from_slice(&iv);

    let mut secure_decipher = SecureVec::from_slice(&cipher_text);
    cipher.decrypt_in_place(&nonce, b"", &mut secure_decipher)
        .map_err(|e| format!("Decryption error: {:?}", e))?;
    Ok(secure_decipher)
}
