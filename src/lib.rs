//! # QuantumPurse KeyVault
//!
//! This module provides a secure password-based authentication interface for managing cryptographic keys in
//! QuantumPurse project. It leverages AES-GCM for encryption, Scrypt for key derivation & hashing,
//! and the SPHINCS+ signature scheme for post-quantum transaction signing. Sensitive data, including
//! root seed and derived SPHINCS+ private keys, is encrypted and stored locally in files,
//! with access authenticated by user-provided passwords.

use bip39::{Language, Mnemonic};
use ckb_fips205_utils::{
    ckb_tx_message_all_from_mock_tx::{generate_ckb_tx_message_all_from_mock_tx, ScriptOrIndex},
    Hasher,
};
use ckb_mock_tx_types::{MockTransaction, ReprMockTransaction};
use fips205::{
    traits::{KeyGen, SerDes, Signer},
    *,
};
use hex::encode;

mod constants;
pub mod db;
mod macros;
mod secure_vec;
mod secure_string;
pub mod types;
pub mod utilities;

use crate::constants::{
    KDF_PATH_PREFIX, MULTISIG_RESERVED_FIELD_VALUE,
    PUBKEY_NUM, REQUIRED_FIRST_N, THRESHOLD,
};
use secure_vec::SecureVec;
use secure_string::SecureString;
use types::*;

////////////////////////////////////////////////////////////////////////////////
///  Key-vault functions
////////////////////////////////////////////////////////////////////////////////
pub struct KeyVault {
    /// The one parameter set chosen for QuantumPurse KeyVault setup in all 12 NIST-approved SPHINCS+ FIPS205 variants
    pub variant: SpxVariant,
}

impl KeyVault {
    /// Constructs a new `KeyVault`.
    ///
    /// **Returns**:
    /// - `KeyVault` - A new instance of the struct.
    pub fn new(variant: SpxVariant) -> Self {
        KeyVault { variant }
    }

    /// To derive SPHINCS+ key pair. One master seed can derive multiple child index-based SPHINCS+ key pairs on demand.
    ///
    /// **Parameters**:
    /// - `seed: &[u8]` - The master seed from which the child sphincs+ key is derived. MUST carry at least N*3 bytes of entropy or panics.
    /// - `index: u32` - The index of the child sphincs+ key to be derived.
    ///
    /// **Returns**:
    /// - `Result<(SecureVec, SecureVec), String>` - The SPHINCS+ key pair on success, or an error message on failure.
    ///
    /// Warning: Proper zeroization of the input seed is the responsibility of the caller.
    fn derive_spx_keys(
        &self,
        seed: &[u8],
        index: u32,
    ) -> Result<(SecureVec, SecureVec), String> {
        match self.variant {
            SpxVariant::Sha2128S => spx_keygen!(slh_dsa_sha2_128s::KG, slh_dsa_sha2_128s::N, seed, index),
            SpxVariant::Sha2128F => spx_keygen!(slh_dsa_sha2_128f::KG, slh_dsa_sha2_128f::N, seed, index),
            SpxVariant::Sha2192S => spx_keygen!(slh_dsa_sha2_192s::KG, slh_dsa_sha2_192s::N, seed, index),
            SpxVariant::Sha2192F => spx_keygen!(slh_dsa_sha2_192f::KG, slh_dsa_sha2_192f::N, seed, index),
            SpxVariant::Sha2256S => spx_keygen!(slh_dsa_sha2_256s::KG, slh_dsa_sha2_256s::N, seed, index),
            SpxVariant::Sha2256F => spx_keygen!(slh_dsa_sha2_256f::KG, slh_dsa_sha2_256f::N, seed, index),
            SpxVariant::Shake128S => spx_keygen!(slh_dsa_shake_128s::KG, slh_dsa_shake_128s::N, seed, index),
            SpxVariant::Shake128F => spx_keygen!(slh_dsa_shake_128f::KG, slh_dsa_shake_128f::N, seed, index),
            SpxVariant::Shake192S => spx_keygen!(slh_dsa_shake_192s::KG, slh_dsa_shake_192s::N, seed, index),
            SpxVariant::Shake192F => spx_keygen!(slh_dsa_shake_192f::KG, slh_dsa_shake_192f::N, seed, index),
            SpxVariant::Shake256S => spx_keygen!(slh_dsa_shake_256s::KG, slh_dsa_shake_256s::N, seed, index),
            SpxVariant::Shake256F => spx_keygen!(slh_dsa_shake_256f::KG, slh_dsa_shake_256f::N, seed, index),
        }
    }

    /// Clears all data in the vault.
    ///
    /// **Returns**:
    /// - `Result<(), String>` - Ok on success, or an error message on failure.
    pub fn clear_database() -> Result<(), String> {
        db::clear_master_seed().map_err(|e| e.to_string())?;
        db::clear_accounts().map_err(|e| e.to_string())?;
        db::clear_wallet_info().map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Retrieves the stored wallet variant.
    ///
    /// **Returns**:
    /// - `Result<SpxVariant, String>` - The stored variant on success, or an error if not found.
    pub fn get_stored_variant() -> Result<SpxVariant, String> {
        let wallet_info = db::get_wallet_info()
            .map_err(|e| e.to_string())?
            .ok_or_else(|| "Wallet not initialized. Run 'init' or 'import' first.".to_string())?;
        Ok(wallet_info.variant)
    }

    /// Retrieves all SPHINCS+ lock script arguments (processed public keys) from the database in the order they get inserted.
    ///
    /// **Returns**:
    /// - `Result<Vec<String>, String>` - An array of hex-encoded SPHINCS+ lock script arguments on success, or an error on failure.
    pub fn get_all_sphincs_lock_args() -> Result<Vec<String>, String> {
        let accounts = db::get_all_accounts().map_err(|e| e.to_string())?;
        let lock_args_array: Vec<String> = accounts
            .into_iter()
            .map(|account| account.lock_args)
            .collect();
        Ok(lock_args_array)
    }

    /// Check if there's a master seed stored.
    ///
    /// **Returns**:
    /// - `Result<bool, String>` - `true` if a master seed exists, or `false` if it doesn't.
    pub fn has_master_seed(&self) -> Result<bool, String> {
        let payload = db::get_encrypted_seed().map_err(|e| e.to_string())?;
        Ok(payload.is_some())
    }

    /// Generates master seed for your wallet, encrypts it with the provided password, and stores it.
    /// Errors if the master seed already exists.
    ///
    /// **Parameters**:
    /// - `password: Vec<u8>` - The password used to encrypt the generated master seed.
    ///
    /// **Returns**:
    /// - `Result<(), String>` - Ok on success, or an error on failure.
    ///
    /// **Notes**:
    /// - The provided `password` buffer is cleared immediately after use.
    pub fn generate_master_seed(&self, password: Vec<u8>) -> Result<(), String> {
        let password = SecureVec::from_slice(&password);

        if password.is_empty() || password.is_uninitialized() {
            return Err("Password cannot be empty or uninitialized".to_string());
        }

        if self.has_master_seed()? {
            return Err("Master seed already exists".to_string());
        }

        let size = self.variant.required_entropy_size_total();
        let entropy = utilities::get_random_bytes(size)
            .map_err(|e| format!("Failed generating master seed: {}", e))?;
        let encrypted_seed = utilities::encrypt(&password, entropy.as_ref())
            .map_err(|e| format!("Encryption error: {}", e))?;

        db::set_encrypted_seed(encrypted_seed).map_err(|e| e.to_string())?;

        // Store wallet info with variant
        let wallet_info = types::WalletInfo {
            variant: self.variant,
        };
        db::set_wallet_info(wallet_info).map_err(|e| e.to_string())?;

        Ok(())
    }

    /// Generates a new SPHINCS+ account - a SPHINCS+ child account derived from the master seed, encrypts the private key with the password, and stores it.
    ///
    /// **Parameters**:
    /// - `password: Vec<u8>` - The password used to decrypt the master seed and encrypt the child private key.
    ///
    /// **Returns**:
    /// - `Result<String, String>` - The hex-encoded SPHINCS+ lock argument (processed SPHINCS+ public key) of the account on success, or an error on failure.
    ///
    /// **Notes**:
    /// - The provided `password` buffer is cleared immediately after use.
    pub fn gen_new_account(&self, password: Vec<u8>) -> Result<String, String> {
        let password = SecureVec::from_slice(&password);

        if password.is_empty() || password.is_uninitialized() {
            return Err("Password cannot be empty or uninitialized".to_string());
        }

        // Get and decrypt the master seed
        let payload = db::get_encrypted_seed()
            .map_err(|e| e.to_string())?
            .ok_or_else(|| "Master seed not found".to_string())?;
        let seed = utilities::decrypt(&password, payload)?;

        let index = Self::get_all_sphincs_lock_args()?.len() as u32;
        let (pub_key, pri_key) = self
            .derive_spx_keys(&seed, index)
            .map_err(|e| format!("Key derivation error: {}", e))?;

        // Calculate lock script args and encrypt corresponding private key
        let lock_script_args = self.get_lock_scrip_arg(&pub_key);
        let encrypted_pri = utilities::encrypt(&password, &pri_key)?;

        // Store to DB
        let account = SphincsPlusAccount {
            index: 0, // Init to 0; Will be set correctly in add_account
            lock_args: encode(lock_script_args),
            pri_enc: encrypted_pri,
        };

        db::add_account(account).map_err(|e| e.to_string())?;

        Ok(encode(lock_script_args))
    }

    /// Imports master seed then encrypting it with the provided password.
    /// Overwrites the existing master seed.
    ///
    /// **Parameters**:
    /// - `seed_phrase: Vec<u8>` - The mnemonic phrase as a valid UTF-8 encoded byte array to import.
    ///    There're only 3 options accepted: 36, 54 or 72 words.
    /// - `password: Vec<u8>` - The password used to encrypt the translated master seed.
    ///
    /// **Returns**:
    /// - `Result<(), String>` - Ok on success, or an error on failure.
    ///
    /// **Notes**:
    /// - The provided `password` and `seed_phrase` buffers are cleared immediately after use.
    pub fn import_seed_phrase(
        &self,
        seed_phrase: Vec<u8>,
        password: Vec<u8>,
    ) -> Result<(), String> {
        let password = SecureVec::from_slice(&password);
        let seed_phrase_str = SecureString::from_utf8(seed_phrase)
            .map_err(|e| format!("Invalid UTF-8: {}", e))?;

        if password.is_empty() || password.is_uninitialized() {
            return Err("Password cannot be empty or uninitialized".to_string());
        }

        if seed_phrase_str.is_empty() || seed_phrase_str.is_uninitialized() {
            return Err("Seed phrase cannot be empty or uninitialized".to_string());
        }

        let words: Vec<&str> = seed_phrase_str.split_whitespace().collect();
        let word_count = words.len();

        if word_count != self.variant.required_bip39_size_in_word_total() {
            return Err(format!(
                "Mismatch: The chosen SPHINCS+ parameter set {} requires {} words whereas the input mnemonic has {} words.",
                self.variant,
                self.variant.required_bip39_size_in_word_total(),
                word_count
            ));
        }

        let mut combined_entropy = SecureVec::new_with_length(0);
        let mut index: u8 = 0;
        let size = self.variant.required_bip39_size_in_word_component();
        for chunk in words.chunks(size) {
            index += 1;
            let chunk_str = SecureString::from_string(chunk.join(" "));
            let mnemonic = Mnemonic::parse_in(Language::English, &*chunk_str).map_err(|e| {
                format!(
                    "Invalid mnemonic: Chunk{} index {}: {}",
                    size, index, e
                )
            })?;
            combined_entropy.extend(&mnemonic.to_entropy());
        }

        let payload = utilities::encrypt(&password, &combined_entropy)?;
        db::set_encrypted_seed(payload).map_err(|e| e.to_string())?;

        // Store wallet info with variant
        let wallet_info = types::WalletInfo {
            variant: self.variant,
        };
        db::set_wallet_info(wallet_info).map_err(|e| e.to_string())?;

        Ok(())
    }

    /// Exports the master seed in the form of a custom bip39 mnemonic phrase. There're only 3 options: 36, 54 or 72 words.
    ///
    /// **Parameters**:
    /// - `password: Vec<u8>` - The password used to decrypt the master seed.
    ///
    /// **Returns**:
    /// - `Result<Vec<u8>, String>` - The mnemonic as a UTF-8 encoded byte array on success, or an error on failure.
    ///
    /// **Warning**: Exporting the mnemonic exposes it and may pose a security risk.
    ///
    /// **Notes**:
    /// - The provided `password` buffer is cleared immediately after use.
    pub fn export_seed_phrase(&self, password: Vec<u8>) -> Result<Vec<u8>, String> {
        let password = SecureVec::from_slice(&password);

        if password.is_empty() || password.is_uninitialized() {
            return Err("Password cannot be empty or uninitialized".to_string());
        }

        let payload = db::get_encrypted_seed()
            .map_err(|e| e.to_string())?
            .ok_or_else(|| "Master seed not found".to_string())?;

        let entropy = utilities::decrypt(&password, payload)?;
        let size = self.variant.required_entropy_size_component();
        let chunks = entropy.chunks(size);

        let mut combined_mnemonic = SecureString::new();
        for chunk in chunks {
            let mnemonic = Mnemonic::from_entropy_in(Language::English, chunk)
                .map_err(|e| format!("Export seed error: {}", e))?;
            combined_mnemonic.extend(&mnemonic.to_string());
        }
        let result: &[u8] = combined_mnemonic.as_ref();
        Ok(result.to_vec())
    }

    /// Sign and produce a valid signature for the Quantum Resistant lock script.
    ///
    /// **Parameters**:
    /// - `password: Vec<u8>` - The password used to decrypt the private key.
    /// - `lock_args: String` - The hex-encoded lock script's arguments corresponding to the SPHINCS+ public key of the account that signs.
    /// - `message: Vec<u8>` - The message to be signed.
    ///
    /// **Returns**:
    /// - `Result<Vec<u8>, String>` - The signature on success, or an error on failure.
    ///
    /// **Notes**:
    /// - The provided `password` buffer is cleared immediately after use.
    pub fn sign(
        &self,
        password: Vec<u8>,
        lock_args: String,
        message: Vec<u8>,
    ) -> Result<Vec<u8>, String> {
        let password = SecureVec::from_slice(&password);

        if password.is_empty() || password.is_uninitialized() {
            return Err("Password cannot be empty or uninitialized".to_string());
        }

        let account = db::get_account(&lock_args)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| "Account not found".to_string())?;

        let pri_key = utilities::decrypt(&password, account.pri_enc)?;

        match self.variant {
            SpxVariant::Sha2128S => spx_sign_native!(slh_dsa_sha2_128s, pri_key, &message, self.variant),
            SpxVariant::Sha2128F => spx_sign_native!(slh_dsa_sha2_128f, pri_key, &message, self.variant),
            SpxVariant::Shake128S => spx_sign_native!(slh_dsa_shake_128s, pri_key, &message, self.variant),
            SpxVariant::Shake128F => spx_sign_native!(slh_dsa_shake_128f, pri_key, &message, self.variant),
            SpxVariant::Sha2192S => spx_sign_native!(slh_dsa_sha2_192s, pri_key, &message, self.variant),
            SpxVariant::Sha2192F => spx_sign_native!(slh_dsa_sha2_192f, pri_key, &message, self.variant),
            SpxVariant::Shake192S => spx_sign_native!(slh_dsa_shake_192s, pri_key, &message, self.variant),
            SpxVariant::Shake192F => spx_sign_native!(slh_dsa_shake_192f, pri_key, &message, self.variant),
            SpxVariant::Sha2256S => spx_sign_native!(slh_dsa_sha2_256s, pri_key, &message, self.variant),
            SpxVariant::Sha2256F => spx_sign_native!(slh_dsa_sha2_256f, pri_key, &message, self.variant),
            SpxVariant::Shake256S => spx_sign_native!(slh_dsa_shake_256s, pri_key, &message, self.variant),
            SpxVariant::Shake256F => spx_sign_native!(slh_dsa_shake_256f, pri_key, &message, self.variant),
        }
    }

    /// Supporting wallet recovery - quickly derives a list of lock script arguments (processed public keys).
    ///
    /// **Parameters**:
    /// - `password: Vec<u8>` - The password used to decrypt the master seed used for account generation.
    /// - `start_index: u32` - The starting index for derivation.
    /// - `count: u32` - The number of sequential lock scripts arguments to derive.
    ///
    /// **Returns**:
    /// - `Result<Vec<String>, String>` - A list of lock script arguments on success, or an error on failure.
    ///
    /// **Notes**:
    /// - The provided `password` buffer is cleared immediately after use.
    pub fn try_gen_account_batch(
        &self,
        password: Vec<u8>,
        start_index: u32,
        count: u32,
    ) -> Result<Vec<String>, String> {
        let password = SecureVec::from_slice(&password);

        if password.is_empty() || password.is_uninitialized() {
            return Err("Password cannot be empty or uninitialized".to_string());
        }

        // Get and decrypt the master seed
        let payload = db::get_encrypted_seed()
            .map_err(|e| e.to_string())?
            .ok_or_else(|| "Master seed not found".to_string())?;
        let seed = utilities::decrypt(&password, payload)?;
        let mut lock_args_array: Vec<String> = Vec::new();
        for index in start_index..(start_index + count) {
            let (pub_key, _) = self
                .derive_spx_keys(&seed, index)
                .map_err(|e| format!("Key derivation error: {}", e))?;

            // Calculate lock script args
            let lock_script_args = self.get_lock_scrip_arg(&pub_key);
            lock_args_array.push(encode(lock_script_args));
        }
        Ok(lock_args_array)
    }

    /// Supporting wallet recovery - Recovers the wallet by deriving and storing private keys for the first N accounts.
    ///
    /// **Parameters**:
    /// - `password: Vec<u8>` - The password used to decrypt the master seed.
    /// - `count: u32` - The number of accounts to recover (from index 0 to count-1).
    ///
    /// **Returns**:
    /// - `Result<Vec<String>, String>` - A list of newly generated sphincs+ lock script arguments (processed public keys) on success, or an error on failure.
    ///
    /// **Notes**:
    /// - The provided `password` buffer is cleared immediately after use.
    pub fn recover_accounts(
        &self,
        password: Vec<u8>,
        count: u32,
    ) -> Result<Vec<String>, String> {
        let password = SecureVec::from_slice(&password);

        if password.is_empty() || password.is_uninitialized() {
            return Err("Password cannot be empty or uninitialized".to_string());
        }

        // Get and decrypt the master seed
        let payload = db::get_encrypted_seed()
            .map_err(|e| e.to_string())?
            .ok_or_else(|| "Master seed not found".to_string())?;
        let mut lock_args_array: Vec<String> = Vec::new();
        let seed = utilities::decrypt(&password, payload)?;
        for index in 0..count {
            let (pub_key, pri_key) = self
                .derive_spx_keys(&seed, index)
                .map_err(|e| format!("Key derivation error: {}", e))?;

            // Calculate lock script args and encrypt corresponding private key
            let lock_script_args = self.get_lock_scrip_arg(&pub_key);
            let encrypted_pri = utilities::encrypt(&password, &pri_key)?;
            // Store to DB
            let account = SphincsPlusAccount {
                index: 0, // Init to 0; Will be set correctly in add_account
                lock_args: encode(lock_script_args),
                pri_enc: encrypted_pri,
            };
            lock_args_array.push(encode(lock_script_args));

            db::add_account(account).map_err(|e| e.to_string())?;
        }
        Ok(lock_args_array)
    }

    /// Building CKB SPHINCS+ all-in-one lockscript arguments
    ///
    /// **Parameters**:
    /// - `public_key: &SecureVec` - The SPHINCS+ public key to be used in the lock script.
    ///
    /// **Returns**:
    /// - `[u8; 32]` - The lock script arguments as a byte array.
    fn get_lock_scrip_arg(&self, public_key: &SecureVec) -> [u8; 32] {
        let all_in_one_config: [u8; 4] = [
            MULTISIG_RESERVED_FIELD_VALUE,
            REQUIRED_FIRST_N,
            THRESHOLD,
            PUBKEY_NUM,
        ];
        let sign_flag: u8 = self.variant << 1;
        let mut script_args_hasher = Hasher::script_args_hasher();
        script_args_hasher.update(&all_in_one_config);
        script_args_hasher.update(&[sign_flag]);
        script_args_hasher.update(&public_key);
        script_args_hasher.hash()
    }
}

////////////////////////////////////////////////////////////////////////////////
///  Key-vault utility functions
////////////////////////////////////////////////////////////////////////////////
pub struct Util;

impl Util {
    /// Generates CKB transaction message all hash.
    /// https://github.com/xxuejie/rfcs/blob/cighash-all/rfcs/0000-ckb-tx-message-all/0000-ckb-tx-message-all.md.
    ///
    /// **Parameters**:
    /// - `serialized_mock_tx: Vec<u8>` - serialized CKB mock transaction.
    ///
    /// **Returns**:
    /// - `Result<Vec<u8>, String>` - The CKB transaction message all hash digest on success, or an error on failure.
    pub fn get_ckb_tx_message_all(serialized_mock_tx: Vec<u8>) -> Result<Vec<u8>, String> {
        let repr_mock_tx: ReprMockTransaction = serde_json::from_slice(&serialized_mock_tx)
            .map_err(|e| format!("Deserialization error: {}", e))?;
        let mock_tx: MockTransaction = repr_mock_tx.into();
        let mut message_hasher = Hasher::message_hasher();
        generate_ckb_tx_message_all_from_mock_tx(
            &mock_tx,
            ScriptOrIndex::Index(0),
            &mut message_hasher,
        )
        .map_err(|e| format!("CKB_TX_MESSAGE_ALL error: {:?}", e))?;
        let message = message_hasher.hash();
        Ok(message.to_vec())
    }

    /// Check strength of a password.
    /// There is no official weighting system to calculate the strength of a password.
    /// This is just a simple implementation for ASCII passwords. Feel free to use your own password checker.
    /// By default will require at least 20 characters
    ///
    /// **Parameters**:
    /// - `password: Vec<u8>` - utf8 serialized password.
    ///
    /// **Returns**:
    /// - `Result<u32, String>` - The strength of the password measured in bit on success, or an error on failure.
    ///
    /// **Notes**:
    /// - The provided `password` buffer is cleared immediately after use.
    pub fn password_checker(password: Vec<u8>) -> Result<u32, String> {
        let password = SecureVec::from_slice(&password);

        if password.is_empty() || password.is_uninitialized() {
            return Err("Password cannot be empty or uninitialized".to_string());
        }

        let password_str =
            std::str::from_utf8(&password).map_err(|e| e.to_string())?;

        let mut has_space = false;
        let mut has_lowercase = false;
        let mut has_uppercase = false;
        let mut has_digit = false;
        let mut has_punctuation = false;
        let mut has_other = false;
        let mut has_consecutive_repeats = false;
        let mut prev_char: Option<char> = None;

        for c in password_str.chars() {
            if let Some(prev) = prev_char {
                if c == prev {
                    has_consecutive_repeats = true;
                }
            }
            prev_char = Some(c);

            if c == ' ' {
                has_space = true;
            } else if c.is_ascii_lowercase() {
                has_lowercase = true;
            } else if c.is_ascii_uppercase() {
                has_uppercase = true;
            } else if c.is_ascii_digit() {
                has_digit = true;
            } else if c.is_ascii_punctuation() {
                has_punctuation = true;
            } else {
                has_other = true;
            }
        }

        if has_consecutive_repeats {
            return Err("Password must not contain consecutive repeated characters!".to_string());
        }
        if !has_uppercase {
            return Err("Password must contain at least one uppercase letter!".to_string());
        }
        if !has_lowercase {
            return Err("Password must contain at least one lowercase letter!".to_string());
        }
        if !has_digit {
            return Err("Password must contain at least one digit!".to_string());
        }
        if !has_punctuation {
            return Err("Password must contain at least one symbol!".to_string());
        }
        if password_str.len() < 20 {
            return Err("Password must contain at least 20 characters!".to_string());
        }

        let character_set_size = if has_other {
            256 // Entire characters space in ASCII
        } else {
            let mut size = 0;
            if has_space {
                size += 1;
            } // Space character
            if has_lowercase {
                size += 26;
            } // a-z
            if has_uppercase {
                size += 26;
            } // A-Z
            if has_digit {
                size += 10;
            } // 0-9
            if has_punctuation {
                size += 32;
            } // ASCII punctuation
            size
        };

        let entropy = (password_str.len() as f64) * (character_set_size as f64).log2();
        let rounded_entropy = entropy.round() as u32;
        Ok(rounded_entropy)
    }
}
