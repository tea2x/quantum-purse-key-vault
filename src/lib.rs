//! # QuantumPurse KeyVault
//!
//! This module provides a secure password-based authentication interface for managing cryptographic keys in
//! QuantumPurse project using WebAssembly. It leverages AES-GCM for encryption, Scrypt for key derivation & hashing,
//! and the SPHINCS+ signature scheme for post-quantum transaction signing. Sensitive data, including
//! root seed and derived SPHINCS+ private keys, is encrypted and stored in the browser via
//! IndexedDB, with access authenticated by user-provided passwords.

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
use indexed_db_futures::{
    error::Error as DBError, iter::ArrayMapIter, prelude::*, transaction::TransactionMode,
};
use serde_wasm_bindgen;
use wasm_bindgen::{prelude::*, JsValue};
use web_sys::js_sys::Uint8Array;

mod constants;
mod db;
mod macros;
mod secure_vec;
mod secure_string;
mod types;
mod utilities;

use crate::constants::{
    CHILD_KEYS_STORE, KDF_PATH_PREFIX, MASTER_SEED_STORE, MULTISIG_RESERVED_FIELD_VALUE,
    PUBKEY_NUM, REQUIRED_FIRST_N, THRESHOLD,
};
use secure_vec::SecureVec;
use secure_string::SecureString;
use types::*;

////////////////////////////////////////////////////////////////////////////////
///  Key-vault functions
////////////////////////////////////////////////////////////////////////////////
#[wasm_bindgen]
pub struct KeyVault {
    /// The one parameter set chosen for QuantumPurse KeyVault setup in all 12 NIST-approved SPHINCS+ FIPS205 variants
    pub variant: SpxVariant,
}

#[wasm_bindgen]
impl KeyVault {
    /// Constructs a new `KeyVault` to serve as a namespace in the output js interface.
    ///
    /// **Returns**:
    /// - `KeyVault` - A new instance of the struct.
    #[wasm_bindgen(constructor)]
    pub fn new(variant: SpxVariant) -> Self {
        KeyVault { variant: variant }
    }

    /// To derive SPHINCS+ key pair. One master seed can derive multiple child index-based SPHINCS+ key pairs on demand.
    ///
    /// **Parameters**:
    /// - `seed: &[u8]` - The master seed from which the child sphincs+ key is derived. MUST carry at least N*3 bytes of entropy or panics.
    /// - `index: u32` - The index of the child sphincs+ key to be derived.
    ///
    /// **Returns**:
    /// - `Result<SecureVec, SecureVec>` - The SPHINCS+ key pair on success, or an error message on failure.
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

    /// Clears all data in the `seed_phrase_store` and `child_keys_store` in IndexedDB.
    ///
    /// **Returns**:
    /// - `Result<(), JsValue>` - A JavaScript Promise that resolves to `undefined` on success,
    ///   or rejects with a JavaScript error on failure.
    ///
    /// **Async**: Yes
    #[wasm_bindgen]
    pub async fn clear_database() -> Result<(), JsValue> {
        let db = db::open_db().await.map_err(|e| e.to_jsvalue())?;
        db::clear_object_store(&db, MASTER_SEED_STORE)
            .await
            .map_err(|e| e.to_jsvalue())?;
        db::clear_object_store(&db, CHILD_KEYS_STORE)
            .await
            .map_err(|e| e.to_jsvalue())?;
        Ok(())
    }

    /// Retrieves all SPHINCS+ lock script arguments (processed public keys) from the database in the order they get inserted.
    ///
    /// **Returns**:
    /// - `Result<Vec<String>, JsValue>` - A JavaScript Promise that resolves to an array of hex-encoded SPHINCS+ lock script arguments on success,
    ///   or rejects with a JavaScript error on failure.
    ///
    /// **Async**: Yes
    #[wasm_bindgen]
    pub async fn get_all_sphincs_lock_args() -> Result<Vec<String>, JsValue> {
        /// Error conversion helper
        fn map_db_error<T>(result: Result<T, DBError>) -> Result<T, JsValue> {
            result.map_err(|e| JsValue::from_str(&format!("Database error: {}", e)))
        }

        let db = db::open_db().await.map_err(|e| e.to_jsvalue())?;
        let tx = map_db_error(
            db.transaction(CHILD_KEYS_STORE)
                .with_mode(TransactionMode::Readonly)
                .build(),
        )?;
        let store = map_db_error(tx.object_store(CHILD_KEYS_STORE))?;

        // Retrieve all accounts
        let iter: ArrayMapIter<JsValue> = map_db_error(store.get_all().await)?;
        let mut accounts: Vec<SphincsPlusAccount> = Vec::new();
        for result in iter {
            let js_value = map_db_error(result)?;
            let account: SphincsPlusAccount = serde_wasm_bindgen::from_value(js_value)?;
            accounts.push(account);
        }

        // Sort by index
        accounts.sort_by_key(|account| account.index);

        // Extract lock args in sorted order
        let lock_args_array: Vec<String> = accounts
            .into_iter()
            .map(|account| account.lock_args)
            .collect();

        Ok(lock_args_array)
    }

    /// Check if there's a master seed stored in the indexDB.
    ///
    /// **Returns**:
    /// - `Result<bool, JsValue>` - A JavaScript Promise that resolves to `true` if a master seed exists,
    ///   or `false` if it doesn't.
    ///
    /// **Async**: Yes
    #[wasm_bindgen]
    pub async fn has_master_seed(&self) -> Result<bool, JsValue> {
        let payload = db::get_encrypted_seed().await.map_err(|e| e.to_jsvalue())?;
        Ok(payload.is_some())
    }

    /// Generates master seed for your wallet, encrypts it with the provided password, and stores it in IndexedDB.
    /// Throw if the master seed already exists.
    ///
    /// **Parameters**:
    /// - `js_password: Uint8Array` - The password used to encrypt the generated master seed, input from js env.
    ///
    /// **Returns**:
    /// - `Result<(), JsValue>` - A JavaScript Promise that resolves to `undefined` on success,
    ///   or rejects with a JavaScript error on failure.
    ///
    /// **Async**: Yes
    /// 
    /// **Notes**:
    /// - For security reasons, the provided `js_password` buffer is cleared immediately after it
    ///   has been copied into a secure container.
    #[wasm_bindgen]
    pub async fn generate_master_seed(&self, js_password: Uint8Array) -> Result<(), JsValue> {
        let password = SecureVec::from_slice(&js_password.to_vec());
        js_password.fill(0, 0, js_password.length());

        if password.is_empty() || password.is_uninitialized() {
            return Err(JsValue::from_str("Password cannot be empty or uninitialized"));
        }

        if self.has_master_seed().await? {
            return Err(JsValue::from_str("Master seed already exists"));
        }

        let size = self.variant.required_entropy_size_total();
        let entropy = utilities::get_random_bytes(size)
            .map_err(|e| JsValue::from_str(&format!("Failed generating master seed: {}", e)))?;
        let encrypted_seed = utilities::encrypt(&password, entropy.as_ref())
            .map_err(|e| JsValue::from_str(&format!("Encryption error: {}", e)))?;

        db::set_encrypted_seed(encrypted_seed)
            .await
            .map_err(|e| e.to_jsvalue())?;
        Ok(())
    }

    /// Generates a new SPHINCS+ account - a SPHINCS+ child account derived from the master seed, encrypts the private key with the password, and stores it in IndexedDB.
    ///
    /// **Parameters**:
    /// - `js_password: Uint8Array` - The password used to decrypt the master seed and encrypt the child private key, input from js env.
    ///
    /// **Returns**:
    /// - `Result<String, JsValue>` - A String Promise that resolves to the hex-encoded SPHINCS+ lock argument (processed SPHINCS+ public key) of the account on success,
    ///   or rejects with a JavaScript error on failure.
    ///
    /// **Async**: Yes
    /// 
    /// **Notes**:
    /// - For security reasons, the provided `js_password` buffer is cleared immediately after it
    ///   has been copied into a secure container.
    #[wasm_bindgen]
    pub async fn gen_new_account(&self, js_password: Uint8Array) -> Result<String, JsValue> {
        let password = SecureVec::from_slice(&js_password.to_vec());
        js_password.fill(0, 0, js_password.length());

        if password.is_empty() || password.is_uninitialized() {
            return Err(JsValue::from_str("Password cannot be empty or uninitialized"));
        }

        // Get and decrypt the master seed
        let payload = db::get_encrypted_seed()
            .await
            .map_err(|e| e.to_jsvalue())?
            .ok_or_else(|| JsValue::from_str("Master seed not found"))?;
        let seed = utilities::decrypt(&password, payload)?;

        let index = Self::get_all_sphincs_lock_args().await?.len() as u32;
        let (pub_key, pri_key) = self
            .derive_spx_keys(&seed, index)
            .map_err(|e| JsValue::from_str(&format!("Key derivation error: {}", e)))?;

        // Calculate lock script args and encrypt corresponding private key
        let lock_script_args = self.get_lock_scrip_arg(&pub_key);
        let encrypted_pri = utilities::encrypt(&password, &pri_key)?;

        // Store to DB
        let account = SphincsPlusAccount {
            index: 0, // Init to 0; Will be set correctly in add_account
            lock_args: encode(lock_script_args),
            pri_enc: encrypted_pri,
        };

        db::add_account(account).await.map_err(|e| e.to_jsvalue())?;

        Ok(encode(lock_script_args))
    }

    /// Imports master seed then encrypting it with the provided password.
    /// Overwrite the existing master seed.
    ///
    /// **Parameters**:
    /// - `js_seed_phrase: Uint8Array` - The mnemonic phrase as a valid UTF-8 encoded Uint8Array to import, input from js env.
    ///    There're only 3 options accepted: 36, 54 or 72 words.
    /// - `js_password: Uint8Array` - The password used to encrypt the translated master seed, input from js env.
    ///
    /// **Returns**:
    /// - `Result<(), JsValue>` - A JavaScript Promise that resolves to `undefined` on success,
    ///   or rejects with a JavaScript error on failure.
    ///
    /// **Async**: Yes
    ///
    /// **Notes**:
    /// - For security reasons, the provided `js_password` and the js_seed_phrase buffers are cleared immediately after they
    ///   have been copied into secure containers.
    #[wasm_bindgen]
    pub async fn import_seed_phrase(
        &self,
        js_seed_phrase: Uint8Array,
        js_password: Uint8Array,
    ) -> Result<(), JsValue> {
        let password = SecureVec::from_slice(&js_password.to_vec());
        js_password.fill(0, 0, js_password.length());

        let seed_phrase_str = SecureString::from_utf8(js_seed_phrase.to_vec())
            .map_err(|e| JsValue::from_str(&format!("Invalid UTF-8: {}", e)))?;
        js_seed_phrase.fill(0, 0, js_seed_phrase.length());

        if password.is_empty() || password.is_uninitialized() {
            return Err(JsValue::from_str("Password cannot be empty or uninitialized"));
        }

        if seed_phrase_str.is_empty() || seed_phrase_str.is_uninitialized() {
            return Err(JsValue::from_str("Seed phrase cannot be empty or uninitialized"));
        }

        let words: Vec<&str> = seed_phrase_str.split_whitespace().collect();
        let word_count = words.len();

        if word_count != self.variant.required_bip39_size_in_word_total() {
            return Err(JsValue::from_str(&format!(
                "Mismatch: The chosen SPHINCS+ parameter set {} requires {} words whereas the input mnemonic has {} words.",
                self.variant,
                self.variant.required_bip39_size_in_word_total(),
                word_count
            )));
        }

        let mut combined_entropy = SecureVec::new_with_length(0);
        let mut index: u8 = 0;
        let size = self.variant.required_bip39_size_in_word_component();
        for chunk in words.chunks(size) {
            index += 1;
            let chunk_str = SecureString::from_string(chunk.join(" "));
            let mnemonic = Mnemonic::parse_in(Language::English, &*chunk_str).map_err(|e| {
                JsValue::from_str(&format!(
                    "Invalid mnemonic: Chunk{} index {}: {}",
                    size, index, e
                ))
            })?;
            combined_entropy.extend(&mnemonic.to_entropy());
        }

        let payload = utilities::encrypt(&password, &combined_entropy)?;
        db::set_encrypted_seed(payload)
            .await
            .map_err(|e| e.to_jsvalue())?;
        Ok(())
    }

    /// Exports the master seed in the form of a custom bip39 mnemonic phrase. There're only 3 options: 36, 54 or 72 words.
    ///
    /// **Parameters**:
    /// - `js_password: Uint8Array` - The password used to decrypt the master seed, input from js env.
    ///
    /// **Returns**:
    /// - `Result<Uint8Array, JsValue>` - A JavaScript Promise that resolves to the mnemonic as a UTF-8 encoded `Uint8Array` on success,
    ///   or rejects with a JavaScript error on failure.
    ///
    /// **Async**: Yes
    ///
    /// **Warning**: Exporting the mnemonic exposes it in JavaScript may pose a security risk.
    /// 
    /// **Async**: Yes
    /// 
    /// **Notes**:
    /// - For security reasons, the provided `js_password` buffer is cleared immediately after it
    ///   has been copied into a secure container.
    #[wasm_bindgen]
    pub async fn export_seed_phrase(&self, js_password: Uint8Array) -> Result<Uint8Array, JsValue> {
        let password = SecureVec::from_slice(&js_password.to_vec());
        js_password.fill(0, 0, js_password.length());

        if password.is_empty() || password.is_uninitialized() {
            return Err(JsValue::from_str("Password cannot be empty or uninitialized"));
        }

        let payload = db::get_encrypted_seed()
            .await
            .map_err(|e| e.to_jsvalue())?
            .ok_or_else(|| JsValue::from_str("Master seed not found"))?;

        let entropy = utilities::decrypt(&password, payload)?;
        let size = self.variant.required_entropy_size_component();
        let chunks = entropy.chunks(size);

        let mut combined_mnemonic  = SecureString::new();
        for chunk in chunks {
            let mnemonic = Mnemonic::from_entropy_in(Language::English, chunk)
                .map_err(|e| JsValue::from_str(&format!("Export seed error: {}", e)))?;
            combined_mnemonic.extend(&mnemonic.to_string());
        }
        Ok(Uint8Array::from(combined_mnemonic.as_ref()))
    }

    /// Sign and produce a valid signature for the Quantum Resistant lock script.
    ///
    /// **Parameters**:
    /// - `js_password: Uint8Array` - The password used to decrypt the private key, input from js env.
    /// - `lock_args: String` - The hex-encoded lock script's arguments corresponding to the SPHINCS+ public key of the account that signs.
    ///    This is a CKB specific thing, check https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0022-transaction-structure/script-p2.png for more information.
    /// - `message: Uint8Array` - The message to be signed.
    ///
    /// **Returns**:
    /// - `Result<Uint8Array, JsValue>` - The signature as a `Uint8Array` on success,
    ///   or a JavaScript error on failure.
    ///
    /// **Async**: Yes
    /// 
    /// **Notes**:
    /// - For security reasons, the provided `js_password` buffer is cleared immediately after it
    ///   has been copied into a secure container.
    #[wasm_bindgen]
    pub async fn sign(
        &self,
        js_password: Uint8Array,
        lock_args: String,
        message: Uint8Array,
    ) -> Result<Uint8Array, JsValue> {
        let password = SecureVec::from_slice(&js_password.to_vec());
        js_password.fill(0, 0, js_password.length());

        if password.is_empty() || password.is_uninitialized() {
            return Err(JsValue::from_str("Password cannot be empty or uninitialized"));
        }

        let account = db::get_account(&lock_args)
            .await
            .map_err(|e| e.to_jsvalue())?
            .ok_or_else(|| JsValue::from_str("Account not found"))?;

        let pri_key = utilities::decrypt(&password, account.pri_enc)?;
        let message_vec = message.to_vec();

        match self.variant {
            SpxVariant::Sha2128S => spx_sign!(slh_dsa_sha2_128s, pri_key, &message_vec, self.variant),
            SpxVariant::Sha2128F => spx_sign!(slh_dsa_sha2_128f, pri_key, &message_vec, self.variant),
            SpxVariant::Shake128S => spx_sign!(slh_dsa_shake_128s, pri_key, &message_vec, self.variant),
            SpxVariant::Shake128F => spx_sign!(slh_dsa_shake_128f, pri_key, &message_vec, self.variant),
            SpxVariant::Sha2192S => spx_sign!(slh_dsa_sha2_192s, pri_key, &message_vec, self.variant),
            SpxVariant::Sha2192F => spx_sign!(slh_dsa_sha2_192f, pri_key, &message_vec, self.variant),
            SpxVariant::Shake192S => spx_sign!(slh_dsa_shake_192s, pri_key, &message_vec, self.variant),
            SpxVariant::Shake192F => spx_sign!(slh_dsa_shake_192f, pri_key, &message_vec, self.variant),
            SpxVariant::Sha2256S => spx_sign!(slh_dsa_sha2_256s, pri_key, &message_vec, self.variant),
            SpxVariant::Sha2256F => spx_sign!(slh_dsa_sha2_256f, pri_key, &message_vec, self.variant),
            SpxVariant::Shake256S => spx_sign!(slh_dsa_shake_256s, pri_key, &message_vec, self.variant),
            SpxVariant::Shake256F => spx_sign!(slh_dsa_shake_256f, pri_key, &message_vec, self.variant),
        }
    }

    /// Supporting wallet recovery - quickly derives a list of lock script arguments (processed public keys).
    ///
    /// **Parameters**:
    /// - `js_password: Uint8Array` - The password used to decrypt the master seed used for account generation, input from js env.
    /// - `start_index: u32` - The starting index for derivation.
    /// - `count: u32` - The number of sequential lock scripts arguments to derive.
    ///
    /// **Returns**:
    /// - `Result<Vec<String>, JsValue>` - A list of lock script arguments on success,
    ///   or a JavaScript error on failure.
    /// 
    /// **Async**: Yes
    /// 
    /// **Notes**:
    /// - For security reasons, the provided `js_password` buffer is cleared immediately after it
    ///   has been copied into a secure container.
    #[wasm_bindgen]
    pub async fn try_gen_account_batch(
        &self,
        js_password: Uint8Array,
        start_index: u32,
        count: u32,
    ) -> Result<Vec<String>, JsValue> {
        let password = SecureVec::from_slice(&js_password.to_vec());
        js_password.fill(0, 0, js_password.length());

        if password.is_empty() || password.is_uninitialized() {
            return Err(JsValue::from_str("Password cannot be empty or uninitialized"));
        }

        // Get and decrypt the master seed
        let payload = db::get_encrypted_seed()
            .await
            .map_err(|e| e.to_jsvalue())?
            .ok_or_else(|| JsValue::from_str("Master seed not found"))?;
        let seed = utilities::decrypt(&password, payload)?;
        let mut lock_args_array: Vec<String> = Vec::new();
        for index in start_index..(start_index + count) {
            let (pub_key, _) = self
                .derive_spx_keys(&seed, index)
                .map_err(|e| JsValue::from_str(&format!("Key derivation error: {}", e)))?;

            // Calculate lock script args
            let lock_script_args = self.get_lock_scrip_arg(&pub_key);
            lock_args_array.push(encode(lock_script_args));
        }
        Ok(lock_args_array)
    }

    /// Supporting wallet recovery - Recovers the wallet by deriving and storing private keys for the first N accounts.
    ///
    /// **Parameters**:
    /// - `js_password: Uint8Array` - The password used to decrypt the master seed, input from js env.
    /// - `count: u32` - The number of accounts to recover (from index 0 to count-1).
    ///
    /// **Returns**:
    /// - `Result<(), JsValue>` - A list of newly generated sphincs+ lock script arguments (processed public keys) on success, or a JavaScript error on failure.
    ///
    /// **Async**: Yes
    /// 
    /// **Notes**:
    /// - For security reasons, the provided `js_password` buffer is cleared immediately after it
    ///   has been copied into a secure container.
    #[wasm_bindgen]
    pub async fn recover_accounts(
        &self,
        js_password: Uint8Array,
        count: u32,
    ) -> Result<Vec<String>, JsValue> {
        let password = SecureVec::from_slice(&js_password.to_vec());
        js_password.fill(0, 0, js_password.length());

        if password.is_empty() || password.is_uninitialized() {
            return Err(JsValue::from_str("Password cannot be empty or uninitialized"));
        }

        // Get and decrypt the master seed
        let payload = db::get_encrypted_seed()
            .await
            .map_err(|e| e.to_jsvalue())?
            .ok_or_else(|| JsValue::from_str("Master seed not found"))?;
        let mut lock_args_array: Vec<String> = Vec::new();
        let seed = utilities::decrypt(&password, payload)?;
        for index in 0..count {
            let (pub_key, pri_key) = self
                .derive_spx_keys(&seed, index)
                .map_err(|e| JsValue::from_str(&format!("Key derivation error: {}", e)))?;

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

            db::add_account(account).await.map_err(|e| e.to_jsvalue())?;
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
#[wasm_bindgen]
pub struct Util;

#[wasm_bindgen]
impl Util {
    /// https://github.com/xxuejie/rfcs/blob/cighash-all/rfcs/0000-ckb-tx-message-all/0000-ckb-tx-message-all.md.
    ///
    /// **Parameters**:
    /// - `serialized_mock_tx: Uint8Array` - serialized CKB mock transaction.
    ///
    /// **Returns**:
    /// - `Result<Uint8Array, JsValue>` - The CKB transaction message all hash digest as a `Uint8Array` on success,
    ///   or a JavaScript error on failure.
    ///
    /// **Async**: no
    #[wasm_bindgen]
    pub fn get_ckb_tx_message_all(serialized_mock_tx: Uint8Array) -> Result<Uint8Array, JsValue> {
        let serialized_bytes = serialized_mock_tx.to_vec();
        let repr_mock_tx: ReprMockTransaction = serde_json::from_slice(&serialized_bytes)
            .map_err(|e| JsValue::from_str(&format!("Deserialization error: {}", e)))?;
        let mock_tx: MockTransaction = repr_mock_tx.into();
        let mut message_hasher = Hasher::message_hasher();
        generate_ckb_tx_message_all_from_mock_tx(
            &mock_tx,
            ScriptOrIndex::Index(0),
            &mut message_hasher,
        )
        .map_err(|e| JsValue::from_str(&format!("CKB_TX_MESSAGE_ALL error: {:?}", e)))?;
        let message = message_hasher.hash();
        Ok(Uint8Array::from(message.as_slice()))
    }

    /// Check strength of a password.
    /// There is no official weighting system to calculate the strength of a password.
    /// This is just a simple implementation for ASCII passwords. Feel free to use your own password checker.
    /// By default will require at least 20 characters
    ///
    /// **Parameters**:
    /// - `js_password: Uint8Array` - utf8 serialized password, input from js env.
    ///
    /// **Returns**:
    /// - `Result<u16, JsValue>` - The strength of the password measured in bit on success,
    ///   or a JavaScript error on failure.
    ///
    /// **Async**: no
    /// 
    /// **Notes**:
    /// - For security reasons, the provided `js_password` buffer is cleared immediately after it
    ///   has been copied into a secure container.
    #[wasm_bindgen]
    pub fn password_checker(js_password: Uint8Array) -> Result<u32, JsValue> {
        let password = SecureVec::from_slice(&js_password.to_vec());
        js_password.fill(0, 0, js_password.length());

        if password.is_empty() || password.is_uninitialized() {
            return Err(JsValue::from_str("Password cannot be empty or uninitialized"));
        }
        
        let password_str =
            std::str::from_utf8(&password).map_err(|e| JsValue::from_str(&e.to_string()))?;

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
            return Err(JsValue::from_str("Password must not contain consecutive repeated characters!"));
        }
        if !has_uppercase {
            return Err(JsValue::from_str("Password must contain at least one uppercase letter!"));
        }
        if !has_lowercase {
            return Err(JsValue::from_str("Password must contain at least one lowercase letter!"));
        }
        if !has_digit {
            return Err(JsValue::from_str("Password must contain at least one digit!"));
        }
        if !has_punctuation {
            return Err(JsValue::from_str("Password must contain at least one symbol!"));
        }
        if password_str.len() < 20 {
            return Err(JsValue::from_str("Password must contain at least 20 characters!"));
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
