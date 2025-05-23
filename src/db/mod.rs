mod errors;

use super::types::{CipherPayload, SphincsPlusAccount};
use crate::constants::{CHILD_KEYS_STORE, DB_NAME, MASTER_SEED_KEY, MASTER_SEED_STORE};
use errors::KeyVaultDBError;
use indexed_db_futures::{
    database::Database, prelude::*, transaction::TransactionMode,
};

/// Opens the IndexedDB database, creating object stores if necessary.
///
/// **Returns**:
/// - `Result<Database, KeyVaultDBError>` - The opened database on success, or an error if the operation fails.
///
/// **Async**: Yes
pub async fn open_db() -> Result<Database, KeyVaultDBError> {
    Database::open(DB_NAME)
        .with_version(1u8)
        .with_on_blocked(|_event| Ok(()))
        .with_on_upgrade_needed(|_event, db| {
            if !db
                .object_store_names()
                .any(|name| name == MASTER_SEED_STORE)
            {
                db.create_object_store(MASTER_SEED_STORE).build()?;
            }
            if !db.object_store_names().any(|name| name == CHILD_KEYS_STORE) {
                db.create_object_store(CHILD_KEYS_STORE).build()?;
            }
            Ok(())
        })
        .await
        .map_err(|e| KeyVaultDBError::DatabaseError(format!("Failed to open IndexedDB: {}", e)))
}

/// Stores the encrypted master seed in the database.
///
/// **Parameters**:
/// - `payload: CipherPayload` - The encrypted master seed data to store.
///
/// **Returns**:
/// - `Result<(), KeyVaultDBError>` - Ok on success, or an error if storage fails.
///
/// **Async**: Yes
///
/// **Warning**: This method overwrites the existing master seed in the database.
pub async fn set_encrypted_seed(payload: CipherPayload) -> Result<(), KeyVaultDBError> {
    let db = open_db().await?;
    let tx = db
        .transaction(MASTER_SEED_STORE)
        .with_mode(TransactionMode::Readwrite)
        .build()?;
    let store = tx.object_store(MASTER_SEED_STORE)?;

    let js_value = serde_wasm_bindgen::to_value(&payload)?;
    store.put(&js_value).with_key(MASTER_SEED_KEY).await?;
    tx.commit().await?;
    Ok(())
}

/// Retrieves the encrypted masterseed from the database.
///
/// **Returns**:
/// - `Result<Option<CipherPayload>, KeyVaultDBError>` - The encrypted master seed if it exists, `None` if not found, or an error if retrieval fails.
///
/// **Async**: Yes
pub async fn get_encrypted_seed() -> Result<Option<CipherPayload>, KeyVaultDBError> {
    let db = open_db().await?;
    let tx = db
        .transaction(MASTER_SEED_STORE)
        .with_mode(TransactionMode::Readonly)
        .build()?;
    let store = tx.object_store(MASTER_SEED_STORE)?;

    if let Some(js_value) = store
        .get(MASTER_SEED_KEY)
        .await
        .map_err(|e| KeyVaultDBError::DatabaseError(e.to_string()))?
    {
        let payload: CipherPayload = serde_wasm_bindgen::from_value(js_value)?;
        Ok(Some(payload))
    } else {
        Ok(None)
    }
}

/// Stores a SPHINCS+ account to the database.
///
/// **Parameters**:
/// - `account: SphincsPlusAccount` - The SPHINCS+ account to store.
///
/// **Returns**:
/// - `Result<(), KeyVaultDBError>` - Ok on success, or an error if storage fails.
///
/// **Async**: Yes
pub async fn add_account(mut account: SphincsPlusAccount) -> Result<(), KeyVaultDBError> {
    let db = open_db().await?;
    let tx = db
        .transaction(CHILD_KEYS_STORE)
        .with_mode(TransactionMode::Readwrite)
        .build()?;
    let store = tx.object_store(CHILD_KEYS_STORE)?;
    let count = store.count().await?;
    account.index = count as u32;
    let js_value = serde_wasm_bindgen::to_value(&account)?;

    store.add(js_value).with_key(account.lock_args).await?;
    tx.commit().await?;
    Ok(())
}

/// Retrieves a child account by its public key from the database.
///
/// **Parameters**:
/// - `lock_args: &str` - The hex-encoded lock script's arguments corresponding to the SPHINCS+ public key of the retrieved child account.
///
/// **Returns**:
/// - `Result<Option<SphincsPlusAccount>, KeyVaultDBError>` - The child key if found, `None` if not found, or an error if retrieval fails.
///
/// **Async**: Yes
pub async fn get_account(lock_args: &str) -> Result<Option<SphincsPlusAccount>, KeyVaultDBError> {
    let db = open_db().await?;
    let tx = db
        .transaction(CHILD_KEYS_STORE)
        .with_mode(TransactionMode::Readonly)
        .build()?;
    let store = tx.object_store(CHILD_KEYS_STORE)?;

    if let Some(js_value) = store
        .get(lock_args)
        .await
        .map_err(|e| KeyVaultDBError::DatabaseError(e.to_string()))?
    {
        let account: SphincsPlusAccount = serde_wasm_bindgen::from_value(js_value)?;
        Ok(Some(account))
    } else {
        Ok(None)
    }
}

/// Clears a specific object store in the database.
///
/// **Parameters**:
/// - `db: &Database` - The database instance to operate on.
/// - `store_name: &str` - The name of the object store to clear.
///
/// **Returns**:
/// - `Result<(), KeyVaultDBError>` - Ok on success, or an error if the operation fails.
///
/// **Async**: Yes
pub async fn clear_object_store(db: &Database, store_name: &str) -> Result<(), KeyVaultDBError> {
    let tx = db
        .transaction(store_name)
        .with_mode(TransactionMode::Readwrite)
        .build()
        .map_err(|e| {
            KeyVaultDBError::DatabaseError(format!(
                "Error starting transaction for {}: {}",
                store_name, e
            ))
        })?;
    let store = tx.object_store(store_name).map_err(|e| {
        KeyVaultDBError::DatabaseError(format!("Error getting object store {}: {}", store_name, e))
    })?;
    store.clear().map_err(|e| {
        KeyVaultDBError::DatabaseError(format!("Error clearing object store {}: {}", store_name, e))
    })?;
    tx.commit().await.map_err(|e| {
        KeyVaultDBError::DatabaseError(format!(
            "Error committing transaction for {}: {}",
            store_name, e
        ))
    })?;
    Ok(())
}
