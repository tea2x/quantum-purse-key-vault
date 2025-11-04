pub mod errors;

use super::types::{CipherPayload, SphincsPlusAccount, WalletInfo};
pub use errors::KeyVaultDBError;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::PathBuf;

/// Gets the data directory path for the key vault
///
/// **Returns**:
/// - `Result<PathBuf, KeyVaultDBError>` - The data directory path on success, or an error if it cannot be determined.
fn get_data_dir() -> Result<PathBuf, KeyVaultDBError> {
    let home_dir = dirs::home_dir()
        .ok_or_else(|| KeyVaultDBError::DatabaseError("Cannot determine home directory".to_string()))?;

    let data_dir = home_dir.join(".quantum-purse");

    // Create directory if it doesn't exist
    if !data_dir.exists() {
        fs::create_dir_all(&data_dir)?;
    }

    Ok(data_dir)
}

/// Gets the path to the master seed file
fn get_master_seed_path() -> Result<PathBuf, KeyVaultDBError> {
    Ok(get_data_dir()?.join("master_seed.json"))
}

/// Gets the path to the accounts file
fn get_accounts_path() -> Result<PathBuf, KeyVaultDBError> {
    Ok(get_data_dir()?.join("accounts.json"))
}

/// Gets the path to the wallet info file
fn get_wallet_info_path() -> Result<PathBuf, KeyVaultDBError> {
    Ok(get_data_dir()?.join("wallet_info.json"))
}

/// Stores the encrypted master seed in the file system.
///
/// **Parameters**:
/// - `payload: CipherPayload` - The encrypted master seed data to store.
///
/// **Returns**:
/// - `Result<(), KeyVaultDBError>` - Ok on success, or an error if storage fails.
///
/// **Warning**: This method overwrites the existing master seed.
pub fn set_encrypted_seed(payload: CipherPayload) -> Result<(), KeyVaultDBError> {
    let path = get_master_seed_path()?;
    let json = serde_json::to_string_pretty(&payload)?;
    let mut file = File::create(path)?;
    file.write_all(json.as_bytes())?;
    Ok(())
}

/// Retrieves the encrypted master seed from the file system.
///
/// **Returns**:
/// - `Result<Option<CipherPayload>, KeyVaultDBError>` - The encrypted master seed if it exists, `None` if not found, or an error if retrieval fails.
pub fn get_encrypted_seed() -> Result<Option<CipherPayload>, KeyVaultDBError> {
    let path = get_master_seed_path()?;

    if !path.exists() {
        return Ok(None);
    }

    let mut file = File::open(path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    let payload: CipherPayload = serde_json::from_str(&contents)?;
    Ok(Some(payload))
}

/// Helper function to load all accounts from file
fn load_accounts() -> Result<HashMap<String, SphincsPlusAccount>, KeyVaultDBError> {
    let path = get_accounts_path()?;

    if !path.exists() {
        return Ok(HashMap::new());
    }

    let mut file = File::open(path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    let accounts: HashMap<String, SphincsPlusAccount> = serde_json::from_str(&contents)?;
    Ok(accounts)
}

/// Helper function to save all accounts to file
fn save_accounts(accounts: &HashMap<String, SphincsPlusAccount>) -> Result<(), KeyVaultDBError> {
    let path = get_accounts_path()?;
    let json = serde_json::to_string_pretty(accounts)?;
    let mut file = File::create(path)?;
    file.write_all(json.as_bytes())?;
    Ok(())
}

/// Stores a SPHINCS+ account to the file system.
///
/// **Parameters**:
/// - `account: SphincsPlusAccount` - The SPHINCS+ account to store.
///
/// **Returns**:
/// - `Result<(), KeyVaultDBError>` - Ok on success, or an error if storage fails.
pub fn add_account(mut account: SphincsPlusAccount) -> Result<(), KeyVaultDBError> {
    let mut accounts = load_accounts()?;
    let count = accounts.len();
    account.index = count as u32;
    accounts.insert(account.lock_args.clone(), account);
    save_accounts(&accounts)?;
    Ok(())
}

/// Retrieves a child account by its lock args from the file system.
///
/// **Parameters**:
/// - `lock_args: &str` - The hex-encoded lock script's arguments corresponding to the SPHINCS+ public key of the retrieved child account.
///
/// **Returns**:
/// - `Result<Option<SphincsPlusAccount>, KeyVaultDBError>` - The child key if found, `None` if not found, or an error if retrieval fails.
pub fn get_account(lock_args: &str) -> Result<Option<SphincsPlusAccount>, KeyVaultDBError> {
    let accounts = load_accounts()?;
    Ok(accounts.get(lock_args).cloned())
}

/// Clears the master seed file.
///
/// **Returns**:
/// - `Result<(), KeyVaultDBError>` - Ok on success, or an error if the operation fails.
pub fn clear_master_seed() -> Result<(), KeyVaultDBError> {
    let path = get_master_seed_path()?;
    if path.exists() {
        fs::remove_file(path)?;
    }
    Ok(())
}

/// Clears the accounts file.
///
/// **Returns**:
/// - `Result<(), KeyVaultDBError>` - Ok on success, or an error if the operation fails.
pub fn clear_accounts() -> Result<(), KeyVaultDBError> {
    let path = get_accounts_path()?;
    if path.exists() {
        fs::remove_file(path)?;
    }
    Ok(())
}

/// Gets all accounts sorted by index.
///
/// **Returns**:
/// - `Result<Vec<SphincsPlusAccount>, KeyVaultDBError>` - All accounts sorted by index on success.
pub fn get_all_accounts() -> Result<Vec<SphincsPlusAccount>, KeyVaultDBError> {
    let accounts = load_accounts()?;
    let mut account_list: Vec<SphincsPlusAccount> = accounts.into_values().collect();
    account_list.sort_by_key(|a| a.index);
    Ok(account_list)
}

/// Gets the count of stored accounts.
///
/// **Returns**:
/// - `Result<usize, KeyVaultDBError>` - The count of accounts.
pub fn get_account_count() -> Result<usize, KeyVaultDBError> {
    let accounts = load_accounts()?;
    Ok(accounts.len())
}

/// Stores wallet info in the file system.
///
/// **Parameters**:
/// - `info: WalletInfo` - The wallet info to store.
///
/// **Returns**:
/// - `Result<(), KeyVaultDBError>` - Ok on success, or an error if storage fails.
pub fn set_wallet_info(info: WalletInfo) -> Result<(), KeyVaultDBError> {
    let path = get_wallet_info_path()?;
    let json = serde_json::to_string_pretty(&info)?;
    let mut file = File::create(path)?;
    file.write_all(json.as_bytes())?;
    Ok(())
}

/// Retrieves wallet info from the file system.
///
/// **Returns**:
/// - `Result<Option<WalletInfo>, KeyVaultDBError>` - The wallet info if it exists, `None` if not found, or an error if retrieval fails.
pub fn get_wallet_info() -> Result<Option<WalletInfo>, KeyVaultDBError> {
    let path = get_wallet_info_path()?;

    if !path.exists() {
        return Ok(None);
    }

    let mut file = File::open(path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    let info: WalletInfo = serde_json::from_str(&contents)?;
    Ok(Some(info))
}

/// Clears the wallet info file.
///
/// **Returns**:
/// - `Result<(), KeyVaultDBError>` - Ok on success, or an error if the operation fails.
pub fn clear_wallet_info() -> Result<(), KeyVaultDBError> {
    let path = get_wallet_info_path()?;
    if path.exists() {
        fs::remove_file(path)?;
    }
    Ok(())
}
