use super::types::ScryptParam;

// Constants
pub const SALT_LENGTH: usize = 16; // 128-bit salt
pub const IV_LENGTH: usize = 12; // 96-bit IV for AES-GCM
pub const DB_NAME: &str = "quantum_purse";
pub const MASTER_SEED_KEY: &str = "master_seed";
pub const MASTER_SEED_STORE: &str = "master_seed_store";
pub const CHILD_KEYS_STORE: &str = "child_keys_store";
pub const KDF_PATH_PREFIX: &str = "ckb/quantum-purse/sphincs-plus/";

/// Scrypt’s original paper suggests N = 16384 (log_n = 14) for interactive logins via low-entropy passwords.
/// QuantumPurse requires passwords of at least 20 characters together with the following scrypt param to protect the master seed in DB.
/// 
/// Given NIST new security post-quantum standards:
/// 1) Key search on a block cipher with a 128-bit key (e.g. AES128)
/// 3) Key search on a block cipher with a 192-bit key (e.g. AES192)
/// 5) Key search on a block cipher with a 256-bit key (e.g. AES 256)
/// 
/// 0                  128       192       256
/// |---------|---------|---------|---------|
///                         ▲
///         current setup: 152
/// 
/// The security with this setup falls between 1) and 3).
/// Note that this is theoretical because user's password often has lower entropy than expected.
pub const ENC_SCRYPT: ScryptParam = ScryptParam {
    log_n: 18,
    r: 8,
    p: 1,
    len: 32,
};

/// All-in-one quantum resistant lock script configuration
pub const MULTISIG_RESERVED_FIELD_VALUE: u8 = 0x80;
pub const REQUIRED_FIRST_N: u8 = 0x00;
pub const THRESHOLD: u8 = 0x01;
pub const PUBKEY_NUM: u8 = 0x01;
