use super::types::ScryptParam;

// Constants
pub const SALT_LENGTH: usize = 16; // 128-bit salt
pub const IV_LENGTH: usize = 12; // 96-bit IV for AES-GCM
pub const KDF_PATH_PREFIX: &str = "ckb/quantum-purse/sphincs-plus/";

/// Scrypt’s original paper suggests N = 16384 (log_n = 14) for interactive logins, but that’s for low-entropy passwords.
/// QuantumPurse requires passwords of at least 20 chars ~ 128 bit security together with the following scrypt param to protect data in DB.
/// Security level for the encryption/decryption keys isn't upgraded with Scrypt, each attacker's guess simply gets longer to run.
/// TODO: Consider scrypt parameters for security/performance
pub const ENC_SCRYPT: ScryptParam = ScryptParam {
    log_n: 14,
    r: 8,
    p: 1,
    len: 32,
};

/// All-in-one quantum resistant lock script configuration
pub const MULTISIG_RESERVED_FIELD_VALUE: u8 = 0x80;
pub const REQUIRED_FIRST_N: u8 = 0x00;
pub const THRESHOLD: u8 = 0x01;
pub const PUBKEY_NUM: u8 = 0x01;
