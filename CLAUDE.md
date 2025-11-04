# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Quantum Purse Key Vault is a cross-platform CLI tool for secure SPHINCS+ (FIPS-205) key management for the CKB blockchain, built with Rust. It provides quantum-resistant cryptographic signing capabilities with file-based encrypted storage.

## Build Commands

### Initial Setup
```bash
# Initialize the quantum-resistant-lockscript submodule
git submodule update --init
```

### Building
```bash
# Build CLI application
./build.sh
# or
cargo build --release

# Run tests
cargo test

# Install globally
cargo install --path .
```

### Running
```bash
# Run directly from target
./target/release/qpkv --help

# Or if installed
qpkv --help
```

## Architecture

### Core Components

**CLI Interface (`src/main.rs`)**
- Command-line interface built with clap
- Handles user interaction, password input, and command routing
- Commands: init, import, export, new-account, list-accounts, sign, recover, batch, clear, check-password, get-message

**KeyVault (`src/lib.rs`)**
- Core library providing all key management functionality
- Manages master seed generation, account derivation, and transaction signing
- Supports 12 SPHINCS+ parameter sets (128/192/256-bit security levels with SHA2/SHAKE variants)
- Each instance is configured with a specific `SpxVariant`

**Storage Layer (`src/db/mod.rs`)**
- File-based storage in `~/.quantum-purse/` directory
- Two JSON files: `master_seed.json` (encrypted master seed) and `accounts.json` (derived accounts)
- All sensitive data is encrypted before storage using AES-256-GCM
- Uses HashMap in accounts.json with lock_args as keys for fast lookup

**Cryptography (`src/utilities/mod.rs`)**
- AES-256-GCM encryption/decryption for local storage
- Scrypt-based key derivation (both for encryption keys and SPHINCS+ child key derivation)
- Custom KDF instead of BIP32 hardened derivation to minimize dependencies

**Custom BIP39 Implementation**
- Standard BIP39 only supports up to 32 bytes of entropy
- SPHINCS+ requires 48/72/96 bytes depending on security level
- Solution: Combine 3 standard BIP39 mnemonics to create 36/54/72 word phrases
- Example: SHA2-256s requires 72 words (3 × 24 words)

**Key Derivation Flow**
```
master_seed (48/72/96 bytes)
    ↓
(sk_seed, sk_prf, pk_seed) - three N-byte components
    ↓
Scrypt("ckb/quantum-purse/sphincs-plus/{index}", component)
    ↓
(derived_sk_seed, derived_sk_prf, derived_pk_seed)
    ↓
SPHINCS+ keygen
    ↓
(public_key, private_key)
```

**Lock Script Arguments**
- CKB blockchain requires specific script argument format
- Constructed via: Blake2b(all_in_one_config || sign_flag || public_key)
- The hash becomes the lock script argument (address identifier)

### Module Structure

- `src/lib.rs` - Main KeyVault and Util API
- `src/types.rs` - Core types (SpxVariant, CipherPayload, SphincsPlusAccount, ScryptParam)
- `src/db/` - IndexedDB operations
- `src/utilities/` - Cryptographic operations (encrypt/decrypt/derive_scrypt_key/get_random_bytes)
- `src/secure_vec.rs` & `src/secure_string.rs` - Memory-zeroizing wrappers for sensitive data
- `src/macros.rs` - `spx_keygen!` and `spx_sign!` macros for handling 12 SPHINCS+ variants
- `src/constants.rs` - Scrypt parameters, DB names, lock script config
- `crates/ckb-fips205-utils/` - CKB-specific SPHINCS+ utilities for message hashing and signing

### Security Features

1. **Password Requirements**: Minimum 20 characters with uppercase, lowercase, digits, symbols, no consecutive repeats
2. **Scrypt Parameters**:
   - Encryption: log_n=14, r=8, p=1 (interactive login security)
   - KDF: log_n=10, r=8, p=1 (faster for high-entropy seeds)
3. **Memory Safety**: SecureVec and SecureString types auto-zeroize on drop
4. **Secure Password Input**: Uses `rpassword` for hidden terminal input
5. **Data Protection**: All files in `~/.quantum-purse/` contain only encrypted data

## Development Notes

- The `KeyVault` struct is instantiated with a specific `SpxVariant` that determines seed size, mnemonic word count, and key sizes
- Use the `spx_keygen!` and `spx_sign_native!` macros to avoid code duplication across 12 SPHINCS+ variants
- All functions are synchronous and use file I/O for storage
- The project uses standard `getrandom` for CSPRNG
- Lock script arguments serve as the primary key for accounts in the HashMap
- Password input uses `rpassword` crate for secure terminal password reading
- Data directory (`~/.quantum-purse/`) is automatically created on first use
- All user-facing functions clear password buffers immediately after use via SecureVec
