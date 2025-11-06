# Quantum Purse key vault

A cross-platform CLI tool for managing FIPS205 (formerly SPHINCS+) cryptographic keys for the CKB blockchain using Rust.

###### <u>Feature list</u>:

| Feature               | Details              |
|-----------------------|----------------------|
| **Signature type**    | SPHINCS+             |
| **Store model**       | File-based (JSON)    |
| **Mnemonic standard** | Custom BIP39 English |
| **Local encryption**  | AES256               |
| **Key derivation**    | Scrypt               |
| **Authentication**    | Password             |
| **Password hashing**  | Scrypt               |
| **Platform**          | macOS, Windows, Linux |

### Custom BIP39
BIP39 is chosen as the mnemonic backup format due to its user-friendliness and quantum resistance.

SPHINCS+ offers 12 parameter sets, grouped by three security parameters: 128-bit, 192-bit, and 256-bit. These require seeds of 48 bytes, 72 bytes, and 96 bytes respectively used across key generation and signing. As BIP39 supports max 32 bytes so this library introduces a custom(combined) BIP39 mnemonic backup format for each security parameter of SPHINCS+ as below:

|    SPHINCS+ security parameter      |  BIP39 entropy level  |   Word count    |
|-------------------------------------|-----------------------|-----------------|
|    128 bit ~ 48 bytes ~ 3*16 bytes  |       3*16 bytes      | 3*12 = 36 words |
|    192 bit ~ 72 bytes ~ 3*24 bytes  |       3*24 bytes      | 3*18 = 54 words |
|    256 bit ~ 96 bytes ~ 3*32 bytes  |       3*32 bytes      | 3*24 = 72 words |

###### For example:
- SHA2-256s will require users to back up 72 words of mnemonic phrase.
- SHAKE-192s will require users to back up 54 words of mnemonic phrase.
- SHA2-128f will require users to back up 36 words of mnemonic phrase.

### Key Derivation
Although "BIP32 hardened key derivation" doesn't involve with ECDSA and can fit in the arch of Quantum Purse but because Scrypt has been used already for the local encryption/decryption, I think using Scrypt-based KDF(Key Derivation Function) here will keep this wallet's dependency list minimum. That's why Quantum Purse uses a simple custom KDF based on Scrypt instead of the 'hardened option' from the standard BIP32.

###### Key Tree:
```
master_seed
   ├─ index 0 → sphincs+ key 1
   ├─ index 1 → sphincs+ key 2
   ├─ index 2 → sphincs+ key 3
   └─ ...
```

###### Derivation Flow:
```
master_seed
     │
     ▼
(seed_part1, seed_part2, seed_part3)
     │
     ├─ Scrypt("ckb/quantum-purse/sphincs-plus/", index)
     │
     ▼
(sk_seed, sk_prf, pk_seed)
     │
     ├─ sphincs+_key_gen()
     │
     ▼
(sphincs+ public_key, sphincs+ private_key)
```

### Dependencies
- Rust & Cargo (1.70+)

### Build
```shell
# Build release binary
cargo build --release

# Run tests
cargo test

# Install globally
cargo install --path .
```

### Usage

The CLI provides the following commands:

```shell
# Initialize a new wallet
qpkv init --variant Sha2256S

# ImportMnemonic an existing wallet
qpkv import-mnemonic --variant Sha2256S

# ExportMnemonic seed phrase
qpkv export-mnemonic --variant Sha2256S

# Generate a new account
qpkv new-account --variant Sha2256S

# List all accounts
qpkv list-accounts

# Sign a message
qpkv sign --variant Sha2256S --lock-args <LOCK_ARGS> --message <HEX_MESSAGE>

# Recover accounts
qpkv recover --variant Sha2256S --count 5

# Generate account batch for discovery
qpkv try-gen-batch --variant Sha2256S --start 0 --count 10

# Check password strength
qpkv check-password

# Clear all wallet data
qpkv clear

# Get CKB transaction message hash
qpkv get-message --tx-file <PATH_TO_MOCK_TX>

# Show help
qpkv --help
```

### Data Storage

Wallet data is stored in `~/.quantum-purse/`:
- `master_seed.json` - Encrypted master seed
- `accounts.json` - Encrypted account private keys

### Supported SPHINCS+ Variants

- Sha2128F, Sha2128S
- Sha2192F, Sha2192S
- Sha2256F, Sha2256S
- Shake128F, Shake128S
- Shake192F, Shake192S
- Shake256F, Shake256S