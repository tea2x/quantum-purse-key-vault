# Quantum Purse key vault

This module provides a secure authentication interface to manage FIPS205 (formerly SPHINCS+) cryptographic keys for CKB blockchain using Rust and WebAssembly.

###### <u>Feature list</u>:

| Feature               | Details              |
|-----------------------|----------------------|
| **Signature type**    | SPHINCS+             |
| **Store model**       | Indexed DB           |
| **Mnemonic standard** | Custom BIP39 English |
| **Local encryption**  | AES256               |
| **Key derivation**    | Scrypt               |
| **Authentication**    | Password             |
| **Password hashing**  | Scrypt               |

### Custom BIP39
SPHINCS+ offers 12 parameter sets, grouped by three security parameters: 128-bit, 192-bit, and 256-bit. These require seeds of 48 bytes, 72 bytes, and 96 bytes respectively, used across key generation and signing.

This library introduces a custom BIP39 mnemonic backup format for each security parameter of SPHINCS+ as below:

|    SPHINCS+ security parameter      |  BIP39 entropy level  |   Word count    |
|-------------------------------------|-----------------------|-----------------|
|    128 bit ~ 48 bytes ~ 3*16 bytes  |       3*16 bytes      | 3*12 = 36 words |
|    192 bit ~ 72 bytes ~ 3*24 bytes  |       3*24 bytes      | 3*18 = 54 words |
|    256 bit ~ 96 bytes ~ 3*32 bytes  |       3*32 bytes      | 3*24 = 72 words |

###### For example:
- SHA2-256s will require users to back up 72 words of mnemonic seed.
- SHAKE-192s will require users to back up 54 words of mnemonic seed.
- SHA2-128f will require users to back up 36 words of mnemonic seed.

### Dependency
- Rust & Cargo
- Wasm-pack
- Npm

### Build
```shell
# init submodule quantum-resistant-lockscript
git submodule update --init

# run build script
./build.sh

# test
cargo test
```

### Package and publish
```shell
cd dist
npm pack
npm login
npm publish
```

### Usage xample

Refer to [QuantumPurse project](https://github.com/tea2x/quantum-purse-web-static.git).