# Quantum Purse key vault

This module provides a secure authentication interface for managing SPHINCS+ cryptographic keys in [QuantumPurse project](https://github.com/tea2x/quantum-purse-web-static.git) using Rust and WebAssembly.

###### <u>Feature list</u>:

| Feature            | Details |
|--------------------|---------|
| **Signature type** | SPHINCS+ |
| **Store model**    | Indexed DB |
| **Mnemonic standard**| Custom BIP39 English |
| **Local encryption** | AES256 |
| **Key derivation** | Scrypt |
| **Authentication** | Password |
| **Password hashing** | Scrypt |

### Custom BIP39
SPHINCS+ offers 12 parameter sets, grouped into three security levels: 128-bit, 192-bit, and 256-bit. These require seeds of 48 bytes, 72 bytes, and 96 bytes respectively, used across key generation and signing.

This library introduces a custom BIP39 mnemonic backup format for each security level of SPHINCS+ as below:

|SPHINCS+ level|BIP39 level|word count      |
|--------------|-----------|----------------|
|128 ~ 48 bytes| 3*16byte  | 3*12 = 36 words|
|192 ~ 72 bytes| 3*24byte  | 3*18 = 54 words|
|256 ~ 96 bytes| 3*32byte  | 3*24 = 72 words|

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
