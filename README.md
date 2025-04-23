# Quantum Purse key vault

This module provides a secure authentication interface for managing SPHINCS+ cryptographic keys in [QuantumPurse project](https://github.com/tea2x/quantum-purse-web-static.git) using Rust and WebAssembly.

###### <u>Feature list</u>:

| Feature            | Details |
|--------------------|---------|
| **Signature type** | SPHINCS+ |
| **Store model**    | Indexed DB |
| **Mnemonic standard**| Custom BIP39 |
| **Local encryption** | AES256 |
| **Key derivation** | Scrypt |
| **Authentication** | Password |
| **Password hashing** | Scrypt |

### Custom BIP39
SPHINCS+ has 12 parameter sets, catergorized in 3 security levels 128bit, 192bit and 256bit security that require 48bytes, 72bytes and 96bytes seeds respectively in key generation and signing.

BIP39 by maximum only support 32byte which is equivalent to 24 words.

This library combine multiple chunks of 32byte-24word mnemonic phrase to use the seed backup format. This leads to the following definition of the seed length for 3 SPHINCS+ categories:

|SPHINCS+ level|BIP39 level|word count|
|--------|---------|----------------|
|48 bytes| 3*16byte| 3*12 = 36 words|
|72 bytes| 3*24byte| 3*18 = 54 words|
|96 bytes| 3*32byte| 3*24 = 72 words|

### Dependency
- Rust & Cargo
- Wasm-pack
- Npm

### Build
`./build.sh`

### Package and publish
```
cd dist
npm pack
npm login
npm publish
```
