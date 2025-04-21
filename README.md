# Quantum Purse key vault

This module provides a secure authentication interface for managing SPHINCS+ cryptographic keys in [QuantumPurse project](https://github.com/tea2x/quantum-purse-web-static.git) using Rust and WebAssembly.

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
