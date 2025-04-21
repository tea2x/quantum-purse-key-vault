# Quantum Purse key vault

This module provides a secure authentication interface for managing SPHINCS+ cryptographic keys in [QuantumPurse project](https://github.com/tea2x/quantum-purse-web-static.git) using Rust and WebAssembly.

### Dependency
- Rust & Cargo
- Wasm-pack
- Npm

### Build
`./build.sh`

### Packaging from dist/
`cd dist`
`npm pack`

### Publishing from dist/
`cd dist`
`npm login`
`npm publish`