# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-01-15
**Note**: Starting with this release, this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

### ⚠️ BREAKING CHANGES ⚠️

**This release introduces incompatible changes to key derivation. Keys generated with v0.3.0 will be DIFFERENT from those generated with v0.2.5 and earlier.**

- **Switched from Scrypt-based KDF to HKDF-SHA256 for child key derivation**
  - Child keys derived from the same master seed will produce completely different addresses
  - **Migration Impact**: Users MUST migrate assets and reimport the wallet if wish to maintain the master seed.
  - **Backward Incompatibility**: Cannot import mnemonics from v0.2.5 and expect same keys/addresses

### Changed
- Replaced Scrypt with HKDF-SHA256 for KDF
- Removed child key caching; keys are now derived on-the-fly from the master seed
- Increase Scrypt log_n param from 14 to 17 in password hashing
- Extracted database operations to dedicated db layer

### Removed
- Child keys storage and caching mechanism

### Added
- Changelog
- `derive_hkdf_key()` function in utilities module
- `sha2`, `hkdf` dependencies

## [0.2.5] - Earlier
### Added
- Database layer abstraction for master seed and child keys storage
- SPHINCS+ key management for CKB blockchain
- Password-based encryption using AES-GCM
- BIP39 mnemonic support