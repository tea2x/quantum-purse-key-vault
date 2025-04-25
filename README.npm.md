## Quantum Purse Key Vault

This module provides a secure authentication interface for managing SPHINCS+ cryptographic keys in [QuantumPurse project](https://github.com/tea2x/quantum-purse-web-static.git) using Rust and WebAssembly.

## JS interface

```typescript
/* tslint:disable */
/* eslint-disable */
/**
 * ID of all 12 SPHINCS+ variants.
 */
export enum SphincsVariant {
  Sha2128F = 48,
  Sha2128S = 49,
  Sha2192F = 50,
  Sha2192S = 51,
  Sha2256F = 52,
  Sha2256S = 53,
  Shake128F = 54,
  Shake128S = 55,
  Shake192F = 56,
  Shake192S = 57,
  Shake256F = 58,
  Shake256S = 59,
}
/**
 *  Key-vault functions
 */
export class KeyVault {
  free(): void;
  /**
   * Constructs a new `KeyVault` to serve as a namespace in the output js interface.
   *
   * **Returns**:
   * - `KeyVault` - A new instance of the struct.
   */
  constructor(variant: SphincsVariant);
  /**
   * Clears all data in the `seed_phrase_store` and `child_keys_store` in IndexedDB.
   *
   * **Returns**:
   * - `Result<(), JsValue>` - A JavaScript Promise that resolves to `undefined` on success,
   *   or rejects with a JavaScript error on failure.
   *
   * **Async**: Yes
   */
  static clear_database(): Promise<void>;
  /**
   * Retrieves all SPHINCS+ lock script arguments (processed public keys) from the database in the order they get inserted.
   *
   * **Returns**:
   * - `Result<Vec<String>, JsValue>` - A JavaScript Promise that resolves to an array of hex-encoded SPHINCS+ lock script arguments on success,
   *   or rejects with a JavaScript error on failure.
   *
   * **Async**: Yes
   */
  static get_all_sphincs_lock_args(): Promise<string[]>;
  /**
   * Check if there's a master seed stored in the indexDB.
   *
   * **Returns**:
   * - `Result<bool, JsValue>` - A JavaScript Promise that resolves to `true` if a master seed exists,
   *   or `false` if it doesn't.
   *
   * **Async**: Yes
   */
  has_master_seed(): Promise<boolean>;
  /**
   * Generates master seed for your wallet, encrypts it with the provided password, and stores it in IndexedDB.
   *
   * **Parameters**:
   * - `password: Uint8Array` - The password used to encrypt the generated master seed.
   *
   * **Returns**:
   * - `Result<(), JsValue>` - A JavaScript Promise that resolves to `undefined` on success,
   *   or rejects with a JavaScript error on failure.
   *
   * **Async**: Yes
   */
  generate_master_seed(password: Uint8Array): Promise<void>;
  /**
   * Generates a new SPHINCS+ account - a SPHINCS+ child account derived from the master seed,
   * encrypts the private key with the password, and stores/appends it in IndexedDB.
   *
   * **Parameters**:
   * - `password: Uint8Array` - The password used to decrypt the master seed and encrypt the child private key.
   *
   * **Returns**:
   * - `Result<String, JsValue>` - A String Promise that resolves to the hex-encoded SPHINCS+ lock argument (processed SPHINCS+ public key) of the account on success,
   *   or rejects with a JavaScript error on failure.
   *
   * **Async**: Yes
   */
  gen_new_account(password: Uint8Array): Promise<string>;
  /**
   * Imports master seed then encrypting it with the provided password.
   *
   * **Parameters**:
   * - `seed_phrase: Uint8Array` - The mnemonic phrase as a valid UTF-8 encoded Uint8Array to import. There're only 3 options accepted: 36, 54 or 72 words.
   * - `password: Uint8Array` - The password used to encrypt the translated master seed.
   *
   * **Returns**:
   * - `Result<(), JsValue>` - A JavaScript Promise that resolves to `undefined` on success,
   *   or rejects with a JavaScript error on failure.
   *
   * **Async**: Yes
   *
   * **Warning**: Handle the mnemonic in JavaScript side carefully.
   */
  import_seed_phrase(seed_phrase: Uint8Array, password: Uint8Array): Promise<void>;
  /**
   * Exports the master seed in the form of a custom bip39 mnemonic phrase. There're only 3 options: 36, 54 or 72 words.
   *
   * **Parameters**:
   * - `password: Uint8Array` - The password used to decrypt the master seed.
   *
   * **Returns**:
   * - `Result<Uint8Array, JsValue>` - A JavaScript Promise that resolves to the mnemonic as a UTF-8 encoded `Uint8Array` on success,
   *   or rejects with a JavaScript error on failure.
   *
   * **Async**: Yes
   *
   * **Warning**: Exporting the mnemonic exposes it in JavaScript, which may pose a security risk.
   * Proper zeroization of exported seed phrase is the responsibility of the caller.
   */
  export_seed_phrase(password: Uint8Array): Promise<Uint8Array>;
  /**
   * Signs a message using the SPHINCS+ private key after decrypting it with the provided password.
   *
   * **Parameters**:
   * - `password: Uint8Array` - The password used to decrypt the private key.
   * - `lock_args: String` - The hex-encoded lock script's arguments corresponding to the SPHINCS+ public key of the account that signs.
   * - `message: Uint8Array` - The message to be signed.
   *
   * **Returns**:
   * - `Result<Uint8Array, JsValue>` - The signature as a `Uint8Array` on success,
   *   or a JavaScript error on failure.
   *
   * **Async**: Yes
   */
  sign(password: Uint8Array, lock_args: string, message: Uint8Array): Promise<Uint8Array>;
  /**
   * Supporting wallet recovery - quickly derives a list of lock script arguments (processed public keys).
   *
   * **Parameters**:
   * - `password: Uint8Array` - The password used to decrypt the master seed used for account generation.
   * - `start_index: u32` - The starting index for derivation.
   * - `count: u32` - The number of sequential lock scripts arguments to derive.
   *
   * **Returns**:
   * - `Result<Vec<String>, JsValue>` - A list of lock script arguments on success,
   *   or a JavaScript error on failure.
   */
  try_gen_account_batch(password: Uint8Array, start_index: number, count: number): Promise<string[]>;
  /**
   * Supporting wallet recovery - Recovers the wallet by deriving and storing private keys for the first N accounts.
   *
   * **Parameters**:
   * - `password: Uint8Array` - The password used to decrypt the master seed.
   * - `count: u32` - The number of accounts to recover (from index 0 to count-1).
   *
   * **Returns**:
   * - `Result<(), JsValue>` - A list of newly generated sphincs+ lock script arguments (processed public keys) on success, or a JavaScript error on failure.
   *
   * **Async**: Yes
   */
  recover_accounts(password: Uint8Array, count: number): Promise<string[]>;
  /**
   * The one parameter set chosen for QuantumPurse KeyVault setup in all 12 NIST-approved SPHINCS+ FIPS205 variants
   */
  variant: SphincsVariant;
}
/**
 *  Key-vault utility functions
 */
export class Util {
  private constructor();
  free(): void;
  /**
   * https://github.com/xxuejie/rfcs/blob/cighash-all/rfcs/0000-ckb-tx-message-all/0000-ckb-tx-message-all.md.
   *
   * **Parameters**:
   * - `serialized_mock_tx: Uint8Array` - serialized CKB mock transaction.
   *
   * **Returns**:
   * - `Result<Uint8Array, JsValue>` - The CKB transaction message all hash digest as a `Uint8Array` on success,
   *   or a JavaScript error on failure.
   *
   * **Async**: no
   */
  static get_ckb_tx_message_all(serialized_mock_tx: Uint8Array): Uint8Array;
  /**
   * Measure bit strength of a password
   *
   * **Parameters**:
   * - `password: Uint8Array` - utf8 serialized password.
   *
   * **Returns**:
   * - `Result<u16, JsValue>` - The strength of the password measured in bit on success,
   *   or a JavaScript error on failure.
   *
   * **Async**: no
   */
  static password_checker(password: Uint8Array): number;
}

/**
* If `module_or_path` is {RequestInfo} or {URL}, makes a request and
* for everything else, calls `WebAssembly.instantiate` directly.
*
* @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
*
* @returns {Promise<InitOutput>}
*/
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
```

## Example

Refer to [QuantumPurse project](https://github.com/tea2x/quantum-purse-web-static.git)