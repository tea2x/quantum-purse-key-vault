## Quantum Purse Key Vault

This module provides a secure authentication interface for managing SPHINCS+ cryptographic keys in Web application using Rust and WebAssembly.

## JS interface

```typescript
/* tslint:disable */
/* eslint-disable */
/**
 * ID of all 12 SPHINCS+ variants following https://github.com/cryptape/quantum-resistant-lock-script/
 */
export enum SpxVariant {
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
  constructor(variant: SpxVariant);
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
   * Throw if the master seed already exists.
   *
   * **Parameters**:
   * - `js_password: Uint8Array` - The password used to encrypt the generated master seed, input from js env. Must not be empty or uninitialized.
   *
   * **Returns**:
   * - `Result<(), JsValue>` - A JavaScript Promise that resolves to `undefined` on success,
   *   or rejects with a JavaScript error on failure.
   *
   * **Async**: Yes
   * 
   * **Notes**:
   * - The provided `js_password` buffer is cleared immediately after use.
   */
  generate_master_seed(js_password: Uint8Array): Promise<void>;
  /**
   * Generates a new SPHINCS+ account - a SPHINCS+ Lock Script arguments that can be encoded to CKB quantum safe addresses at higher layers.
   *
   * **Parameters**:
   * - `js_password: Uint8Array` - The password used to decrypt the master seed and encrypt the child private key, input from js env. Must not be empty or uninitialized.
   *
   * **Returns**:
   * - `Result<String, JsValue>` - A String Promise that resolves to the hex-encoded SPHINCS+ lock argument (processed SPHINCS+ public key) of the account on success,
   *   or rejects with a JavaScript error on failure.
   *
   * **Async**: Yes
   * 
   * **Notes**:
   * - The provided `js_password` buffer is cleared immediately after use.
   */
  gen_new_account(js_password: Uint8Array): Promise<string>;
  /**
   * Imports master seed then encrypting it with the provided password.
   * Overwrite the existing master seed.
   *
   * **Parameters**:
   * - `js_seed_phrase: Uint8Array` - The mnemonic phrase as a valid UTF-8 encoded Uint8Array to import, input from js env.
   *    There're only 3 options accepted: 36, 54 or 72 words.
   * - `js_password: Uint8Array` - The password used to encrypt the translated master seed, input from js env. Must not be empty or uninitialized.
   *
   * **Returns**:
   * - `Result<(), JsValue>` - A JavaScript Promise that resolves to `undefined` on success,
   *   or rejects with a JavaScript error on failure.
   *
   * **Async**: Yes
   *
   * **Notes**:
   * - The provided `js_password` and the js_seed_phrase buffers are cleared immediately after use.
   */
  import_seed_phrase(js_seed_phrase: Uint8Array, js_password: Uint8Array): Promise<void>;
  /**
   * Exports the master seed in the form of a custom bip39 mnemonic phrase. There're only 3 options: 36, 54 or 72 words.
   *
   * **Parameters**:
   * - `js_password: Uint8Array` - The password used to decrypt the master seed, input from js env. Must not be empty or uninitialized.
   *
   * **Returns**:
   * - `Result<Uint8Array, JsValue>` - A JavaScript Promise that resolves to the mnemonic as a UTF-8 encoded `Uint8Array` on success,
   *   or rejects with a JavaScript error on failure.
   *
   * **Async**: Yes
   *
   * **Warning**: Exporting the mnemonic exposes it in JavaScript may pose a security risk.
   * 
   * **Async**: Yes
   * 
   * **Notes**:
   * - The provided `js_password` buffer is cleared immediately after use.
   */
  export_seed_phrase(js_password: Uint8Array): Promise<Uint8Array>;
  /**
   * Sign and produce a valid signature for the Quantum Resistant lock script.
   *
   * **Parameters**:
   * - `js_password: Uint8Array` - The password used to decrypt the private key, input from js env. Must not be empty or uninitialized.
   * - `lock_args: String` - The hex-encoded lock script's arguments corresponding to the SPHINCS+ public key of the account that signs.
   *    This is a CKB specific thing, check https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0022-transaction-structure/script-p2.png for more information.
   * - `message: Uint8Array` - The message to be signed.
   *
   * **Returns**:
   * - `Result<Uint8Array, JsValue>` - The signature as a `Uint8Array` on success,
   *   or a JavaScript error on failure.
   *
   * **Async**: Yes
   * 
   * **Notes**:
   * - The provided `js_password` buffer is cleared immediately after use.
   */
  sign(js_password: Uint8Array, lock_args: string, message: Uint8Array): Promise<Uint8Array>;
  /**
   * Supporting wallet recovery - quickly derives a list of lock script arguments (processed public keys).
   *
   * **Parameters**:
   * - `js_password: Uint8Array` - The password used to decrypt the master seed used for account generation, input from js env. Must not be empty or uninitialized.
   * - `start_index: u32` - The starting index for derivation.
   * - `count: u32` - The number of sequential lock scripts arguments to derive.
   *
   * **Returns**:
   * - `Result<Vec<String>, JsValue>` - A list of lock script arguments on success,
   *   or a JavaScript error on failure.
   * 
   * **Async**: Yes
   * 
   * **Notes**:
   * - The provided `js_password` buffer is cleared immediately after use.
   */
  try_gen_account_batch(js_password: Uint8Array, start_index: number, count: number): Promise<string[]>;
  /**
   * Supporting wallet recovery - Recovers the wallet by deriving and caching quantum-safe Lock Script arguments for the first N addresses.
   *
   * **Parameters**:
   * - `js_password: Uint8Array` - The password used to decrypt the master seed, input from js env. Must not be empty or uninitialized.
   * - `count: u32` - The number of accounts to recover (from index 0 to count-1).
   *
   * **Returns**:
   * - `Result<(), JsValue>` - A list of newly generated sphincs+ lock script arguments (processed public keys) on success, or a JavaScript error on failure.
   *
   * **Async**: Yes
   * 
   * **Notes**:
   * - The provided `js_password` buffer is cleared immediately after use.
   */
  recover_accounts(js_password: Uint8Array, count: number): Promise<string[]>;
  /**
   * The one parameter set chosen for QuantumPurse KeyVault setup in all 12 NIST-approved SPHINCS+ FIPS205 variants
   */
  variant: SpxVariant;
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
   * Check strength of a password.
   * There is no official weighting system to calculate the strength of a password.
   * This is just a simple implementation for ASCII passwords. Feel free to use your own password checker.
   * By default will require at least 20 characters
   *
   * **Parameters**:
   * - `js_password: Uint8Array` - utf8 serialized password, input from js env. Must not be empty or uninitialized.
   *
   * **Returns**:
   * - `Result<u16, JsValue>` - The strength of the password measured in bit on success,
   *   or a JavaScript error on failure.
   *
   * **Async**: no
   * 
   * **Notes**:
   * - The provided `js_password` buffer is cleared immediately after use.
   */
  static password_checker(js_password: Uint8Array): number;
}

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly __wbg_keyvault_free: (a: number, b: number) => void;
  readonly __wbg_get_keyvault_variant: (a: number) => number;
  readonly __wbg_set_keyvault_variant: (a: number, b: number) => void;
  readonly keyvault_new: (a: number) => number;
  readonly keyvault_clear_database: () => any;
  readonly keyvault_get_all_sphincs_lock_args: () => any;
  readonly keyvault_has_master_seed: (a: number) => any;
  readonly keyvault_generate_master_seed: (a: number, b: any) => any;
  readonly keyvault_gen_new_account: (a: number, b: any) => any;
  readonly keyvault_import_seed_phrase: (a: number, b: any, c: any) => any;
  readonly keyvault_export_seed_phrase: (a: number, b: any) => any;
  readonly keyvault_sign: (a: number, b: any, c: number, d: number, e: any) => any;
  readonly keyvault_try_gen_account_batch: (a: number, b: any, c: number, d: number) => any;
  readonly keyvault_recover_accounts: (a: number, b: any, c: number) => any;
  readonly __wbg_util_free: (a: number, b: number) => void;
  readonly util_get_ckb_tx_message_all: (a: any) => [number, number, number];
  readonly util_password_checker: (a: any) => [number, number, number];
  readonly __wbindgen_malloc: (a: number, b: number) => number;
  readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
  readonly __wbindgen_exn_store: (a: number) => void;
  readonly __externref_table_alloc: () => number;
  readonly __wbindgen_export_4: WebAssembly.Table;
  readonly __wbindgen_export_5: WebAssembly.Table;
  readonly __externref_table_dealloc: (a: number) => void;
  readonly closure89_externref_shim_multivalue_shim: (a: number, b: number, c: any) => [number, number];
  readonly closure143_externref_shim: (a: number, b: number, c: any) => void;
  readonly closure166_externref_shim: (a: number, b: number, c: any) => void;
  readonly _dyn_core__ops__function__FnMut_____Output___R_as_wasm_bindgen__closure__WasmClosure___describe__invoke__h6a08b498e20e740b: (a: number, b: number) => void;
  readonly closure242_externref_shim: (a: number, b: number, c: any, d: any) => void;
  readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;
/**
* Instantiates the given `module`, which can either be bytes or
* a precompiled `WebAssembly.Module`.
*
* @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
*
* @returns {InitOutput}
*/
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

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

Refer to [QuantumPurse project](https://github.com/tea2x/quantum-purse.git)