#[macro_export]
macro_rules! debug {
    ($($arg:tt)*) => {
        web_sys::console::log_1(&format!($($arg)*).into());
    }
}

#[macro_export]
macro_rules! spx_keygen {
    ($kg:ty, $n:expr, $seed:expr, $index:expr) => {{
        const N: usize = $n;
        let path = format!("{}{}", KDF_PATH_PREFIX, $index);

        // Spliting the master seed into three length-equal parts.
        let sk_seed: &[u8; N] = $seed[0..N].try_into().expect("Invalid sk seed length");
        let sk_prf: &[u8; N] = $seed[N..2 * N].try_into().expect("Invalid sk prf length");
        let pk_seed: &[u8; N] = $seed[2 * N..3 * N]
            .try_into()
            .expect("Invalid pk seed length");

        let sk_seed_kd: SecureVec = utilities::derive_hkdf_key(sk_seed, path.as_bytes(), N)?;
        let sk_prf_kd: SecureVec = utilities::derive_hkdf_key(sk_prf, path.as_bytes(), N)?;
        let pk_seed_kd: SecureVec = utilities::derive_hkdf_key(pk_seed, path.as_bytes(), N)?;

        let sk_seed_kd_ref: &[u8; N] = sk_seed_kd
            .as_ref()
            .try_into()
            .map_err(|_| "Invalid sk seed length")?;
        let sk_prf_kd_ref: &[u8; N] = sk_prf_kd
            .as_ref()
            .try_into()
            .map_err(|_| "Invalid sk prf length")?;
        let pk_seed_kd_ref: &[u8; N] = pk_seed_kd
            .as_ref()
            .try_into()
            .map_err(|_| "Invalid pk seed length")?;

        let (pub_key, pri_key) =
            <$kg>::keygen_with_seeds(sk_seed_kd_ref, sk_prf_kd_ref, pk_seed_kd_ref);

        Ok((
            SecureVec::from_vec(pub_key.into_bytes().to_vec()),
            SecureVec::from_vec(pri_key.into_bytes().to_vec()),
        ))
    }};
}

#[macro_export]
macro_rules! spx_sign {
    ($module:ident, $pri_key:expr, $message_vec:expr, $variant:expr) => {{
        let pri_key_ref: &[u8; $module::SK_LEN] = $pri_key
            .as_ref()
            .try_into()
            .map_err(|_| JsValue::from_str("Invalid private key length"))?;

        let signing_key = $module::PrivateKey::try_from_bytes(&pri_key_ref)
            .map_err(|e| JsValue::from_str(&format!("Unable to construct private key: {:?}", e)))?;
        let signature = signing_key
            .try_sign($message_vec, &[], true)
            .map_err(|e| JsValue::from_str(&format!("Signing error: {:?}", e)))?;

        let all_in_one_config: [u8; 4] = [
            MULTISIG_RESERVED_FIELD_VALUE,
            REQUIRED_FIRST_N,
            THRESHOLD,
            PUBKEY_NUM,
        ];
        let param_id_and_sign_flag: u8 = ($variant << 1) | 1;

        // The sphincs+ public key is the second half of the private key
        // [sk_seed][sk_prf] [pk_seed][pk_root]
        let pub_key_slice: &[u8] = &pri_key_ref[$module::PK_LEN..$module::SK_LEN];
        let ckb_qr_full_signature = [
            &all_in_one_config[..],
            &[param_id_and_sign_flag],
            &pub_key_slice[..],
            signature.as_slice(),
        ]
        .concat();

        Ok(Uint8Array::from(ckb_qr_full_signature.as_slice()))
    }};
}
