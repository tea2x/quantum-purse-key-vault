/// A secure string type for custom BIP39 menmonic seed words
/// Used in containing BIP39 component/elemental mnemonic word string
/// facilitating custom BIP39 for quantumPurse Keyvault

use std::ops::{Deref, /*DerefMut*/};
use zeroize::Zeroize;

#[derive(Debug)]
pub struct SecureString(String);

impl SecureString {
    pub fn new() -> Self {
        SecureString(String::new())
    }

    pub fn from_utf8(bytes: Vec<u8>) -> Result<Self, std::string::FromUtf8Error> {
        match String::from_utf8(bytes) {
            Ok(s) => Ok(SecureString(s)),
            Err(e) => Err(e),
        }
    }

    pub fn from_string(s: String) -> Self {
        SecureString(s)
    }

    /// Notice: Only used in combining mnemonics to mnemonics.
    /// If used in other cases will introduce unexpected outcomes
    pub fn extend(&mut self, s: &str) {
        if !self.0.is_empty() {
            self.0.push(' ');
        }
        self.0.push_str(s);
    }

    pub fn is_uninitialized(&self) -> bool {
        self.0.as_bytes().iter().all(|&byte| byte == 0)
    }
}

impl Drop for SecureString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Deref for SecureString {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// impl DerefMut for SecureString {
//     fn deref_mut(&mut self) -> &mut Self::Target {
//         &mut self.0
//     }
// }
