/// A secure vector that zeroizes its contents when dropped.
/// Used in containing sensitive bytes like passwords or master seed.

use std::ops::{Deref, DerefMut};
use zeroize::Zeroize;
#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};
use aes_gcm::aead::{Buffer, Error as AeadError};
#[cfg(test)]
pub static ZEROIZED: AtomicBool = AtomicBool::new(false);

#[derive(Debug)]
pub struct SecureVec(Vec<u8>);

impl SecureVec {
    pub fn new_with_length(len: usize) -> Self {
        SecureVec(vec![0u8; len])
    }

    pub fn from_slice(slice: &[u8]) -> Self {
      SecureVec(slice.to_vec())
    }

    pub fn extend(&mut self, slice: &[u8]) {
        self.0.extend_from_slice(slice);
    }
}

impl Zeroize for SecureVec {
    fn zeroize(&mut self) {
        self.0.zeroize();
        #[cfg(test)]
        ZEROIZED.store(true, Ordering::SeqCst);
    }
}

// impl ZeroizeOnDrop for SecureVec {}
impl Drop for SecureVec {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Deref for SecureVec {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for SecureVec {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl AsRef<[u8]> for SecureVec {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for SecureVec {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl Buffer for SecureVec {
    fn extend_from_slice(&mut self, other: &[u8]) -> Result<(), AeadError> {
        self.0.extend_from_slice(other);
        Ok(())
    }

    fn truncate(&mut self, len: usize) {
        if len < self.0.len() {
            use zeroize::Zeroize;
            self.0[len..].zeroize();
        }
        self.0.truncate(len);
    }

    fn len(&self) -> usize {
        self.0.len()
    }
}
