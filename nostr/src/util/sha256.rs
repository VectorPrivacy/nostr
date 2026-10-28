use alloc::string::String;
use core::fmt;
use core::str::{self, FromStr};

use bitcoin_hashes::sha256;
use serde::{Deserialize, Deserializer, Serialize};

use super::hex_decode;
use crate::error::Error;

const SIZE: usize = 32;

/// SHA-256 hash
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sha256Hash([u8; SIZE]);

impl Sha256Hash {
    /// Construct from a 32-byte array
    #[inline]
    pub const fn from_byte_array(bytes: [u8; SIZE]) -> Self {
        Self(bytes)
    }

    /// Parse from hex string
    pub fn from_hex(hex: &str) -> Result<Self, Error> {
        let bytes: [u8; SIZE] = hex_decode(hex)?;
        Ok(Self::from_byte_array(bytes))
    }

    // With std, event ids stream through `from_engine` instead.
    #[cfg(any(not(feature = "std"), feature = "nip98", test))]
    #[inline]
    pub(crate) fn hash(bytes: &[u8]) -> Self {
        let hash: sha256::Hash = sha256::Hash::hash(bytes);
        Self::from_byte_array(hash.to_byte_array())
    }

    /// The digest of everything `engine` has taken in.
    #[cfg(feature = "std")]
    #[inline]
    pub(crate) fn from_engine(engine: sha256::HashEngine) -> Self {
        Self::from_byte_array(sha256::Hash::from_engine(engine).to_byte_array())
    }

    /// Get as bytes
    #[inline]
    pub fn as_bytes(&self) -> &[u8; SIZE] {
        &self.0
    }

    /// Consume and get bytes
    #[inline]
    pub fn to_bytes(self) -> [u8; SIZE] {
        self.0
    }

    /// Get as hex string
    #[inline]
    pub fn to_hex(&self) -> String {
        // SAFETY: hex is a valid UTF-8
        unsafe { String::from_utf8_unchecked(self.to_hex_byte_array().to_vec()) }
    }

    // Get as hex 64-byte array
    #[inline]
    fn to_hex_byte_array(self) -> [u8; SIZE * 2] {
        let mut buf = [0u8; SIZE * 2];
        faster_hex::hex_encode(self.as_bytes(), &mut buf).expect("Buffer size is correct");
        buf
    }
}

impl fmt::Debug for Sha256Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sha256Hash({})", self.to_hex())
    }
}

impl fmt::Display for Sha256Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl FromStr for Sha256Hash {
    type Err = Error;

    #[inline]
    fn from_str(hash: &str) -> Result<Self, Self::Err> {
        Self::from_hex(hash)
    }
}

impl Serialize for Sha256Hash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let bytes: [u8; SIZE * 2] = self.to_hex_byte_array();
        // SAFETY: hex is a valid UTF-8
        let encoded: &str = unsafe { str::from_utf8_unchecked(&bytes) };
        serializer.serialize_str(encoded)
    }
}

impl<'de> Deserialize<'de> for Sha256Hash {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let id: String = String::deserialize(deserializer)?;
        Self::from_hex(&id).map_err(serde::de::Error::custom)
    }
}
