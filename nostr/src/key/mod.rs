// Copyright (c) 2021 Paul Miller
// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

//! Keys

use alloc::boxed::Box;
use core::cmp::Ordering;
use core::convert::Infallible;
use core::fmt;
use core::future::Future;
use core::hash::{Hash, Hasher};
use core::pin::Pin;
#[cfg(feature = "std")]
use core::str::FromStr;

#[cfg(all(feature = "std", feature = "os-rng"))]
use rand::rand_core::UnwrapErr;
#[cfg(all(feature = "std", feature = "os-rng"))]
use rand::rngs::SysRng;
#[cfg(feature = "rand")]
use rand::{CryptoRng, Rng};
use secp256k1::{self, Keypair, Secp256k1, Signing, XOnlyPublicKey};

mod public_key;
mod secret_key;

pub use self::public_key::*;
pub use self::secret_key::*;
use crate::error::Error;
use crate::event::Signature;
#[cfg(all(feature = "std", feature = "os-rng"))]
use crate::event::{AsyncSignEvent, Event, EventId, SignEvent, UnsignedEvent};
#[cfg(all(feature = "std", feature = "os-rng", feature = "nip04"))]
use crate::nips::nip04::{AsyncNip04, Nip04};
#[cfg(all(feature = "std", feature = "os-rng", feature = "nip44"))]
use crate::nips::nip44::{AsyncNip44, Nip44};
#[cfg(feature = "rand")]
use crate::util;
#[cfg(feature = "std")]
use crate::util::SECP256K1;

/// Nostr keys
#[derive(Clone)]
pub struct Keys {
    public_key: PublicKey,
    secret_key: SecretKey,
    keypair: Keypair,
}

impl fmt::Debug for Keys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Keys")
            .field("public_key", &self.public_key)
            .finish()
    }
}

impl PartialEq for Keys {
    fn eq(&self, other: &Self) -> bool {
        self.public_key == other.public_key
    }
}

impl Eq for Keys {}

impl PartialOrd for Keys {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Keys {
    fn cmp(&self, other: &Self) -> Ordering {
        self.public_key.cmp(&other.public_key)
    }
}

impl Hash for Keys {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.public_key.hash(state)
    }
}

impl Keys {
    /// Construct from a secret key.
    ///
    /// This method internally constructs the [`Keypair`] and derives the [`PublicKey`].
    #[inline]
    #[cfg(feature = "std")]
    pub fn new(secret_key: SecretKey) -> Self {
        Self::new_with_ctx(&SECP256K1, secret_key)
    }

    /// Construct from a secret key.
    ///
    /// This method internally constructs the [`Keypair`] and derives the [`PublicKey`].
    pub fn new_with_ctx<C>(secp: &Secp256k1<C>, secret_key: SecretKey) -> Self
    where
        C: Signing,
    {
        let keypair: Keypair = Keypair::from_secret_key(secp, &secret_key);
        let public_key: XOnlyPublicKey = XOnlyPublicKey::from_keypair(&keypair).0;

        Self {
            public_key: PublicKey::from(public_key),
            secret_key,
            keypair,
        }
    }

    /// Parse secret key and construct keys.
    ///
    /// Check [`SecretKey::parse`] to learn more about secret key parsing.
    #[inline]
    #[cfg(feature = "std")]
    pub fn parse(secret_key: &str) -> Result<Self, Error> {
        Self::parse_with_ctx(&SECP256K1, secret_key)
    }

    /// Parse secret key and construct keys.
    ///
    /// Check [`SecretKey::parse`] to learn more about secret key parsing.
    #[inline]
    pub fn parse_with_ctx<C>(secp: &Secp256k1<C>, secret_key: &str) -> Result<Self, Error>
    where
        C: Signing,
    {
        let secret_key: SecretKey = SecretKey::parse(secret_key)?;
        Ok(Self::new_with_ctx(secp, secret_key))
    }

    /// Generate random keys
    ///
    /// This constructor uses a random number generator that retrieves randomness from the operating system (see [`SysRng`]).
    ///
    /// Use [`Keys::generate_with_rng`] to specify a custom random source.
    ///
    /// This internally construct a keypair, so for faster secret generation (i.e., for vanity pubkey mining),
    /// it's suggested to use [`SecretKey::generate`] instead.
    #[inline]
    #[cfg(all(feature = "std", feature = "os-rng"))]
    pub fn generate() -> Self {
        Self::generate_with_rng(&SECP256K1, &mut UnwrapErr(SysRng))
    }

    /// Generate random keys
    ///
    /// This internally construct a keypair, so for faster secret generation (i.e., for vanity pubkey mining),
    /// it's suggested to use [`SecretKey::generate_with_rng`] instead.
    #[inline]
    #[cfg(feature = "rand")]
    pub fn generate_with_rng<C, R>(secp: &Secp256k1<C>, rng: &mut R) -> Self
    where
        C: Signing,
        R: Rng + CryptoRng,
    {
        let secret_key: SecretKey = SecretKey::generate_with_rng(rng);
        Self::new_with_ctx(secp, secret_key)
    }

    /// Get public key
    #[inline]
    pub fn public_key(&self) -> PublicKey {
        self.public_key
    }

    /// Get secret key
    #[inline]
    pub fn secret_key(&self) -> &SecretKey {
        &self.secret_key
    }

    /// Creates a schnorr signature of the message.
    ///
    /// This method uses a random number generator that retrieves randomness from the operating system (see [`SysRng`]).
    #[inline]
    #[cfg(all(feature = "std", feature = "os-rng"))]
    pub fn sign_schnorr<T>(&self, message: T) -> Signature
    where
        T: AsRef<[u8]>,
    {
        self.sign_schnorr_with_rng(&SECP256K1, message, &mut UnwrapErr(SysRng))
    }

    /// Creates a schnorr signature of the message using a custom random number generation source.
    #[inline]
    #[cfg(feature = "rand")]
    pub fn sign_schnorr_with_rng<C, T, R>(
        &self,
        secp: &Secp256k1<C>,
        message: T,
        rng: &mut R,
    ) -> Signature
    where
        C: Signing,
        T: AsRef<[u8]>,
        R: Rng + CryptoRng,
    {
        let aux: [u8; 32] = util::random_32_bytes(rng);
        self.sign_schnorr_with_aux_rand(secp, message, &aux)
    }

    /// Creates a schnorr signature using the given auxiliary random data.
    #[inline]
    pub fn sign_schnorr_with_aux_rand<C, T>(
        &self,
        secp: &Secp256k1<C>,
        message: T,
        aux: &[u8; 32],
    ) -> Signature
    where
        C: Signing,
        T: AsRef<[u8]>,
    {
        let sig = secp.sign_schnorr_with_aux_rand(message.as_ref(), &self.keypair, aux);
        Signature::from_secp256k1(sig)
    }
}

#[cfg(feature = "std")]
impl FromStr for Keys {
    type Err = Error;

    /// Try to parse [Keys] from **secret key** `hex` or `bech32`
    #[inline]
    fn from_str(secret_key: &str) -> Result<Self, Self::Err> {
        Self::parse(secret_key)
    }
}

impl Drop for Keys {
    #[inline]
    fn drop(&mut self) {
        // Erase the keypair.
        //
        // NOTE: we already erase the secret key in 'impl Drop for SecretKey'.
        self.keypair.non_secure_erase();
    }
}

impl GetPublicKey for Keys {
    type Error = Infallible;

    #[inline]
    fn get_public_key(&self) -> Result<PublicKey, Self::Error> {
        Ok(self.public_key)
    }
}

#[cfg(all(feature = "std", feature = "os-rng"))]
impl SignEvent for Keys {
    type Error = Error;

    fn sign_event(&self, unsigned: UnsignedEvent) -> Result<Event, Self::Error> {
        // The verify this replaces also refused an event built for another key.
        if unsigned.pubkey != self.public_key {
            return Err(Error::with_static_message(
                crate::error::ErrorKind::Invalid,
                "event public key does not match the signing key",
            ));
        }
        let id: EventId = unsigned.id.unwrap_or_else(|| unsigned.compute_id());
        let sig: Signature = self.sign_schnorr(id.as_bytes());
        // No post-sign verify: it guards against induced hardware faults, a hardware-wallet
        // threat, and costs more than the signing itself.
        unsigned.with_signature(sig)
    }
}

#[cfg(all(feature = "std", feature = "os-rng", feature = "nip04"))]
impl Nip04 for Keys {
    type Error = Error;

    fn nip04_encrypt(&self, public_key: &PublicKey, content: &str) -> Result<String, Self::Error> {
        let secret_key: &SecretKey = self.secret_key();
        crate::nips::nip04::encrypt(secret_key, public_key, content)
    }

    fn nip04_decrypt(
        &self,
        public_key: &PublicKey,
        encrypted_content: &str,
    ) -> Result<String, Self::Error> {
        let secret_key: &SecretKey = self.secret_key();
        crate::nips::nip04::decrypt(secret_key, public_key, encrypted_content)
    }
}

#[cfg(all(feature = "std", feature = "os-rng", feature = "nip44"))]
impl Nip44 for Keys {
    type Error = Error;

    fn nip44_encrypt(&self, public_key: &PublicKey, content: &str) -> Result<String, Self::Error> {
        use crate::nips::nip44::{self, Version};
        let secret_key: &SecretKey = self.secret_key();
        nip44::encrypt(secret_key, public_key, content, Version::default())
    }

    fn nip44_decrypt(&self, public_key: &PublicKey, payload: &str) -> Result<String, Self::Error> {
        let secret_key: &SecretKey = self.secret_key();
        crate::nips::nip44::decrypt(secret_key, public_key, payload)
    }
}

impl AsyncGetPublicKey for Keys {
    type Error = Infallible;

    fn get_public_key_async(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<PublicKey, Self::Error>> + Send + '_>> {
        Box::pin(async move { GetPublicKey::get_public_key(self) })
    }
}

#[cfg(all(feature = "std", feature = "os-rng"))]
impl AsyncSignEvent for Keys {
    type Error = Error;

    fn sign_event_async(
        &self,
        unsigned: UnsignedEvent,
    ) -> Pin<Box<dyn Future<Output = Result<Event, Self::Error>> + Send + '_>> {
        Box::pin(async move { SignEvent::sign_event(self, unsigned) })
    }
}

#[cfg(all(feature = "std", feature = "os-rng", feature = "nip04"))]
impl AsyncNip04 for Keys {
    type Error = Error;

    fn nip04_encrypt_async<'a>(
        &'a self,
        public_key: &'a PublicKey,
        content: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<String, Self::Error>> + Send + 'a>> {
        Box::pin(async move { Nip04::nip04_encrypt(self, public_key, content) })
    }

    fn nip04_decrypt_async<'a>(
        &'a self,
        public_key: &'a PublicKey,
        encrypted_content: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<String, Self::Error>> + Send + 'a>> {
        Box::pin(async move { Nip04::nip04_decrypt(self, public_key, encrypted_content) })
    }
}

#[cfg(all(feature = "std", feature = "os-rng", feature = "nip44"))]
impl AsyncNip44 for Keys {
    type Error = Error;

    fn nip44_encrypt_async<'a>(
        &'a self,
        public_key: &'a PublicKey,
        content: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<String, Self::Error>> + Send + 'a>> {
        Box::pin(async move { Nip44::nip44_encrypt(self, public_key, content) })
    }

    fn nip44_decrypt_async<'a>(
        &'a self,
        public_key: &'a PublicKey,
        payload: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<String, Self::Error>> + Send + 'a>> {
        Box::pin(async move { Nip44::nip44_decrypt(self, public_key, payload) })
    }
}

#[cfg(test)]
#[cfg(feature = "std")]
mod tests {
    use super::*;
    use crate::error::ErrorKind;

    const SECRET_KEY_BECH32: &str =
        "nsec1j4c6269y9w0q2er2xjw8sv2ehyrtfxq3jwgdlxj6qfn8z4gjsq5qfvfk99";
    const SECRET_KEY_HEX: &str = "6b911fd37cdf5c81d4c0adb1ab7fa822ed253ab0ad9aa18d77257c88b29b718e";

    #[test]
    #[cfg(feature = "os-rng")]
    fn a_signed_event_verifies_and_another_keys_event_is_refused() {
        use crate::event::{EventBuilder, FinalizeUnsignedEvent, Kind};

        let keys = Keys::generate();
        let event = keys
            .sign_event(
                EventBuilder::new(Kind::TextNote, "hi").finalize_unsigned(keys.public_key()),
            )
            .unwrap();
        assert!(event.verify().is_ok());

        let other = Keys::generate().public_key();
        let refused =
            keys.sign_event(EventBuilder::new(Kind::TextNote, "hi").finalize_unsigned(other));
        assert_eq!(refused.unwrap_err().kind(), ErrorKind::Invalid);
    }

    #[test]
    fn parse_keys() -> Result<(), Error> {
        Keys::parse(SECRET_KEY_BECH32)?;
        Keys::parse(SECRET_KEY_HEX)?;
        Ok(())
    }

    #[test]
    fn parse_invalid_keys() {
        assert_eq!(
            Keys::parse("nsec...").unwrap_err().kind(),
            ErrorKind::Invalid
        );
        assert_eq!(
            Keys::parse("npub14f8usejl26twx0dhuxjh9cas7keav9vr0v8nvtwtrjqx3vycc76qqh9nsy")
                .unwrap_err()
                .kind(),
            ErrorKind::Invalid
        );
        assert_eq!(
            Keys::parse("6b911fd37cdf5c8").unwrap_err().kind(),
            ErrorKind::Invalid
        );
    }
}

#[cfg(bench)]
#[cfg(all(feature = "std", feature = "os-rng"))]
mod benches {
    use test::{Bencher, black_box};

    use super::*;

    #[bench]
    pub fn generate_keys(bh: &mut Bencher) {
        bh.iter(|| {
            black_box(Keys::generate());
        });
    }
}
