use std::sync::Arc;

use nostr::error::{Error, ErrorKind};
use nostr::event::{Event, Kind};
use nostr_database::NostrDatabase;
use nostr_gossip::NostrGossip;

use crate::authenticator::Authenticator;
use crate::monitor::Monitor;
use crate::policy::AdmitPolicy;
use crate::transport::websocket::WebSocketTransport;
use crate::verification_cache::VerificationCache;

#[derive(Debug, Clone)]
pub(crate) struct SharedState {
    pub(crate) database: Arc<dyn NostrDatabase>,
    pub(crate) transport: Arc<dyn WebSocketTransport>,
    pub(crate) gossip: Option<Arc<dyn NostrGossip>>,
    verification_cache: VerificationCache,
    pub(crate) admit_policy: Option<Arc<dyn AdmitPolicy>>,
    pub(crate) authenticator: Option<Arc<dyn Authenticator>>,
    pub(crate) monitor: Option<Monitor>,
}

impl SharedState {
    pub(crate) fn new(
        database: Arc<dyn NostrDatabase>,
        transport: Arc<dyn WebSocketTransport>,
        gossip: Option<Arc<dyn NostrGossip>>,
        admit_policy: Option<Arc<dyn AdmitPolicy>>,
        authenticator: Option<Arc<dyn Authenticator>>,
        monitor: Option<Monitor>,
    ) -> Self {
        Self {
            database,
            transport,
            gossip,
            verification_cache: VerificationCache::shared(),
            admit_policy,
            authenticator,
            monitor,
        }
    }

    #[inline]
    pub(crate) fn database(&self) -> &Arc<dyn NostrDatabase> {
        &self.database
    }

    #[inline]
    pub(crate) fn is_authenticator_available(&self) -> bool {
        self.authenticator.is_some()
    }

    /// Check if the event was already verified or verify it.
    ///
    /// This is useful if someone continues to send the same invalid event:
    /// since invalid events aren't stored in the database,
    /// skipping this check would result in the re-verification of the event.
    /// This may also be useful to avoid double verification if the event is received at the exact same time by many different Relay instances.
    ///
    /// This is important since event signature verification is a heavy job!
    pub(crate) async fn verify_and_cache(&self, event: &Event) -> Result<(), Error> {
        // The ID is sent by the relay: recompute it before trusting the cache,
        // so a cache hit only skips the signature check of identical event data.
        if !event.verify_id() {
            return Err(Error::with_static_message(
                ErrorKind::Invalid,
                "Invalid event ID",
            ));
        }

        // NIP-59: a gift wrap is signed by a throwaway key, so its signature proves nothing;
        // authorship rides the seal inside, which readers verify. The ID check above still binds.
        if event.kind == Kind::GiftWrap {
            return Ok(());
        }

        // Full IDs avoid treating a hash collision as proof of event verification.
        if !self.verification_cache.verify_signature(event) {
            return Err(Error::with_static_message(
                ErrorKind::Invalid,
                "Invalid signature",
            ));
        }

        Ok(())
    }
}
