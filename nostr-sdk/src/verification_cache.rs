//! Verification cache

use std::fmt;
use std::num::NonZeroUsize;
use std::sync::{Arc, LazyLock, Mutex, MutexGuard, PoisonError};

use lru::LruCache;
use nostr::event::{Event, EventId};

const DEFAULT_CAPACITY: NonZeroUsize = NonZeroUsize::new(128_000).unwrap();

/// IDs of events whose signature checked out. Clones share one cache, which grows with use
/// up to its capacity.
#[derive(Clone)]
pub(crate) struct VerificationCache {
    ids: Arc<Mutex<LruCache<EventId, ()>>>,
    capacity: NonZeroUsize,
}

impl Default for VerificationCache {
    fn default() -> Self {
        Self::new(DEFAULT_CAPACITY)
    }
}

impl fmt::Debug for VerificationCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerificationCache")
            .field("len", &self.lock().len())
            .field("capacity", &self.capacity)
            .finish()
    }
}

impl VerificationCache {
    /// The process's cache. A signature's validity is a property of the event alone, so every
    /// client shares it: an event several of them receive is verified once.
    pub(crate) fn shared() -> Self {
        static SHARED: LazyLock<VerificationCache> = LazyLock::new(VerificationCache::default);
        SHARED.clone()
    }

    pub(crate) fn new(capacity: NonZeroUsize) -> Self {
        Self {
            ids: Arc::new(Mutex::new(LruCache::unbounded())),
            capacity,
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.lock().len()
    }

    #[cfg(test)]
    fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }

    fn lock(&self) -> MutexGuard<'_, LruCache<EventId, ()>> {
        self.ids.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Whether the signature is valid, checking it only for an ID not seen before.
    ///
    /// The caller must have recomputed the event's ID: a hit vouches for the event data that
    /// hashes to that ID, nothing else.
    pub(crate) fn verify_signature(&self, event: &Event) -> bool {
        if self.lock().promote(&event.id) {
            return true;
        }

        // Checked outside the lock, which every client sharing the cache contends on.
        if !event.verify_signature() {
            return false;
        }

        let mut ids = self.lock();
        ids.put(event.id, ());
        if ids.len() > self.capacity.get() {
            ids.pop_lru();
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use nostr::prelude::*;

    use super::*;

    fn note(content: &str) -> Event {
        EventBuilder::new(Kind::TextNote, content)
            .finalize(&Keys::generate())
            .unwrap()
    }

    fn with_bad_signature(mut event: Event) -> Event {
        let mut sig = event.sig.to_bytes();
        sig[10] ^= 1;
        event.sig = Signature::from_slice(&sig).unwrap();
        event
    }

    #[test]
    fn clones_share_what_one_verified() {
        let cache = VerificationCache::default();
        let other = cache.clone();
        let event = note("shared");
        assert!(cache.verify_signature(&event));
        assert_eq!(other.len(), 1);
        assert!(other.verify_signature(&event));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn a_bad_signature_is_never_cached() {
        let cache = VerificationCache::default();
        let event = with_bad_signature(note("forged"));
        assert!(!cache.verify_signature(&event));
        assert!(!cache.verify_signature(&event));
        assert!(cache.is_empty());
    }

    #[test]
    fn it_holds_no_more_than_its_capacity_dropping_the_least_recent() {
        let cache = VerificationCache::new(NonZeroUsize::new(2).unwrap());
        let (a, b, c) = (note("a"), note("b"), note("c"));
        assert!(cache.verify_signature(&a));
        assert!(cache.verify_signature(&b));
        assert!(cache.verify_signature(&a));
        assert!(cache.verify_signature(&c));
        assert_eq!(cache.len(), 2);
        let ids = cache.lock();
        assert!(ids.contains(&a.id) && ids.contains(&c.id) && !ids.contains(&b.id));
    }
}
