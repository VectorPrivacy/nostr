//! Verification cache

use std::collections::HashSet;
use std::fmt;
use std::num::NonZeroUsize;
use std::sync::{Arc, LazyLock, Mutex, MutexGuard, PoisonError};

use nostr::event::{Event, EventId};

/// The same event reaches every relay within seconds, so a short window keeps the hits.
const DEFAULT_CAPACITY: NonZeroUsize = NonZeroUsize::new(32_000).unwrap();

/// Two generations of IDs: when the newer fills, the older is dropped whole. A table, not a
/// linked list, so an entry costs no allocation of its own.
#[derive(Default)]
struct Generations {
    current: HashSet<EventId>,
    previous: HashSet<EventId>,
}

impl Generations {
    fn len(&self) -> usize {
        self.current.len() + self.previous.len()
    }

    #[cfg(test)]
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[cfg(test)]
    fn contains(&self, id: &EventId) -> bool {
        self.current.contains(id) || self.previous.contains(id)
    }
}

/// IDs of events whose signature checked out. Clones share one cache, which grows with use
/// up to its capacity.
#[derive(Clone)]
pub(crate) struct VerificationCache {
    ids: Arc<Mutex<Generations>>,
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
            ids: Arc::new(Mutex::new(Generations::default())),
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

    fn lock(&self) -> MutexGuard<'_, Generations> {
        self.ids.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Whether the signature is valid, checking it only for an ID not seen before.
    ///
    /// The caller must have recomputed the event's ID: a hit vouches for the event data that
    /// hashes to that ID, nothing else.
    pub(crate) fn verify_signature(&self, event: &Event) -> bool {
        {
            let mut ids = self.lock();
            if ids.current.contains(&event.id) {
                return true;
            }
            if ids.previous.contains(&event.id) {
                self.remember(&mut ids, event.id);
                return true;
            }
        }

        // Checked outside the lock, which every client sharing the cache contends on.
        if !event.verify_signature() {
            return false;
        }

        let mut ids = self.lock();
        self.remember(&mut ids, event.id);
        true
    }

    fn remember(&self, ids: &mut Generations, id: EventId) {
        ids.current.insert(id);
        if ids.current.len() >= self.capacity.get().div_ceil(2) {
            ids.previous = std::mem::take(&mut ids.current);
        }
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
    fn it_holds_no_more_than_its_capacity_dropping_the_oldest() {
        let cache = VerificationCache::new(NonZeroUsize::new(4).unwrap());
        let events: Vec<Event> = (0..7).map(|i| note(&i.to_string())).collect();
        for e in &events[..5] {
            assert!(cache.verify_signature(e));
        }
        assert!(cache.len() <= 4);
        let ids = cache.lock();
        assert!(!ids.contains(&events[0].id) && !ids.contains(&events[1].id));
        assert!(ids.contains(&events[2].id) && ids.contains(&events[3].id) && ids.contains(&events[4].id));
    }

    #[test]
    fn a_hit_in_the_older_generation_survives_the_next_turnover() {
        let cache = VerificationCache::new(NonZeroUsize::new(4).unwrap());
        let events: Vec<Event> = (0..5).map(|i| note(&i.to_string())).collect();
        assert!(cache.verify_signature(&events[0]));
        assert!(cache.verify_signature(&events[1]));
        // 0 and 1 are now the older generation; seeing 0 again carries it forward.
        assert!(cache.verify_signature(&events[0]));
        assert!(cache.verify_signature(&events[2]));
        assert!(cache.verify_signature(&events[3]));
        let ids = cache.lock();
        assert!(ids.contains(&events[0].id) && !ids.contains(&events[1].id));
    }

    #[test]
    fn the_older_generation_still_answers() {
        let cache = VerificationCache::new(NonZeroUsize::new(4).unwrap());
        let (a, b) = (note("a"), note("b"));
        assert!(cache.verify_signature(&a));
        assert!(cache.verify_signature(&b));
        assert!(cache.lock().current.is_empty(), "a and b moved to the older generation");
        assert!(cache.verify_signature(&with_bad_signature(b)));
    }

    #[test]
    fn a_cached_id_answers_without_rechecking() {
        let cache = VerificationCache::default();
        let event = note("once");
        assert!(cache.verify_signature(&event));
        // Same id, broken signature: only a hit can answer true.
        assert!(cache.verify_signature(&with_bad_signature(event)));
    }
}
