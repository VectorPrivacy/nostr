use std::collections::{BTreeSet, HashSet};
use std::future::Future;
use std::pin::Pin;

use nostr::prelude::*;
use nostr_database::error::Error;
use nostr_database::prelude::*;
use tokio::sync::RwLock;

const MAX_EVENTS: usize = 35_000;

/// Two generations of seen IDs: when the newer fills, the older is dropped whole. Grows with
/// use, where a preallocated LRU of the full size cost ~1 MB per client before any event.
#[derive(Debug, Default)]
struct Seen {
    current: HashSet<EventId>,
    previous: HashSet<EventId>,
}

impl Seen {
    fn insert(&mut self, id: EventId) {
        self.current.insert(id);
        if self.current.len() >= MAX_EVENTS / 2 {
            self.previous = std::mem::take(&mut self.current);
        }
    }

    fn contains(&self, id: &EventId) -> bool {
        self.current.contains(id) || self.previous.contains(id)
    }
}

/// Memory Database (RAM)
#[derive(Debug, Default)]
pub(crate) struct MemoryEventsTracker {
    tracker: RwLock<Seen>,
}

impl NostrDatabase for MemoryEventsTracker {
    #[inline]
    fn backend(&self) -> &'static str {
        "in-memory-events-tracker"
    }

    fn features(&self) -> Features {
        Features {
            persistent: false,
            event_expiration: false,
            full_text_search: false,
            request_to_vanish: false,
        }
    }

    fn save_event<'a>(
        &'a self,
        event: &'a Event,
    ) -> Pin<Box<dyn Future<Output = Result<SaveEventStatus, Error>> + Send + 'a>> {
        Box::pin(async move {
            // Mark it as seen
            let mut seen_event_ids = self.tracker.write().await;
            seen_event_ids.insert(event.id);

            Ok(SaveEventStatus::Success)
        })
    }

    fn check_id<'a>(
        &'a self,
        event_id: &'a EventId,
    ) -> Pin<Box<dyn Future<Output = Result<DatabaseEventStatus, Error>> + Send + 'a>> {
        Box::pin(async move {
            let seen_event_ids = self.tracker.read().await;

            Ok(if seen_event_ids.contains(event_id) {
                DatabaseEventStatus::Saved
            } else {
                DatabaseEventStatus::NotExistent
            })
        })
    }

    fn event_by_id<'a>(
        &'a self,
        _event_id: &'a EventId,
    ) -> Pin<Box<dyn Future<Output = Result<Option<Event>, Error>> + Send + 'a>> {
        Box::pin(async move { Ok(None) })
    }

    fn count(
        &self,
        _filter: Filter,
    ) -> Pin<Box<dyn Future<Output = Result<usize, Error>> + Send + '_>> {
        Box::pin(async move { Ok(0) })
    }

    fn query(
        &self,
        _filter: Filter,
    ) -> Pin<Box<dyn Future<Output = Result<BTreeSet<Event>, Error>> + Send + '_>> {
        Box::pin(async move { Ok(BTreeSet::new()) })
    }

    fn negentropy_items(
        &self,
        _filter: Filter,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<(EventId, Timestamp)>, Error>> + Send + '_>> {
        Box::pin(async move { Ok(Vec::new()) })
    }

    fn delete(
        &self,
        _filter: Filter,
    ) -> Pin<Box<dyn Future<Output = Result<(), Error>> + Send + '_>> {
        Box::pin(async move {
            Err(Error::unsupported(
                "delete is not supported for the in-memory events tracker",
            ))
        })
    }

    fn wipe(&self) -> Pin<Box<dyn Future<Output = Result<(), Error>> + Send + '_>> {
        Box::pin(async move {
            *self.tracker.write().await = Seen::default();
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: usize) -> EventId {
        let mut b = [0u8; 32];
        b[..8].copy_from_slice(&(n as u64).to_le_bytes());
        EventId::from_byte_array(b)
    }

    #[test]
    fn it_remembers_the_newest_and_drops_the_oldest() {
        let mut seen = Seen::default();
        for n in 0..MAX_EVENTS + MAX_EVENTS / 4 {
            seen.insert(id(n));
        }
        assert!(seen.current.len() + seen.previous.len() <= MAX_EVENTS);
        assert!(!seen.contains(&id(0)));
        assert!(seen.contains(&id(MAX_EVENTS)), "the previous generation still answers");
        assert!(seen.contains(&id(MAX_EVENTS + MAX_EVENTS / 4 - 1)));
    }

    #[test]
    fn nothing_is_allocated_before_an_event() {
        let seen = Seen::default();
        assert_eq!(seen.current.capacity() + seen.previous.capacity(), 0);
    }
}
