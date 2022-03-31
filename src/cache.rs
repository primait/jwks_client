use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration as StdDuration;

use chrono::{Duration, Utc};
use tokio::sync::RwLock;
use tokio::sync::{RwLockReadGuard, RwLockWriteGuard};

use crate::error::Error;
use crate::keyset::JsonWebKeySet;
use crate::JsonWebKey;

#[derive(Clone)]
pub struct Cache {
    inner: Arc<RwLock<Entry>>,
    time_to_live: Duration,
    refreshed: Arc<AtomicBool>,
}

impl Cache {
    pub fn new(time_to_live: StdDuration) -> Self {
        let ttl: Duration = Duration::from_std(time_to_live)
            .expect("Failed to convert from `std::time::Duration` to `chrono::Duration`");
        let json_web_key_set: JsonWebKeySet = JsonWebKeySet::empty();

        Self {
            inner: Arc::new(RwLock::new(Entry::new(json_web_key_set, &ttl))),
            time_to_live: ttl,
            refreshed: Arc::new(AtomicBool::new(false)),
        }
    }

    pub async fn get_or_refresh<F>(&self, key: &str, future: F) -> Result<JsonWebKey, Error>
    where
        F: Future<Output = Result<JsonWebKeySet, Error>> + Send + 'static,
    {
        let read: RwLockReadGuard<Entry> = self.inner.read().await;
        let is_entry_expired: bool = (*read).is_expired();
        let get_key_result: Result<JsonWebKey, Error> = (*read).set.get_key(key).cloned();
        // Drop RwLock read guard prematurely to be able to write in the lock
        drop(read);

        match get_key_result {
            // Key not found. Maybe a refresh is needed
            Err(_) => self.try_refresh(future).await.and_then(|v| v.take_key(key)),
            // Specified key exist but a refresh is needed
            Ok(json_web_key) if is_entry_expired => self
                .try_refresh(future)
                .await
                .and_then(|v| v.take_key(key))
                .or(Ok(json_web_key)),
            // Specified key exist and is still valid. Return this one
            Ok(key) => Ok(key),
        }
    }

    async fn try_refresh<F>(&self, future: F) -> Result<JsonWebKeySet, Error>
    where
        F: Future<Output = Result<JsonWebKeySet, Error>> + Send + 'static,
    {
        let mut guard: RwLockWriteGuard<Entry> = self.inner.write().await;
        let _ = self.refreshed.swap(false, Ordering::Relaxed);
        
        if !self.refreshed.load(Ordering::SeqCst) {
            let set: JsonWebKeySet = future.await?;
            *guard = Entry::new(set.clone(), &self.time_to_live);
            let _ = self.refreshed.swap(true, Ordering::Relaxed);
            Ok(set)
        } else {
            Ok((*guard).set.clone())
        }
        // we drop the write guard here so "refresh=true" for the other threads/tasks
    }
}

struct Entry {
    set: JsonWebKeySet,
    expire_time_millis: i64,
}

impl Entry {
    fn new(set: JsonWebKeySet, expiration: &Duration) -> Self {
        Self {
            set,
            expire_time_millis: Utc::now().timestamp_millis() + expiration.num_milliseconds(),
        }
    }

    fn is_expired(&self) -> bool {
        Utc::now().timestamp_millis() > self.expire_time_millis
    }
}
