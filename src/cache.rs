use std::future::Future;
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
    inner: Arc<RwLock<Entry<JsonWebKeySet>>>,
    time_to_live: Duration,
}

impl Cache {
    pub fn new(time_to_live: StdDuration) -> Self {
        let ttl: Duration = Duration::from_std(time_to_live)
            .expect("Failed to convert from `std::time::Duration` to `chrono::Duration`");
        let json_web_key_set: JsonWebKeySet = JsonWebKeySet::empty();

        Self {
            inner: Arc::new(RwLock::new(Entry::new(&json_web_key_set, &ttl))),
            time_to_live: ttl,
        }
    }

    pub async fn get_or_refresh<F>(&self, key: &str, future: F) -> Result<JsonWebKey, Error>
    where
        F: Future<Output = Result<JsonWebKeySet, Error>> + Send + 'static,
    {
        let read: RwLockReadGuard<Entry<JsonWebKeySet>> = self.inner.read().await;
        let entry: Entry<JsonWebKeySet> = (*read).clone();
        // Drop RwLock read guard prematurely to be able to write in the lock
        drop(read);

        match entry.value.get_key(key) {
            // Key not found. Maybe a refresh is needed
            Err(_) => self.try_refresh(future).await.and_then(|v| v.take_key(key)),
            // Specified key exist but a refresh is needed
            Ok(json_web_key) if entry.is_expired() => self
                .try_refresh(future)
                .await
                .and_then(|v| v.take_key(key))
                .or_else(|_| Ok(json_web_key.to_owned())),
            // Specified key exist and is still valid. Return this one
            Ok(key) => Ok(key.to_owned()),
        }
    }

    async fn try_refresh<F>(&self, future: F) -> Result<JsonWebKeySet, Error>
    where
        F: Future<Output = Result<JsonWebKeySet, Error>> + Send + 'static,
    {
        let set: JsonWebKeySet = future.await?;
        let mut guard: RwLockWriteGuard<Entry<JsonWebKeySet>> = self.inner.write().await;
        *guard = Entry::new(&set, &self.time_to_live);
        Ok(set)
    }
}

#[derive(Clone)]
pub(crate) struct Entry<V> {
    value: V,
    expire_time_millis: i64,
}

impl<V: Clone> Entry<V> {
    fn new(value: &V, expiration: &Duration) -> Self {
        Self {
            value: value.clone(),
            expire_time_millis: Utc::now().timestamp_millis() + expiration.num_milliseconds(),
        }
    }

    fn is_expired(&self) -> bool {
        Utc::now().timestamp_millis() > self.expire_time_millis
    }
}
