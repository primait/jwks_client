use std::collections::HashMap;
use std::future::Future;
use std::hash::Hash;
use std::sync::Arc;
use std::time::Duration as StdDuration;

use chrono::{Duration, Utc};
use tokio::sync::RwLock;
use tokio::sync::{Mutex, MutexGuard, RwLockReadGuard, RwLockWriteGuard};

type Map<K, V> = HashMap<K, Mutex<Entry<V>>>;

#[derive(Clone)]
pub struct Cache<K, V> {
    inner: Arc<RwLock<Map<K, V>>>,
    time_to_live: Duration,
}

impl<K: Clone + Eq + Hash, V: Clone> Cache<K, V> {
    pub fn new(time_to_live: StdDuration) -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
            time_to_live: Duration::from_std(time_to_live)
                .expect("Failed to convert from `std::time::Duration` to `chrono::Duration`"),
        }
    }

    pub async fn get_or_try_insert_with<F, E>(&self, key: &K, future: F) -> Result<V, E>
    where
        F: Future<Output = Result<V, E>> + Send + 'static,
        E: Send + Sync + 'static,
    {
        let read: RwLockReadGuard<Map<K, V>> = self.inner.read().await;

        let value: V = match read.get(key) {
            None => {
                // Drop RwLock read guard prematurely to be able to write in the lock
                drop(read);
                let v: V = future.await?;
                self.put::<E>(key, &v).await?;
                v
            }
            Some(mutex) => {
                let mut guard: MutexGuard<Entry<V>> = mutex.lock().await;

                if guard.is_expired() {
                    match future.await {
                        Ok(value) => {
                            // Update guard with new value caught from remote
                            *guard = Entry::new(&value, &self.time_to_live);
                            value
                        }
                        Err(_) => guard.value.clone(),
                    }
                } else {
                    guard.value.clone()
                }
            }
        };

        Ok(value)
    }

    async fn put<E>(&self, key: &K, value: &V) -> Result<Option<Mutex<Entry<V>>>, E>
    where
        E: Send + Sync + 'static,
    {
        let mut guard: RwLockWriteGuard<HashMap<K, Mutex<Entry<V>>>> = self.inner.write().await;

        Ok((*guard).insert(
            key.clone(),
            Mutex::new(Entry::new(value, &self.time_to_live)),
        ))
    }
}

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
