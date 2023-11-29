use std::marker::PhantomData;
use std::time::Duration;

use crate::source::JwksSource;
use crate::JwksClient;

pub struct JwksClientBuilder<T> {
    ttl_opt: Option<Duration>,
    t: PhantomData<*const T>,
    // New PR to add this?
    // cache_size: Option<usize>,
}

impl<T: JwksSource + Send + Sync + 'static> JwksClientBuilder<T> {
    pub(crate) fn new() -> Self {
        Self {
            ttl_opt: None,
            t: PhantomData,
        }
    }

    pub fn time_to_live(&self, ttl: Duration) -> Self {
        Self {
            ttl_opt: Some(ttl),
            t: PhantomData,
        }
    }

    #[must_use]
    pub fn build(self, source: T) -> JwksClient<T> {
        JwksClient::new(source, self.ttl_opt)
    }
}
