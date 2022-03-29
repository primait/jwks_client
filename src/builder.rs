use crate::source::JwksSource;
use crate::JwksClient;
use std::marker::PhantomData;
use std::time::Duration;

pub struct JwksClientBuilder<T> {
    ttl_opt: Option<Duration>,
    t: PhantomData<T>,
    // cache_size: Option<usize>,
}

impl<T: JwksSource + Send + Sync + 'static> JwksClientBuilder<T> {
    pub(crate) fn new() -> Self {
        Self {
            ttl_opt: None,
            t: PhantomData::default(),
        }
    }

    pub fn time_to_live(&self, ttl: Duration) -> Self {
        Self {
            ttl_opt: Some(ttl),
            t: PhantomData::default(),
        }
    }

    pub fn build(self, source: T) -> JwksClient<T> {
        JwksClient::new(source, self.ttl_opt)
    }
}
