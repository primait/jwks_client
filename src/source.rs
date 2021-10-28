use async_trait::async_trait;
use reqwest::Url;

use crate::error::Error;
use crate::keyset::JsonWebKeySet;

#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait JwksSource {
    async fn fetch_keys(&self) -> Result<JsonWebKeySet, Error>;
}

pub struct WebSource {
    client: reqwest::Client,
    url: Url,
}

impl WebSource {
    pub fn new(url: Url) -> Self {
        Self {
            client: reqwest::Client::default(),
            url,
        }
    }
}

#[async_trait]
impl JwksSource for WebSource {
    async fn fetch_keys(&self) -> Result<JsonWebKeySet, Error> {
        let request = self.client.get(self.url.clone()).build()?;
        let keys = self.client.execute(request).await?.error_for_status()?.json().await?;

        Ok(keys)
    }
}
