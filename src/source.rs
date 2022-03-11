use std::time::Duration;

use async_trait::async_trait;
use reqwest::{Request, Url};

use crate::error::Error;
use crate::keyset::JsonWebKeySet;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
const TIMEOUT: Duration = Duration::from_secs(10);

#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait JwksSource {
    async fn fetch_keys(&self) -> Result<JsonWebKeySet, Error>;
}

pub struct WebSource {
    client: reqwest::Client,
    url: Url,
}

#[async_trait]
impl JwksSource for WebSource {
    async fn fetch_keys(&self) -> Result<JsonWebKeySet, Error> {
        let request: Request = self.client.get(self.url.clone()).build()?;
        let keys: JsonWebKeySet = self
            .client
            .execute(request)
            .await?
            .error_for_status()?
            .json()
            .await?;

        Ok(keys)
    }
}

pub struct WebSourceBuilder {
    client_builder: reqwest::ClientBuilder,
    url: Url,
    timeout_opt: Option<Duration>,
    connect_timeout_opt: Option<Duration>,
}

impl WebSourceBuilder {
    pub fn new(url: Url) -> Self {
        Self {
            client_builder: reqwest::ClientBuilder::default(),
            url,
            timeout_opt: None,
            connect_timeout_opt: None,
        }
    }

    pub fn with_timeout(self, timeout: Duration) -> Self {
        Self {
            timeout_opt: Some(timeout),
            ..self
        }
    }

    pub fn with_connect_timeout(self, connect_timeout: Duration) -> Self {
        Self {
            connect_timeout_opt: Some(connect_timeout),
            ..self
        }
    }

    pub fn build(self) -> Result<WebSource, reqwest::Error> {
        let timeout: Duration = self.timeout_opt.unwrap_or(TIMEOUT);
        let connect_timeout: Duration = self.connect_timeout_opt.unwrap_or(CONNECT_TIMEOUT);
        Ok(WebSource {
            client: self
                .client_builder
                .timeout(timeout)
                .connect_timeout(connect_timeout)
                .build()?,
            url: self.url,
        })
    }
}
