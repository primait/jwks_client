use std::time::Duration;

use async_trait::async_trait;
use reqwest::{Request, Url};

use crate::error::Error;
use crate::keyset::JsonWebKeySet;
use crate::JwksClientError;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
const TIMEOUT: Duration = Duration::from_secs(10);

#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait JwksSource {
    async fn fetch_keys(&self) -> Result<JsonWebKeySet, JwksClientError>;
}

pub struct WebSource {
    client: reqwest::Client,
    url: Url,
}

impl WebSource {
    pub fn builder() -> WebSourceBuilder {
        WebSourceBuilder::new()
    }
}

#[async_trait]
impl JwksSource for WebSource {
    #[tracing::instrument(skip(self), fields(url = %self.url))]
    async fn fetch_keys(&self) -> Result<JsonWebKeySet, JwksClientError> {
        fetch_keys(self).await.map_err(JwksClientError::from)
    }
}

async fn fetch_keys(source: &WebSource) -> Result<JsonWebKeySet, Error> {
    let request: Request = source.client.get(source.url.clone()).build()?;
    let keys: JsonWebKeySet = source
        .client
        .execute(request)
        .await?
        .error_for_status()?
        .json()
        .await?;

    Ok(keys)
}

pub struct WebSourceBuilder {
    client_builder: reqwest::ClientBuilder,
    timeout_opt: Option<Duration>,
    connect_timeout_opt: Option<Duration>,
}

impl WebSourceBuilder {
    fn new() -> Self {
        Self {
            client_builder: reqwest::ClientBuilder::default(),
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

    pub fn build(self, url: Url) -> Result<WebSource, reqwest::Error> {
        let timeout: Duration = self.timeout_opt.unwrap_or(TIMEOUT);
        let connect_timeout: Duration = self.connect_timeout_opt.unwrap_or(CONNECT_TIMEOUT);
        Ok(WebSource {
            url,
            client: self
                .client_builder
                .timeout(timeout)
                .connect_timeout(connect_timeout)
                .build()?,
        })
    }
}
