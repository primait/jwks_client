use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use jsonwebtoken::{Algorithm, DecodingKey, Header, Validation};
use serde::de::DeserializeOwned;

use crate::builder::JwksClientBuilder;
use crate::cache::Cache;
use crate::error::{Error, JwksClientError};
use crate::keyset::JsonWebKey;
use crate::source::JwksSource;

const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(86400);

pub struct JwksClient<T: JwksSource> {
    source: Arc<T>,
    cache: Cache,
}

impl<T: JwksSource> Clone for JwksClient<T> {
    fn clone(&self) -> Self {
        Self {
            source: self.source.clone(),
            cache: self.cache.clone(),
        }
    }
}

impl<T: JwksSource + Send + Sync + 'static> JwksClient<T> {
    /// Constructs the client.
    /// This should be cloned when passed to threads.
    pub(crate) fn new(source: T, ttl_opt: Option<Duration>) -> Self {
        Self {
            source: Arc::new(source),
            cache: Cache::new(ttl_opt.unwrap_or(DEFAULT_CACHE_TTL)),
        }
    }

    pub fn builder() -> JwksClientBuilder<T> {
        JwksClientBuilder::new()
    }

    /// Retrieves the key from the cache, if not found it fetches it from the provided `source`.
    /// If the key is not found after fetching it, returns an error.
    pub async fn get(&self, key_id: String) -> Result<JsonWebKey, JwksClientError> {
        let source: Arc<T> = self.source.clone();

        let key: JsonWebKey = self
            .cache
            .get_or_refresh(&key_id, async move { source.fetch_keys().await })
            .await?;

        Ok(key)
    }

    /// Retrieves the key from the cache, if not found it fetches it from the provided `source`.
    /// If the key is not found after fetching it, returns Ok(None).
    pub async fn get_opt(&self, key_id: String) -> Result<Option<JsonWebKey>, JwksClientError> {
        match self.get(key_id).await {
            Ok(res) => Ok(Some(res)),
            Err(error) => Err(error),
        }
    }

    /// Decodes and validates the token using the keyset from the provided `source`.
    ///
    /// If you don't want to validate the audience members pass an empty slice.
    pub async fn decode<O: DeserializeOwned>(
        &self,
        token: &str,
        audience: &[impl ToString],
    ) -> Result<O, JwksClientError> {
        let header: Header = jsonwebtoken::decode_header(token)?;

        if let Some(kid) = header.kid {
            let key: JsonWebKey = self.get(kid).await?;

            let mut validation = if let Some(alg) = key.alg() {
                Validation::new(Algorithm::from_str(alg)?)
            } else {
                Validation::default()
            };

            if !audience.is_empty() {
                validation.set_audience(audience);
            }

            match key {
                JsonWebKey::Rsa(jwk) => {
                    let decoding_key: DecodingKey =
                        DecodingKey::from_rsa_components(jwk.modulus(), jwk.exponent())?;
                    // Can this block the current thread? (should I spawn_blocking?)
                    Ok(jsonwebtoken::decode(token, &decoding_key, &validation)?.claims)
                }
            }
        } else {
            Err(Error::MissingKid.into())
        }
    }
}

#[cfg(test)]
mod test {
    use std::time::Duration;

    use httpmock::prelude::*;
    use jsonwebtoken::{Algorithm, EncodingKey, Header};
    use serde_json::{json, Value};
    use url::Url;

    use crate::error::Error;
    use crate::source::WebSource;
    use crate::{JwksClient, JwksClientError};

    const MODULUS: &str = "qjNzuylUQpyU9qX3_bMGpiRUO1G_xKbB0fyqQy0naETviHIqPS2D3lGcfK9XIFLZOq1O7K2KRXEE5nSDTf-S9qc0nPRkS38CXK4DBKPTBXtjufLK3e9lN9dh8Ehazx8xNmdCc6aocVKKlamOJv7Qr_UgmoFllq7W-UQ0YK2qfN8WgqxOQUPrss-40RWslCAKpjZmMOpIpRXQLGmR-GGZUdQZXnTUhnhRyDz5VcXHH--o1PkH_F0rlabMxgNFfsCIWKWbGy8G89bNrvoeVKq15QPCeaGBV13f2Do6XHGt0l2M3eYz85wyz1pISvjQuR4PrtJr6VsuHz3Puh_KgY8GqQ";
    const EXPONENT: &str = "AQAB";

    #[tokio::test]
    async fn get_key() {
        let server = MockServer::start();
        let path: &str = "/keys";
        let kid: &str = "go14h7EBWUvPRncjniI_2";

        let mock = server.mock(|when, then| {
            when.method(GET).path(path);

            then.status(200)
                .header("content-type", "application/json")
                .json_body(jwks_endpoint_response(kid));
        });

        let url: Url = Url::parse(&server.url(path)).unwrap();
        let source: WebSource = WebSource::builder().build(url).unwrap();
        let client: JwksClient<WebSource> = JwksClient::new(source, None);

        assert!(client.get(kid.to_string()).await.is_ok());
        mock.assert();
    }

    #[tokio::test]
    async fn get_key_after_expiration_should_update() {
        let server = MockServer::start();
        let path: &str = "/keys";
        let kid: &str = "go14h7EBWUvPRncjniI_2";

        let mut mock = server.mock(|when, then| {
            when.method(GET).path(path);

            then.status(200)
                .header("content-type", "application/json")
                .json_body(jwks_endpoint_response(kid));
        });

        let url: Url = Url::parse(&server.url(path)).unwrap();
        let source: WebSource = WebSource::builder().build(url).unwrap();
        let ttl_opt: Option<Duration> = Some(Duration::from_millis(1));
        let client: JwksClient<WebSource> = JwksClient::new(source, ttl_opt);

        let result_key_1 = client.get(kid.to_string()).await;
        assert!(result_key_1.is_ok());
        let x5t_1: String = result_key_1.unwrap().x5t().unwrap();

        mock.assert();
        mock.delete();

        // This test that if the key is expired a new call to remote endpoint is performed.

        // Give time to let the keys expire
        std::thread::sleep(Duration::from_millis(2));

        let mut mock = server.mock(|when, then| {
            when.method(GET).path(path);

            then.status(200)
                .header("content-type", "application/json")
                .json_body(jwks_endpoint_response(kid));
        });

        let result_key_2 = client.get(kid.to_string()).await;
        assert!(result_key_2.is_ok());
        let x5t_2: String = result_key_2.unwrap().x5t().unwrap();

        assert_ne!(x5t_1, x5t_2);

        mock.assert();
        mock.delete();

        // This test that if the key is expired but the remote call fails the value is
        // still the same

        // Give time to let the keys expire
        std::thread::sleep(Duration::from_millis(2));

        let mock = server.mock(|when, then| {
            when.method(GET).path(path);
            then.status(400).body("Error");
        });

        let result_key_3 = client.get(kid.to_string()).await;
        assert!(result_key_3.is_ok());
        let x5t_3: String = result_key_3.unwrap().x5t().unwrap();

        assert_eq!(x5t_2, x5t_3);

        mock.assert();
    }

    #[tokio::test]
    async fn get_key_fails_to_fetch_keys() {
        let server = MockServer::start();
        let path: &str = "/keys";
        let kid: &str = "go14h7EBWUvPRncjniI_2";

        let mock = server.mock(|when, then| {
            when.method(GET).path(path);

            then.status(400).body("Error");
        });

        let url: Url = Url::parse(&server.url(path)).unwrap();
        let source: WebSource = WebSource::builder().build(url).unwrap();
        let client: JwksClient<WebSource> = JwksClient::new(source, None);

        let result = client.get(kid.to_string()).await;
        assert!(result.is_err());
        match result.err().unwrap() {
            JwksClientError::Error(err) => match *err {
                Error::Reqwest(_) => {}
                _ => {
                    eprintln!("{}", err);
                    unreachable!()
                }
            },
        }
        mock.assert();
    }

    #[tokio::test]
    async fn get_key_key_not_found() {
        let server = MockServer::start();
        let path: &str = "/keys";
        let kid: &str = "other_kid";

        let mock = server.mock(|when, then| {
            when.method(GET).path(path);

            then.status(200)
                .header("content-type", "application/json")
                .json_body(jwks_endpoint_response("go14h7EBWUvPRncjniI_2"));
        });

        let url: Url = Url::parse(&server.url(path)).unwrap();
        let source: WebSource = WebSource::builder().build(url).unwrap();
        let client: JwksClient<WebSource> = JwksClient::new(source, None);

        let result = client.get(kid.to_string()).await;
        assert!(result.is_err());

        match result.err().unwrap() {
            JwksClientError::Error(err) => match *err {
                Error::KeyNotFound(ref key_id) => assert_eq!(kid, key_id),
                _ => {
                    eprintln!("{}", err);
                    unreachable!()
                }
            },
        }
        mock.assert();
    }

    #[tokio::test]
    async fn decode_missing_kid_in_header() {
        let source = crate::source::MockJwksSource::new();
        let client = JwksClient::new(source, None);

        // pem generated using: ssh-keygen -t rsa -b 4096 -m PEM -f jwtRS256.key
        let encoding_key = EncodingKey::from_rsa_pem(
            r#"-----BEGIN RSA PRIVATE KEY-----
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
            -----END RSA PRIVATE KEY-----"#
                .trim()
                .as_bytes(),
        )
        .unwrap();

        let header = Header::new(Algorithm::RS256);

        use serde::{Deserialize, Serialize};
        #[derive(Debug, Serialize, Deserialize)]
        struct Claims {
            iss: String,
            aud: String,
            exp: usize,
        }

        let claims = Claims {
            iss: "me".to_string(),
            aud: "jwks-client".to_string(),
            exp: 1000000, // year 2286
        };
        let token = jsonwebtoken::encode(&header, &claims, &encoding_key).unwrap();

        let result: Result<Claims, _> = client.decode(&token, &["test"]).await;
        assert!(result.is_err());

        match result.err().unwrap() {
            JwksClientError::Error(err) => match *err {
                Error::MissingKid => {}
                _ => {
                    eprintln!("{}", err);
                    unreachable!()
                }
            },
        }
    }

    fn jwks_endpoint_response(kid: &str) -> Value {
        json!({
              "keys": [
                {
                  "alg": "RS256",
                  "kty": "RSA",
                  "use": "sig",
                  "n": MODULUS,
                  "e": EXPONENT,
                  "kid": kid,
                  "x5t": random_string(),
                  "x5c": [
                    "MIIDDTCCAfWgAwIBAgIJWUyDuZMhkTwpMA0GCSqGSIb3DQEBCwUAMCQxIjAgBgNVBAMTGWRldi1mOHJkejF3dy5ldS5hdXRoMC5jb20wHhcNMjEwOTA2MDkxODQ0WhcNMzUwNTE2MDkxODQ0WjAkMSIwIAYDVQQDExlkZXYtZjhyZHoxd3cuZXUuYXV0aDAuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqjNzuylUQpyU9qX3/bMGpiRUO1G/xKbB0fyqQy0naETviHIqPS2D3lGcfK9XIFLZOq1O7K2KRXEE5nSDTf+S9qc0nPRkS38CXK4DBKPTBXtjufLK3e9lN9dh8Ehazx8xNmdCc6aocVKKlamOJv7Qr/UgmoFllq7W+UQ0YK2qfN8WgqxOQUPrss+40RWslCAKpjZmMOpIpRXQLGmR+GGZUdQZXnTUhnhRyDz5VcXHH++o1PkH/F0rlabMxgNFfsCIWKWbGy8G89bNrvoeVKq15QPCeaGBV13f2Do6XHGt0l2M3eYz85wyz1pISvjQuR4PrtJr6VsuHz3Puh/KgY8GqQIDAQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQ1uIfkGnNThAvMeJzxnOYxn+w5iDAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADggEBADE2QQ3SL4mMIzF4Y63TI+KfD9TOQGSqxmavU5jMYhzlDsQpSR8CyK4Nl6wgVNJuESeXCNcOdBTtViQJ5PmUPkEaswCfI2qufWM44tKkKNhKdgh15Dzq6e0LK8oeadA6OdADnz9QvTaHU7VIxpi2swJEPtlmMb58wkkVhxLAtVtLNp90fbE0EQstBbQWcgodjOOQXmOJlCyIOCmvkBcbUkQSXt66Yn/GTU2jvco0U5yBzLHSOANSfi5GQIdzlSNFmdbq057Zc/GivQAEL4adPQPHeAgDZvnarvX+UqU8lp/yuNOycJ24SRnRTcCqeNB0kjybYLTgOedv/E6D2RGvF2E="
                  ]
                }
              ]
            }
        )
    }

    fn random_string() -> String {
        use rand::{distributions::Alphanumeric, Rng};
        rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(7)
            .map(char::from)
            .collect()
    }
}
