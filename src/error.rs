use std::sync::Arc;
use jsonwebtoken::errors::ErrorKind;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Failed fetching the key: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("Cannot find key for key_id: {0}")]
    KeyNotFound(String),
    #[error("Token decoding error: {0}")]
    JsonWebToken(#[from] jsonwebtoken::errors::Error),
    #[error("Missing Kid value in the JWT token header")]
    MissingKid,
}

#[derive(thiserror::Error, Debug)]
pub enum JwksClientError {
    #[error(transparent)]
    Error(#[from] Arc<Error>),
}

impl From<Error> for JwksClientError {
    fn from(error: Error) -> Self {
        Self::Error(Arc::new(error))
    }
}

impl From<jsonwebtoken::errors::Error> for JwksClientError {
    fn from(error: jsonwebtoken::errors::Error) -> Self {
        Self::Error(Arc::new(error.into()))
    }
}

impl JwksClientError {
    pub fn is_jwt_expired(&self) -> bool {
        match self { JwksClientError::Error(e) => { e.is_jwt_expired() } }
    }
}

impl Error {
    fn is_jwt_expired(&self) -> bool {
        match self {
            Error::JsonWebToken(err) => { matches!(err.kind(), ErrorKind::ExpiredSignature) }
            _ => false
        }
    }
}
