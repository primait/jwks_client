// https://tools.ietf.org/id/draft-ietf-jose-json-web-key-00.html#rfc.section.3.1

use serde::Deserialize;

use crate::{error::Error, JwksClientError};

#[derive(Debug, Deserialize, Clone)]
pub struct JsonWebKeySet {
    keys: Vec<JsonWebKey>,
}

impl From<Vec<JsonWebKey>> for JsonWebKeySet {
    fn from(keys: Vec<JsonWebKey>) -> Self {
        Self { keys }
    }
}

impl JsonWebKeySet {
    pub(crate) fn empty() -> Self {
        Self { keys: vec![] }
    }

    pub fn get_key(&self, key_id: &str) -> Result<&JsonWebKey, JwksClientError> {
        self.keys
            .iter()
            .find(|key| key.key_id() == key_id)
            .ok_or_else(|| Error::KeyNotFound(key_id.to_string()).into())
    }

    pub fn take_key(self, key_id: &str) -> Result<JsonWebKey, JwksClientError> {
        self.keys
            .into_iter()
            .find(|key| key.key_id() == key_id)
            .ok_or_else(|| Error::KeyNotFound(key_id.to_string()).into())
    }

    pub fn keys(self) -> Vec<JsonWebKey> {
        self.keys
    }
}

// https://tools.ietf.org/id/draft-ietf-jose-json-web-key-00.html#rfc.section.3
#[derive(Debug, Deserialize, Clone)]
#[serde(tag = "kty")]
pub enum JsonWebKey {
    #[serde(alias = "RSA")]
    Rsa(RsaPublicJwk),
    #[serde(alias = "EC")]
    Ec(EcPublicJwk),
}

impl JsonWebKey {
    pub fn key_id(&self) -> &str {
        match self {
            JsonWebKey::Rsa(rsa_pk) => rsa_pk.key_id(),
            JsonWebKey::Ec(ec_pk) => ec_pk.key_id(),
        }
    }

    pub fn alg(&self) -> Option<&str> {
        match self {
            JsonWebKey::Rsa(rsa_pk) => rsa_pk.algorithm(),
            JsonWebKey::Ec(ec_pk) => ec_pk.algorithm(),
        }
    }

    pub fn as_rsa_public_key(&self) -> Result<&RsaPublicJwk, Error> {
        match self {
            JsonWebKey::Rsa(rsa_pk) => Ok(rsa_pk),
            JsonWebKey::Ec(_ec_pk) => Err(Error::InvalidOperation("EC".to_string())),
        }
    }

    pub fn as_ec_public_key(&self) -> Result<&EcPublicJwk, Error> {
        match self {
            JsonWebKey::Rsa(_rsa_pk) => Err(Error::InvalidOperation("RSA".to_string())),
            JsonWebKey::Ec(ec_pk) => Ok(ec_pk),
        }
    }

    #[cfg(test)]
    pub fn x5t(&self) -> Option<String> {
        match self {
            JsonWebKey::Rsa(rsa_pk) => rsa_pk.x5t.clone(),
            JsonWebKey::Ec(_ec_pk) => None,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct RsaPublicJwk {
    r#use: Option<Use>,
    #[serde(rename(deserialize = "alg"))]
    algorithm: Option<String>,
    #[serde(rename(deserialize = "kid"))]
    key_id: String,
    // X.509 certificate chain
    #[serde(rename(deserialize = "x5c"))]
    certificates: Option<Vec<String>>,
    #[cfg(test)]
    x5t: Option<String>,
    #[serde(rename(deserialize = "n"))]
    modulus: String,
    #[serde(rename(deserialize = "e"))]
    exponent: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct EcPublicJwk {
    #[serde(rename(deserialize = "alg"))]
    algorithm: Option<String>,
    #[serde(rename(deserialize = "kid"))]
    key_id: String,
    #[serde(rename(deserialize = "crv"))]
    curve: String,
    #[serde(rename(deserialize = "x"))]
    x: String,
    #[serde(rename(deserialize = "y"))]
    y: String,
}

impl RsaPublicJwk {
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn modulus(&self) -> &str {
        &self.modulus
    }

    pub fn exponent(&self) -> &str {
        &self.exponent
    }

    pub fn r#use(&self) -> Option<Use> {
        self.r#use
    }

    pub fn algorithm(&self) -> Option<&str> {
        self.algorithm.as_deref()
    }

    pub fn certificates(&self) -> Option<&[String]> {
        self.certificates.as_deref()
    }
}

impl EcPublicJwk {
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn algorithm(&self) -> Option<&str> {
        self.algorithm.as_deref()
    }

    pub fn curve(&self) -> &str {
        &self.curve
    }

    pub fn x(&self) -> &str {
        &self.x
    }

    pub fn y(&self) -> &str {
        &self.y
    }
}

#[derive(Debug, Deserialize, Clone, Copy)]
#[serde(rename_all(deserialize = "lowercase"))]
pub enum Use {
    Sig,
    Enc,
}

#[cfg(test)]
mod tests {
    use super::JsonWebKeySet;

    #[test]
    fn deserialize_public_rsa_key_set() -> Result<(), Box<dyn std::error::Error>> {
        let keys = r#"
            {
              "keys": [
                {
                  "alg": "RS256",
                  "kty": "RSA",
                  "use": "sig",
                  "n": "qjNzuylUQpyU9qX3_bMGpiRUO1G_xKbB0fyqQy0naETviHIqPS2D3lGcfK9XIFLZOq1O7K2KRXEE5nSDTf-S9qc0nPRkS38CXK4DBKPTBXtjufLK3e9lN9dh8Ehazx8xNmdCc6aocVKKlamOJv7Qr_UgmoFllq7W-UQ0YK2qfN8WgqxOQUPrss-40RWslCAKpjZmMOpIpRXQLGmR-GGZUdQZXnTUhnhRyDz5VcXHH--o1PkH_F0rlabMxgNFfsCIWKWbGy8G89bNrvoeVKq15QPCeaGBV13f2Do6XHGt0l2M3eYz85wyz1pISvjQuR4PrtJr6VsuHz3Puh_KgY8GqQ",
                  "e": "AQAB",
                  "kid": "go14h7EBWUvPRncjniI_2",
                  "x5t": "dfrlEXMuWrPaCbmIrpXaiwNjFf4",
                  "x5c": [
                    "MIIDDTCCAfWgAwIBAgIJWUyDuZMhkTwpMA0GCSqGSIb3DQEBCwUAMCQxIjAgBgNVBAMTGWRldi1mOHJkejF3dy5ldS5hdXRoMC5jb20wHhcNMjEwOTA2MDkxODQ0WhcNMzUwNTE2MDkxODQ0WjAkMSIwIAYDVQQDExlkZXYtZjhyZHoxd3cuZXUuYXV0aDAuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqjNzuylUQpyU9qX3/bMGpiRUO1G/xKbB0fyqQy0naETviHIqPS2D3lGcfK9XIFLZOq1O7K2KRXEE5nSDTf+S9qc0nPRkS38CXK4DBKPTBXtjufLK3e9lN9dh8Ehazx8xNmdCc6aocVKKlamOJv7Qr/UgmoFllq7W+UQ0YK2qfN8WgqxOQUPrss+40RWslCAKpjZmMOpIpRXQLGmR+GGZUdQZXnTUhnhRyDz5VcXHH++o1PkH/F0rlabMxgNFfsCIWKWbGy8G89bNrvoeVKq15QPCeaGBV13f2Do6XHGt0l2M3eYz85wyz1pISvjQuR4PrtJr6VsuHz3Puh/KgY8GqQIDAQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQ1uIfkGnNThAvMeJzxnOYxn+w5iDAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADggEBADE2QQ3SL4mMIzF4Y63TI+KfD9TOQGSqxmavU5jMYhzlDsQpSR8CyK4Nl6wgVNJuESeXCNcOdBTtViQJ5PmUPkEaswCfI2qufWM44tKkKNhKdgh15Dzq6e0LK8oeadA6OdADnz9QvTaHU7VIxpi2swJEPtlmMb58wkkVhxLAtVtLNp90fbE0EQstBbQWcgodjOOQXmOJlCyIOCmvkBcbUkQSXt66Yn/GTU2jvco0U5yBzLHSOANSfi5GQIdzlSNFmdbq057Zc/GivQAEL4adPQPHeAgDZvnarvX+UqU8lp/yuNOycJ24SRnRTcCqeNB0kjybYLTgOedv/E6D2RGvF2E="
                  ]
                }
              ]
            }
        "#;

        let keyset: JsonWebKeySet = serde_json::from_str(keys)?;
        let key = keyset.get_key("go14h7EBWUvPRncjniI_2")?;

        assert_eq!("RS256", key.alg().unwrap());

        let _rsa_pk = key.as_rsa_public_key()?;

        Ok(())
    }

    #[test]
    fn deserialize_public_ec_key_set() -> Result<(), Box<dyn std::error::Error>> {
        let keys = r#"
        {
          "keys": [
            {
              "alg": "ES256",
              "kty": "EC",
              "crv": "P-256",
              "x": "LEBfQpwTDXJtLFiPcnYvGv-WaFXZGBnFP_yGhLL9MGc",
              "y": "a1Or3ovkpH12b0o3ruZUtm_z8bg3xQtHXi-uPC7UJT0",
              "kid": "test-key"
            }
          ]
        }
        "#;

        let keyset: JsonWebKeySet = serde_json::from_str(keys)?;
        let key = keyset.get_key("test-key")?;

        assert_eq!("ES256", key.alg().unwrap());

        let ec_pk = key.as_ec_public_key()?;
        assert_eq!("LEBfQpwTDXJtLFiPcnYvGv-WaFXZGBnFP_yGhLL9MGc", ec_pk.x());
        assert_eq!("a1Or3ovkpH12b0o3ruZUtm_z8bg3xQtHXi-uPC7UJT0", ec_pk.y());

        Ok(())
    }
}
