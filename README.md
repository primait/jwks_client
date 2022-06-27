# JWKS Client

This lib is used to store Json Web Key Set from your authentication provider. It stores in an internal Cache fetched JWKS
and automatically refresh them after a given time.

## Installation

Add to your `Cargo.toml`

```toml
# Cargo.toml
[dependencies]
jwks_client_rs = "0.3.0"
```

## Code example

```rust
// Put in your application context or wherever this can live long enough
use jwks_client_rs::source::WebSource;
use jwks_client_rs::JwksClient;

// here you must join your `BASE_AUTH0_URL` env var with `.well-known/jwks.json` or whatever is the jwks url
let url: reqwest::Url = todo!();
let timeout: std::time::Duration = todo!();
// You can define a different source too using `JwksSource` trait
let source: WebSource = WebSource::builder()
    .with_timeout(timeout)
    .with_connect_timeout(timeout)
    .build(url);

let client: JwksClient<WebSource> = JwksClient::builder()
    .build(source);

// Store your client in your application context or whatever
// ..

// Get jwk by kid
use jwks_client_rs::{JsonWebKey, JwksClientError};

let kid: String = todo!();
let result: Result<JsonWebKey, JwksClientError> = app_context.jwks_client.get(kid).await;
```

It is possible to decode your token validating it has been signed by one of your authentication provider JWKS.

```rust
#[derive(serde::Deserialize)]
struct Claims {
    aud: String,
}

let client: JwksClient = todo!();
// Here's the token. Remember to remove "Bearer " from your token in case it is present
let token: &str = todo!();
// The audience the token were released for.
let audience: &str = todo!();
let result: Result<Claims, JwksClientError> = client.decode::<Claims>(token, audience).await;
```

## Example

A working example could be found in [examples](./examples) folder. To run the example:
- Export the `KID` env variable (take it from your tenant well known jwks)
- Export the `BASE_AUTH0_URL` (by running [localauth0](https://github.com/primait/localauth0) or using your 
  auth0 tenant; the url should be your localauth0 exposed port on `localhost` or something like 
  `https://{your-tenant}.eu.auth0.com`)
- Run in shell `cargo run --example get_jwks`
