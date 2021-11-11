# JWKS Client

This lib is used to store Json Web Key Set from your authentication provider. It stores in an internal Cache fetched JWKS
and automatically refresh them after a given time.

## Installation

Add to your `Cargo.toml`

```toml
# Cargo.toml
[dependencies]
jwks_client_rs = "0.1.1"
```

## Code example

```rust
// Put in your application context or wherever this can live long enough
use jwks_client_rs::source::WebSource;
use jwks_client_rs::JwksClient;

// here you must join your `BASE_AUTH0_URL` env var with `.well-known/jwks.json` or whatever is the jwks url
let url: reqwest::Url = todo!();
let source: WebSource = WebSource::new(url); // You can define a different source too using `JwksSource` trait
let client: JwksClient = JwksClient::new(source);

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

To run the example:
- Export the `KID` env variable (take if from your tenant well known jwks)
- Export the `BASE_AUTH0_URL` (something like `http://{your-tenant}.eu.auth0.com`)
- Run in shell `cargo run --bin get_jwks`
