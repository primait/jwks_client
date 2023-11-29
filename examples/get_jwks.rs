use std::str::FromStr;
use std::time::Duration;

use reqwest::Url;

use jwks_client_rs::source::WebSource;
use jwks_client_rs::{JsonWebKey, JwksClient, JwksClientError};

#[tokio::main]
async fn main() {
    // This value must be set as one of your tenant key id (in the json: "keys"[0]."kid")
    // $ export KID={YOUR-KID}
    let kid: String = std::env::var("KID").unwrap();
    // This should be something like
    // $ export AUTH0_BASE_URL=https://{YOUR-TENANT}.eu.auth0.com
    // or running localauth0
    // $ docker run -d -p 3000:3000 public.ecr.aws/prima/localauth0:0.3.0
    // $ export AUTH0_BASE_URL=http://localhost:3000
    let url_string: String = std::env::var("AUTH0_BASE_URL").unwrap();

    let url: Url = Url::from_str(url_string.as_str()).unwrap();
    let url: Url = url.join(".well-known/jwks.json").unwrap();

    let source: WebSource = WebSource::builder()
        .build(url)
        .expect("Failed to build WebSource");

    let time_to_live: Duration = Duration::from_secs(60);

    let client: JwksClient<WebSource> = JwksClient::builder()
        .time_to_live(time_to_live)
        .build(source);

    // The kid "unknown" cannot be a JWKS valid KID. This must not be found here
    let result: Result<JsonWebKey, JwksClientError> = client.get("unknown").await;
    println!(
        "Get with kid \"unknown\": {}",
        result.unwrap_err()
    );

    // The provided kid (assuming is the same you got from your tenant) is valid and could be found.
    let result: Result<JsonWebKey, JwksClientError> = client.get(&kid).await;
    println!("Get with kid \"{}\": {:?}", kid, result.unwrap());
}
