# Okta JWT Verifier for Rust

## Install

Cargo.toml

```toml
[dependencies]
okta-jwt-verifier = "0.1.2"
```

## Basic Usage

This example attempts to retrieve the keys from the provided Okta authorization server,
decodes the token header to identify the key id, attempts to find a matching key,
attempts to decode the token, and finally attempts to deserialize the claims.

This method will attempt to retrieve the keys upon each request.

```rust
use okta_jwt_verifier::verify;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct Claims {
    pub iss: String,
    pub sub: String,
    pub scp: Vec<String>,
    pub cid: String,
    pub uid: String,
    pub exp: u64,
    pub iat: u64,
}

let token = "token";
let issuer = "https://your.domain/oauth2/default";

verify::<Claims>(&issuer, &token).await?;
```

## Advanced Usage

This example matches the basic example in function but would allow for caching of the keys

```rust
use okta_jwt_verifier::{token, key, JWK, JWKS};
use jsonwebkey::JsonWebKey;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct Claims {
    pub iss: String,
    pub sub: String,
    pub scp: Vec<String>,
    pub cid: String,
    pub uid: String,
    pub exp: u64,
    pub iat: u64,
}

let token = "token";
let issuer = "https://your.domain/oauth2/default";

let kid: String = token::key_id(&token)?;
let jwks: JWKS = key::get(&issuer).await?;
let jwk: Option<&JWK> = jwks.where_id(&kid);
match jwk {
    Some(key_jwk) => {
        let key: JsonWebKey = serde_json::to_string(&key_jwk)?.parse()?;
        let claims = token::decode::<Claims>(&token, key).await?;
    }
    None => {}
}

```

## Examples

- Tide Middleware (Basic):

  This example implements the basic usage example as tide middleware.

    ```sh
    ISSUER="https://your.domain/oauth2/default" cargo run --example tide_middleware_basic
    ```

## Development

### Testing

- Note that this requires an internet connection

First copy the example config to a new file:

```sh
cp .env_example .env
```

Update the ISSUER variable to reflect your environment (authorization host).
Also set TEST_TOKEN to a JWT to test against, then run the tests.

```sh
cargo test
```
