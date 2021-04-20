# Okta JWT Verifier for Rust

## Install

Cargo.toml

```toml
okta-jwt-verifier = { git = "https://gitlab.com/06chaynes/okta-jwt-verifier.git", branch = "master" }
```

## Basic Usage

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

```rust
use okta_jwt_verifier::{verify, token, key, JWK, JWKS};
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

## Development

### Testing

* Note that this requires an internet connection

First copy the example config to a new file:

```sh
cp .env_example .env
```

Update the ISSUER variable to reflect your environment (authorization host).
Also set TEST_TOKEN to a JWT to test against, then run the tests.

```sh
cargo test
```