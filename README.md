# okta-jwt-verifier

![crates.io](https://img.shields.io/crates/v/okta-jwt-verifier.svg)

A helper library for working with JWT's for Okta in Rust

## Install

Cargo.toml

```toml
[dependencies]
okta-jwt-verifier = "0.4.0"
```

With [cargo add](https://github.com/killercup/cargo-edit#Installation) installed :

```sh
cargo add okta-jwt-verifier
```

## Example - Basic Usage

This example attempts to retrieve the keys from the provided Okta authorization server,
decodes the token header to identify the key id, attempts to find a matching key,
attempts to decode the token, and finally attempts to deserialize the claims.

This method will attempt to retrieve the keys upon each request.

```rust
use okta_jwt_verifier::Verifier;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

// You can provide your own Claims struct or use the provided defaults
// This example matches okta_jwt_verifier::DefaultClaims
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
let mut aud = HashSet::new();
aud.insert("api://default");
aud.insert("api://test");

// An optional leeway (in seconds) can be provided to account for clock skew (default: 120)
// Optional audience claims can be provided to validate against
Verifier::new(&issuer)
  .await?
  // overriding leeway to be 0 seconds
  .leeway(0)
  // setting aud with a provided HashSet
  .audience(aud)
  // adding a single aud entry without building a HashSet manually
  .add_audience("api://dev")
  .verify::<DefaultClaims>(&token)
  .await?;
```

## Example - Caching

This example matches the basic example but would cache the keys on disk. Requires the `disk-cache` feature to be enabled (disabled by default). Creates a `surf-cacache` directory relative to the working directory where the cache files will reside.

Cargo.toml

```toml
[dependencies]
okta-jwt-verifier = { version = "0.4.0", features = ["disk-cache"] }
```

## Example - Tide Middleware

- Tide Middleware (Basic):

  This example implements the basic usage example as tide middleware.

    ```sh
    ISSUER="https://your.domain/oauth2/default" cargo run --example tide_middleware_basic
    ```

## Features

The following features are available. By default no features are enabled.

- `disk-cache`: use a cache on disk to store keys (respects cache-control).

## Documentation

- [API Docs](https://docs.rs/okta-jwt-verifier)

## Development

### Testing

- Note that this requires an internet connection

First copy the example config to a new file:

```sh
cp .env_example .env
```

Update the ISSUER variable to reflect your environment (authorization host).
Also set TEST_TOKEN to a JWT to test against, then run the tests:

```sh
cargo test
```

Or test with the optional disk cache:

```sh
cargo test --features disk-cache
```
