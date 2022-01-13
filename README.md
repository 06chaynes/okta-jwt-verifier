# okta-jwt-verifier

[![Rust](https://github.com/06chaynes/okta-jwt-verifier/actions/workflows/rust.yml/badge.svg)](https://github.com/06chaynes/okta-jwt-verifier/actions/workflows/rust.yml)
![crates.io](https://img.shields.io/crates/v/okta-jwt-verifier.svg)
[![Docs.rs](https://docs.rs/okta-jwt-verifier/badge.svg)](https://docs.rs/okta-jwt-verifier)

The purpose of this library is to help with the
verification of access and ID tokens issued by Okta.
Check the [API Docs](https://docs.rs/okta-jwt-verifier) for more details.

## Install

With [cargo add](https://github.com/killercup/cargo-edit#Installation) installed :

```sh
cargo add okta-jwt-verifier
```

## Examples

### Minimal

This example attempts to retrieve the keys from the provided Okta authorization server,
decodes the token header to identify the key id, attempts to find a matching key,
attempts to decode the token, and finally attempts to deserialize the claims.

This method will attempt to retrieve the keys upon each request unless a cache feature is enabled.

```rust
use okta_jwt_verifier::{Verifier, DefaultClaims};

#[async_std::main]
async fn main() -> anyhow::Result<()> {
    let token = "token";
    let issuer = "https://your.domain/oauth2/default";

    Verifier::new(&issuer)
        .await?
        .verify::<DefaultClaims>(&token)
        .await?;
    Ok(())
}
```

### Optional Configuration

This example shows the use of optional configurations for validation.

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
    pub scp: Option<Vec<String>>,
    pub cid: Option<String>,
    pub uid: Option<String>,
    pub exp: u64,
    pub iat: u64,
}

let token = "token";
let issuer = "https://your.domain/oauth2/default";
let mut aud = HashSet::new();
aud.insert("api://default");
aud.insert("api://test");

let claims = Verifier::new(&issuer)
    .await?
    // An optional leeway (in seconds) can be provided to account for clock skew (default: 120)
    .leeway(0)
    // Optional audience claims can be provided to validate against
    .audience(aud)
    // Adding a single aud entry without building a HashSet manually
    .add_audience("api://dev")
    // An optional client ID can be provided to match against the cid claim
    .client_id("Bl3hStrINgiD")
    .verify::<Claims>(&token)
    .await?;
dbg!(&claims)
```

### Key Caching

This example matches the basic example but would cache the keys on disk. Requires the `disk-cache` feature to be enabled (disabled by default). Creates an `http-cacache` directory relative to the working directory where the cache files will reside.

With [cargo add](https://github.com/killercup/cargo-edit#Installation) installed :

```sh
cargo add okta-jwt-verifier --features disk-cache
```

### Tide Middleware

This example implements the basic usage example as tide middleware.

  ```sh
  ISSUER="https://your.domain/oauth2/default" cargo run --example tide_middleware_basic
  ```

## Features

The following features are available. By default no features are enabled.

- `disk-cache`: use a cache on disk to store keys (respects cache-control).

## Documentation

- [API Docs](https://docs.rs/okta-jwt-verifier)

## License

Licensed under either of

- Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license
   ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
