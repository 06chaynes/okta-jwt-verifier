//! A helper library for working with JWT's for Okta.
//!
//! The purpose of this library is to help with the
//! verification of access and ID tokens issued by Okta.
//!
//! ## Examples
//!
//! ### Minimal example
//!
//! ```no_run
//! use okta_jwt_verifier::{Verifier, DefaultClaims};
//!
//! #[async_std::main]
//! async fn main() -> anyhow::Result<()> {
//!     let token = "token";
//!     let issuer = "https://your.domain/oauth2/default";
//!
//!     Verifier::new(&issuer)
//!         .await?
//!         .verify::<DefaultClaims>(&token)
//!         .await?;
//!     Ok(())
//! }
//!```
//!
//! ### Verify audience (helper for single entry)
//!
//! ```no_run
//! use okta_jwt_verifier::{Verifier, DefaultClaims};
//!
//! #[async_std::main]
//! async fn main() -> anyhow::Result<()> {
//!     let token = "token";
//!     let issuer = "https://your.domain/oauth2/default";
//!
//!     Verifier::new(&issuer)
//!         .await?
//!         .add_audience("api://default")
//!         .verify::<DefaultClaims>(&token)
//!         .await?;
//!     Ok(())
//! }
//!```
//!
//! ### Verify audience (method for multiple entries)
//!
//! ```no_run
//! use okta_jwt_verifier::{Verifier, DefaultClaims};
//! use std::collections::HashSet;
//!
//! #[async_std::main]
//! async fn main() -> anyhow::Result<()> {
//!     let token = "token";
//!     let issuer = "https://your.domain/oauth2/default";
//!     let mut aud = HashSet::new();
//!     aud.insert("api://default".to_string());
//!     aud.insert("api://admin".to_string());
//!
//!     Verifier::new(&issuer)
//!         .await?
//!         .audience(aud)
//!         .verify::<DefaultClaims>(&token)
//!         .await?;
//!     Ok(())
//! }
//!```
//!
//! ### Custom leeway (default is 120 seconds)
//!
//! ```no_run
//! use okta_jwt_verifier::{Verifier, DefaultClaims};
//!
//! #[async_std::main]
//! async fn main() -> anyhow::Result<()> {
//!     let token = "token";
//!     let issuer = "https://your.domain/oauth2/default";
//!
//!     Verifier::new(&issuer)
//!         .await?
//!         .leeway(60)
//!         .verify::<DefaultClaims>(&token)
//!         .await?;
//!     Ok(())
//! }
//!```
#![forbid(unsafe_code, future_incompatible)]
#![deny(
    missing_docs,
    missing_debug_implementations,
    missing_copy_implementations,
    nonstandard_style,
    unused_qualifications,
    rustdoc::missing_doc_code_examples
)]

use std::collections::{HashMap, HashSet};

use anyhow::{bail, Result};
use jsonwebkey::JsonWebKey;
use jsonwebtoken::{TokenData, Validation};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

#[cfg(feature = "disk-cache")]
use surf_middleware_cache::{managers::CACacheManager, Cache, CacheMode};

/// Describes the default claims inside a decoded token
#[derive(Debug, Serialize, Deserialize)]
pub struct DefaultClaims {
    /// The Issuer Identifier of the response.
    /// This value is the unique identifier for the Authorization Server instance.
    pub iss: String,
    /// The subject of the token.
    pub sub: String,
    /// Array of scopes that are granted to this access token.
    pub scp: Option<Vec<String>>,
    /// Client ID of the client that requested the access token.
    pub cid: Option<String>,
    /// A unique identifier for the user.
    /// It isn't included in the access token if there is no user bound to it.
    pub uid: Option<String>,
    /// The time the access token expires, represented in Unix time (seconds).
    pub exp: u64,
    /// The time the access token was issued, represented in Unix time (seconds).
    pub iat: u64,
}

// Describes the key retrieved from upstream
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Jwk {
    // The "kty" (key type) parameter identifies the cryptographic algorithm
    // family used with the key, such as "RSA" or "EC".
    kty: String,
    // The "alg" (algorithm) parameter identifies the algorithm intended for
    // use with the key.
    alg: String,
    // The "kid" (key ID) parameter is used to match a specific key.  This
    // is used, for instance, to choose among a set of keys within a Jwk Set
    // during key rollover.  The structure of the "kid" value is
    // unspecified.  When "kid" values are used within a Jwk Set, different
    // keys within the Jwk Set SHOULD use distinct "kid" values.
    kid: String,
    // The "use" (public key use) parameter identifies the intended use of
    // the public key.  The "use" parameter is employed to indicate whether
    // a public key is used for encrypting data or verifying the signature
    // on data.
    #[serde(rename = "use")]
    uses: String,
    // RSA public exponent is used on signed / encoded data to decode the original value
    e: String,
    // RSA modulus is the product of two prime numbers used to generate the key pair
    n: String,
}

// Container for keys
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Jwks {
    inner: HashMap<String, Jwk>,
}

#[derive(Debug, Deserialize)]
struct KeyResponse {
    keys: Vec<Jwk>,
}

impl Jwks {
    // Attempts to retrieve a key by given id
    pub fn where_id(&self, kid: &str) -> Option<&Jwk> {
        self.inner.get(kid)
    }
}

#[cfg(feature = "disk-cache")]
fn build_client() -> surf::Client {
    surf::Client::new().with(Cache {
        mode: CacheMode::Default,
        cache_manager: CACacheManager::default(),
    })
}

#[cfg(not(feature = "disk-cache"))]
fn build_client() -> surf::Client {
    surf::Client::new()
}

/// main struct
#[derive(Debug, Clone)]
pub struct Verifier {
    issuer: String,
    leeway: Option<u64>,
    aud: Option<HashSet<String>>,
    keys: Jwks,
}

impl Verifier {
    /// builds main struct
    pub async fn new(issuer: &str) -> Result<Self> {
        let keys = get(issuer).await?;
        Ok(Self { issuer: issuer.to_string(), leeway: None, aud: None, keys })
    }

    /// verifies token
    pub async fn verify<T>(&self, token: &str) -> Result<TokenData<T>>
    where
        T: DeserializeOwned,
    {
        let kid: String = self.key_id(token)?;
        let jwk: Option<&Jwk> = self.keys.where_id(&kid);
        match jwk {
            Some(key_jwk) => self.decode::<T>(token, key_jwk).await,
            None => bail!("No matching key found!"),
        }
    }

    /// set aud directly
    pub fn audience(mut self, audience: HashSet<String>) -> Self {
        self.aud = Some(audience);
        self
    }

    /// override leeway (seconds)
    pub fn leeway(mut self, leeway: u64) -> Self {
        self.leeway = Some(leeway);
        self
    }

    /// helper to insert a single audience
    pub fn add_audience(mut self, audience: &str) -> Self {
        if let Some(mut a) = self.aud.clone() {
            a.insert(audience.to_string());
        } else {
            let mut a = HashSet::new();
            a.insert(audience.to_string());
            self.aud = Some(a);
        }
        self
    }

    // Attempts to retrieve a key id for a given token
    fn key_id(&self, token: &str) -> Result<String> {
        let header = jsonwebtoken::decode_header(token)?;
        if header.kid.is_some() {
            Ok(header.kid.unwrap())
        } else {
            bail!("No key id found!")
        }
    }

    async fn decode<T>(
        &self,
        token: &str,
        key_jwk: &Jwk,
    ) -> Result<TokenData<T>>
    where
        T: DeserializeOwned,
    {
        let key: JsonWebKey = serde_json::to_string(key_jwk)?.parse()?;
        let mut validation = Validation::new(jsonwebtoken::Algorithm::RS256);
        if let Some(secs) = self.leeway {
            validation.leeway = secs;
        } else {
            // default PT2M
            validation.leeway = 120;
        }
        validation.aud = self.aud.clone();
        validation.iss = Some(self.issuer.clone());
        let tdata = jsonwebtoken::decode::<T>(
            token,
            &key.key.to_decoding_key(),
            &validation,
        )?;
        Ok(tdata)
    }
}

async fn get(issuer: &str) -> Result<Jwks> {
    let url = format!("{}/v1/keys", &issuer);
    let req = surf::get(&url);
    let client = build_client();
    let mut res = match client.send(req).await {
        Ok(r) => r,
        Err(e) => {
            bail!(e)
        }
    };
    let KeyResponse { keys } = match res.body_json().await {
        Ok(k) => k,
        Err(e) => {
            bail!(e)
        }
    };
    let mut keymap = Jwks { inner: HashMap::new() };
    for key in keys {
        keymap.inner.insert(key.kid.clone(), key);
    }
    Ok(keymap)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[async_std::test]
    async fn can_verify_token() -> Result<()> {
        dotenv::dotenv().ok();
        let issuer = dotenv::var("ISSUER")?;
        let token = dotenv::var("TEST_TOKEN")?;
        Verifier::new(&issuer).await?.verify::<DefaultClaims>(&token).await?;
        Ok(())
    }
}
