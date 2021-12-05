//! A helper library for working with JWT's for Okta.
//!
//! ## Example
//!
//! ```no_run
//! use okta_jwt_verifier::{verify, DefaultClaims};
//! use serde::{Deserialize, Serialize};
//!
//! #[async_std::main]
//! async fn main() -> anyhow::Result<()> {
//!     let token = "token";
//!     let issuer = "https://your.domain/oauth2/default";
//!
//!     verify::<DefaultClaims>(&issuer, &token).await?;
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
/// Provides a method for retrieving keys from an upsteam auth endpoint
/// as well as structs to ease serialization/deserialization.
pub mod key;
/// Provides a method to decode a given jwt
/// and a struct describing the default claims.
pub mod token;

use anyhow::{bail, Result};
use jsonwebtoken::TokenData;
use serde::de::DeserializeOwned;

pub use self::key::{JWK, JWKS};
pub use self::token::DefaultClaims;

/// Accepts an issuer and token, attempts key retrieval,
/// then attempts to decode a token
pub async fn verify<T>(issuer: &str, token: &str) -> Result<TokenData<T>>
where
    T: DeserializeOwned,
{
    let kid: String = token::key_id(token)?;
    let keys: JWKS = key::get(issuer).await?;
    let jwk: Option<&JWK> = keys.where_id(&kid);
    match jwk {
        Some(key_jwk) => {
            let key: jsonwebkey::JsonWebKey = serde_json::to_string(&key_jwk)?.parse()?;
            token::decode::<T>(token, key).await
        }
        None => bail!("No matching key found!"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[async_std::test]
    async fn can_verify_token() -> Result<()> {
        dotenv::dotenv().ok();
        let issuer = dotenv::var("ISSUER")?;
        let token = dotenv::var("TEST_TOKEN")?;
        verify::<DefaultClaims>(&issuer, &token).await?;
        Ok(())
    }
}
