#![allow(dead_code)]
mod error;
mod key;
mod token;

use jsonwebtoken::TokenData;
use serde::de::DeserializeOwned;

pub use self::key::{JWK, JWKS};

type Result<T> = std::result::Result<T, error::Error>;

pub async fn verify<T>(issuer: &str, token: &str) -> Result<TokenData<T>>
where
    T: DeserializeOwned,
{
    let kid: String = token::key_id(&token)?;
    let jwks: JWKS = key::get(&issuer).await?;
    let jwk: Option<&JWK> = jwks.where_id(&kid);
    match jwk {
        Some(key_jwk) => {
            let key: jsonwebkey::JsonWebKey = serde_json::to_string(&key_jwk)?.parse()?;
            return Ok(token::decode::<T>(&token, key).await?);
        }
        None => {
            return Err(error::Error::Custom("No matching key found!".into()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize)]
    pub struct Claims {
        pub iss: String,
        pub sub: String,
        pub scp: Vec<String>,
        pub cid: String,
        pub uid: String,
        pub exp: u64,
        pub iat: u64,
    }

    #[async_std::test]
    async fn can_verify_token() -> Result<()> {
        dotenv::dotenv().ok();
        let issuer = dotenv::var("ISSUER")?;
        let token = dotenv::var("TEST_TOKEN")?;
        verify::<Claims>(&issuer, &token).await?;
        Ok(())
    }
}
