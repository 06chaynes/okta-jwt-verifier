use anyhow::{bail, Result};
use jsonwebkey::JsonWebKey;
use jsonwebtoken::{TokenData, Validation};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

/// Describes the default claims inside a decoded token
#[derive(Debug, Serialize, Deserialize)]
pub struct DefaultClaims {
    /// The Issuer Identifier of the response. This value is the unique identifier for the Authorization Server instance.
    pub iss: String,
    /// The subject of the token.
    pub sub: String,
    /// Array of scopes that are granted to this access token.
    pub scp: Vec<String>,
    /// Client ID of the client that requested the access token.
    pub cid: String,
    /// A unique identifier for the user. It isn't included in the access token if there is no user bound to it.
    pub uid: String,
    /// The time the access token expires, represented in Unix time (seconds).
    pub exp: u64,
    /// The time the access token was issued, represented in Unix time (seconds).
    pub iat: u64,
}

/// Attempts to retrieve a key id for a given token
pub fn key_id(token: &str) -> Result<String> {
    let header = jsonwebtoken::decode_header(token)?;
    if header.kid.is_some() {
        Ok(header.kid.unwrap())
    } else {
        bail!("No key id found!")
    }
}

/// Attempts to decode a given jwt against a given key
pub async fn decode<T>(token: &str, key: JsonWebKey) -> Result<TokenData<T>>
where
    T: DeserializeOwned,
{
    let alg: jsonwebtoken::Algorithm = key.algorithm.unwrap_or(jsonwebkey::Algorithm::RS256).into();
    let validation = Validation::new(alg);
    let claims = jsonwebtoken::decode::<T>(token, &key.key.to_decoding_key(), &validation)?;
    Ok(claims)
}
