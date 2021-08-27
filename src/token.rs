use crate::{error::Error, Result};
use jsonwebkey::JsonWebKey;
use jsonwebtoken::{TokenData, Validation};
use serde::de::DeserializeOwned;

pub fn key_id(token: &str) -> Result<String> {
    let header = jsonwebtoken::decode_header(token)?;
    if header.kid.is_some() {
        Ok(header.kid.unwrap())
    } else {
        Err(Error::Custom("No key id found!".into()))
    }
}

pub async fn decode<T>(token: &str, key: JsonWebKey) -> Result<TokenData<T>>
where
    T: DeserializeOwned,
{
    let alg: jsonwebtoken::Algorithm = key.algorithm.unwrap_or(jsonwebkey::Algorithm::RS256).into();
    let validation = Validation::new(alg);
    let claims = jsonwebtoken::decode::<T>(token, &key.key.to_decoding_key(), &validation)?;
    Ok(claims)
}
