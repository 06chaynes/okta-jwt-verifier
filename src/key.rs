use crate::{error::Error, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JWK {
    pub kty: String,
    pub alg: String,
    pub kid: String,
    #[serde(rename = "use")]
    pub uses: String,
    pub e: String,
    pub n: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Keys {
    pub jwks: JWKS,
    pub cache_control: Option<String>,
    pub expires: Option<String>,
    pub max_age: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JWKS {
    inner: HashMap<String, JWK>,
}

#[derive(Debug, Deserialize)]
struct KeyResponse {
    keys: Vec<JWK>,
}

impl JWKS {
    pub fn where_id(&self, kid: &str) -> Option<&JWK> {
        self.inner.get(kid)
    }
}

fn extract_max_age(text: &str) -> Result<u32> {
    let re = Regex::new(r"max-age=(\d+)")?;
    let caps = re.captures(text);
    if let Some(c) = caps {
        let s = c.get(1);
        if let Some(a) = s {
            let age: u32 = a.as_str().parse()?;
            return Ok(age);
        }
    }
    Err(Error::Custom(
        "Unable to extract max age from cache-control header".into(),
    ))
}

pub async fn get(issuer: &str) -> Result<Keys> {
    let url = format!("{}/v1/keys", &issuer);
    let mut res = match surf::get(&url).await {
        Ok(r) => r,
        Err(e) => {
            return Err(Error::Other(e.into_inner()));
        }
    };
    let cache_control = res.header("Cache-Control").map(|c| c.as_str().to_string());
    let max_age: Option<u32>;
    // TODO: Need to implement better error handling/logging, throwing away for now
    match &cache_control {
        Some(c) => match extract_max_age(c) {
            Ok(age) => max_age = Some(age),
            Err(_e) => max_age = None,
        },
        None => max_age = None,
    }
    let expires = res.header("expires").map(|c| c.as_str().to_string());
    let KeyResponse { keys } = match res.body_json().await {
        Ok(k) => k,
        Err(e) => {
            return Err(Error::Other(e.into_inner()));
        }
    };
    let mut keymap = JWKS {
        inner: HashMap::new(),
    };
    for key in keys {
        keymap.inner.insert(key.kid.clone(), key);
    }
    Ok(Keys {
        jwks: keymap,
        cache_control,
        expires,
        max_age,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Result;

    #[async_std::test]
    async fn can_get_key() -> Result<()> {
        dotenv::dotenv().ok();
        let issuer = dotenv::var("ISSUER")?;
        get(&issuer).await?;
        Ok(())
    }
}
