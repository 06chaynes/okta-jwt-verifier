use crate::{error::Error, Result};
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

pub async fn get(issuer: &str) -> Result<JWKS> {
    let url = format!("{}/v1/keys", &issuer);
    let KeyResponse { keys } = match surf::get(&url).recv_json().await {
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
    Ok(keymap)
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
