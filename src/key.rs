use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[cfg(feature = "disk-cache")]
use surf_middleware_cache::{managers::CACacheManager, Cache, CacheMode};

/// Describes the key retrieved from upstream
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JWK {
    /// The "kty" (key type) parameter identifies the cryptographic algorithm
    /// family used with the key, such as "RSA" or "EC".
    pub kty: String,
    /// The "alg" (algorithm) parameter identifies the algorithm intended for
    /// use with the key.
    pub alg: String,
    /// The "kid" (key ID) parameter is used to match a specific key.  This
    /// is used, for instance, to choose among a set of keys within a JWK Set
    /// during key rollover.  The structure of the "kid" value is
    /// unspecified.  When "kid" values are used within a JWK Set, different
    /// keys within the JWK Set SHOULD use distinct "kid" values.
    pub kid: String,
    /// The "use" (public key use) parameter identifies the intended use of
    /// the public key.  The "use" parameter is employed to indicate whether
    /// a public key is used for encrypting data or verifying the signature
    // on data.
    #[serde(rename = "use")]
    pub uses: String,
    /// RSA public exponent is used on signed / encoded data to decode the original value
    pub e: String,
    /// RSA modulus is the product of two prime numbers used to generate the key pair
    pub n: String,
}

/// Container for keys
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JWKS {
    inner: HashMap<String, JWK>,
}

#[derive(Debug, Deserialize)]
struct KeyResponse {
    keys: Vec<JWK>,
}

impl JWKS {
    /// Attempts to retrieve a key by given id
    pub fn where_id(&self, kid: &str) -> Option<&JWK> {
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

/// Attempts to retrieve keys from upstream auth endpoint
pub async fn get(issuer: &str) -> Result<JWKS> {
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
    use anyhow::Result;

    #[async_std::test]
    async fn can_get_key() -> Result<()> {
        dotenv::dotenv().ok();
        let issuer = dotenv::var("ISSUER")?;
        get(&issuer).await?;
        Ok(())
    }
}
