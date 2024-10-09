//! A helper library for working with JWT's for Okta.
//!
//! The purpose of this library is to help with the
//! verification of access and ID tokens issued by Okta.
//! See [`Verifier`] for more examples, and a
//! [tide](https://github.com/http-rs/tide) middleware
//! implementation in the repository under the examples directory.
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
#![forbid(unsafe_code, future_incompatible)]
#![deny(
    missing_docs,
    missing_debug_implementations,
    missing_copy_implementations,
    nonstandard_style,
    unused_qualifications
)]

#[cfg(not(any(feature = "client-surf", feature = "client-reqwest")))]
compile_error!("Either feature \"client-surf\" or \"client-reqwest\" must be enabled for this crate.");

#[cfg(all(feature = "client-surf", feature = "client-reqwest"))]
compile_error!("Only either feature \"client-surf\" or \"client-reqwest\" must be enabled for this crate, not both.");

#[cfg(all(feature = "cache-surf", not(feature = "client-surf")))]
compile_error!(
    "Feature \"cache-surf\" requires that \"client-surf\" be enabled."
);

#[cfg(all(feature = "cache-reqwest", not(feature = "client-reqwest")))]
compile_error!(
    "Feature \"cache-reqwest\" requires that \"client-reqwest\" be enabled."
);

use std::collections::{HashMap, HashSet};

use anyhow::{bail, Result};
use jsonwebkey::JsonWebKey;
use jsonwebtoken::{TokenData, Validation};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

#[cfg(feature = "cache-surf")]
use http_cache_surf::{
    CACacheManager, Cache, CacheMode, HttpCache, HttpCacheOptions,
};

#[cfg(feature = "cache-reqwest")]
use http_cache_reqwest::{
    CACacheManager, Cache, CacheMode, HttpCache, HttpCacheOptions,
};

const DEFAULT_ENDPOINT: &str = "/v1/keys";

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

// Describes issuer keys response
#[derive(Debug, Deserialize)]
struct KeyResponse {
    keys: Vec<Jwk>,
}

// Needed for the cid verification workaround
#[derive(Debug, Serialize, Deserialize)]
struct ClientId {
    cid: String,
}

impl Jwks {
    // Attempts to retrieve a key by given id
    pub fn where_id(&self, kid: &str) -> Option<&Jwk> {
        self.inner.get(kid)
    }
}

/// Describes optional config when creating a new Verifier
#[derive(Debug)]
pub struct Config {
    /// The endpoint to retrieve json web keys from
    pub keys_endpoint: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self { keys_endpoint: Some(DEFAULT_ENDPOINT.into()) }
    }
}

/// Attempts to retrieve the keys from an Okta issuer,
/// decode and verify a given access/ID token, and
/// deserialize the requested claims.
#[derive(Debug, Clone)]
pub struct Verifier {
    issuer: String,
    cid: Option<String>,
    leeway: Option<u64>,
    aud: Option<HashSet<String>>,
    keys: Jwks,
}

impl Verifier {
    /// `new` constructs an instance of Verifier and attempts
    /// to retrieve the keys from the specified issuer.
    pub async fn new(issuer: &str) -> Result<Self> {
        let keys = get(issuer, DEFAULT_ENDPOINT).await?;
        Ok(Self {
            issuer: issuer.to_string(),
            cid: None,
            leeway: None,
            aud: None,
            keys,
        })
    }

    /// `configure` constructs an instance of Verifier and attempts
    /// to retrieve the keys from the specified issuer while specifying extra config.
    pub async fn new_with_config(issuer: &str, config: Config) -> Result<Self> {
        let mut endpoint = DEFAULT_ENDPOINT.to_owned();
        if let Some(keys_endpoint) = config.keys_endpoint {
            endpoint = keys_endpoint
        }
        let keys = get(issuer, &endpoint).await?;
        Ok(Self {
            issuer: issuer.to_string(),
            cid: None,
            leeway: None,
            aud: None,
            keys,
        })
    }

    /// `verify` will attempt to validate a passed access
    /// or ID token. Upon a successful validation it will then
    /// attempt to deserialize the requested claims. A [`DefaultClaims`]
    /// struct has been provided for use or to serve as an example
    /// for constructing a custom claim struct.
    ///
    /// ```no_run
    /// use okta_jwt_verifier::{Verifier, DefaultClaims};
    ///
    /// #[async_std::main]
    /// async fn main() -> anyhow::Result<()> {
    ///     let token = "token";
    ///     let issuer = "https://your.domain/oauth2/default";
    ///
    ///     Verifier::new(&issuer)
    ///         .await?
    ///         .verify::<DefaultClaims>(&token)
    ///         .await?;
    ///     Ok(())
    /// }
    ///```
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

    /// `client_id` can be used to require cid claim verification.
    ///
    /// ```no_run
    /// use okta_jwt_verifier::{Verifier, DefaultClaims};
    ///
    /// #[async_std::main]
    /// async fn main() -> anyhow::Result<()> {
    ///     let token = "token";
    ///     let issuer = "https://your.domain/oauth2/default";
    ///
    ///     Verifier::new(&issuer)
    ///         .await?
    ///         .client_id("Bl3hStrINgiD")
    ///         .verify::<DefaultClaims>(&token)
    ///         .await?;
    ///     Ok(())
    /// }
    ///```
    pub fn client_id(mut self, cid: &str) -> Self {
        self.cid = Some(cid.to_string());
        self
    }

    /// `audience` is for setting multiple aud values
    /// to check against.
    ///
    /// ```no_run
    /// use okta_jwt_verifier::{Verifier, DefaultClaims};
    /// use std::collections::HashSet;
    ///
    /// #[async_std::main]
    /// async fn main() -> anyhow::Result<()> {
    ///     let token = "token";
    ///     let issuer = "https://your.domain/oauth2/default";
    ///     let mut aud = HashSet::new();
    ///     aud.insert("api://default".to_string());
    ///     aud.insert("api://admin".to_string());
    ///
    ///     Verifier::new(&issuer)
    ///         .await?
    ///         .audience(aud)
    ///         .verify::<DefaultClaims>(&token)
    ///         .await?;
    ///     Ok(())
    /// }
    ///```
    pub fn audience(mut self, audience: HashSet<String>) -> Self {
        self.aud = Some(audience);
        self
    }

    /// `add_audience` helps to make adding a single
    /// aud entry easier.
    ///
    /// ```no_run
    /// use okta_jwt_verifier::{Verifier, DefaultClaims};
    ///
    /// #[async_std::main]
    /// async fn main() -> anyhow::Result<()> {
    ///     let token = "token";
    ///     let issuer = "https://your.domain/oauth2/default";
    ///
    ///     Verifier::new(&issuer)
    ///         .await?
    ///         .add_audience("api://default")
    ///         .verify::<DefaultClaims>(&token)
    ///         .await?;
    ///     Ok(())
    /// }
    ///```
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

    /// `leeway` is for overriding the default leeway
    /// of 120 seconds, this is to help deal with clock skew.
    ///
    /// ```no_run
    /// use okta_jwt_verifier::{Verifier, DefaultClaims};
    ///
    /// #[async_std::main]
    /// async fn main() -> anyhow::Result<()> {
    ///     let token = "token";
    ///     let issuer = "https://your.domain/oauth2/default";
    ///
    ///     Verifier::new(&issuer)
    ///         .await?
    ///         .leeway(60)
    ///         .verify::<DefaultClaims>(&token)
    ///         .await?;
    ///     Ok(())
    /// }
    ///```
    pub fn leeway(mut self, leeway: u64) -> Self {
        self.leeway = Some(leeway);
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

    // Attempts to decode the passed token and deserialize the claims
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
        if let Some(cid) = &self.cid {
            // This isn't ideal but what we have to do for now
            let cid_tdata = jsonwebtoken::decode::<ClientId>(
                token,
                &key.key.to_decoding_key(),
                &validation,
            )?;
            if &cid_tdata.claims.cid != cid {
                bail!("client_id validation failed!")
            }
        }
        if let Some(secs) = self.leeway {
            validation.leeway = secs;
        } else {
            // default PT2M
            validation.leeway = 120;
        }
        validation.aud = self.aud.clone();
        let mut iss = HashSet::new();
        iss.insert(self.issuer.clone());
        validation.iss = Some(iss);
        let tdata = jsonwebtoken::decode::<T>(
            token,
            &key.key.to_decoding_key(),
            &validation,
        )?;
        Ok(tdata)
    }
}

// Attempts to retrieve the keys from the issuer
async fn get(issuer: &str, keys_endpoint: &str) -> Result<Jwks> {
    let url = format!(
        "{issuer}{keys_endpoint}",
        issuer = &issuer,
        keys_endpoint = &keys_endpoint
    );
    let keys = remote_fetch(&url).await?;
    let mut keymap = Jwks { inner: HashMap::new() };
    for key in keys {
        keymap.inner.insert(key.kid.clone(), key);
    }
    Ok(keymap)
}

// Builds a default surf client
#[cfg(all(feature = "client-surf", not(feature = "cache-surf")))]
fn build_surf_client() -> surf::Client {
    surf::Client::new()
}

// Builds a surf client configured to use a disk cache
#[cfg(all(feature = "client-surf", feature = "cache-surf"))]
fn build_surf_client() -> surf::Client {
    surf::Client::new().with(Cache(HttpCache {
        mode: CacheMode::Default,
        manager: CACacheManager::default(),
        options: HttpCacheOptions::default(),
    }))
}

#[cfg(feature = "client-surf")]
async fn remote_fetch(url: &str) -> Result<Vec<Jwk>> {
    let req = surf::get(url);
    let client = build_surf_client();
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
    Ok(keys)
}

// Builds a default reqwest client
#[cfg(all(feature = "client-reqwest", not(feature = "cache-reqwest")))]
fn build_reqwest_client() -> reqwest_middleware::ClientWithMiddleware {
    reqwest_middleware::ClientBuilder::new(reqwest::Client::new()).build()
}

// Builds a reqwest client configured to use a disk cache
#[cfg(all(feature = "client-reqwest", feature = "cache-reqwest"))]
fn build_reqwest_client() -> reqwest_middleware::ClientWithMiddleware {
    reqwest_middleware::ClientBuilder::new(reqwest::Client::new())
        .with(Cache(HttpCache {
            mode: CacheMode::Default,
            manager: CACacheManager::default(),
            options: HttpCacheOptions::default(),
        }))
        .build()
}

#[cfg(feature = "client-reqwest")]
async fn remote_fetch(url: &str) -> Result<Vec<Jwk>> {
    let client = build_reqwest_client();
    let res = client.get(url).send().await?;
    let KeyResponse { keys } = res.json().await?;
    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;

    use jwt_simple::prelude::*;

    #[cfg(feature = "client-surf")]
    use async_std::test as async_test;
    #[cfg(feature = "client-reqwest")]
    use tokio::test as async_test;

    #[derive(Debug, serde::Serialize)]
    struct Res {
        keys: Vec<Jwk>,
    }

    // Pulled test data from https://github.com/jedisct1/rust-jwt-simple/blob/master/src/lib.rs

    const RSA_KP_PEM: &str = r"
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAyqq0N5u8Jvl+BLH2VMP/NAv/zY9T8mSq0V2Gk5Ql5H1a+4qi
3viorUXG3AvIEEccpLsW85ps5+I9itp74jllRjA5HG5smbb+Oym0m2Hovfj6qP/1
m1drQg8oth6tNmupNqVzlGGWZLsSCBLuMa3pFaPhoxl9lGU3XJIQ1/evMkOb98I3
hHb4ELn3WGtNlAVkbP20R8sSii/zFjPqrG/NbSPLyAl1ctbG2d8RllQF1uRIqYQj
85yx73hqQCMpYWU3d9QzpkLf/C35/79qNnSKa3t0cyDKinOY7JGIwh8DWAa4pfEz
gg56yLcilYSSohXeaQV0nR8+rm9J8GUYXjPK7wIDAQABAoIBAQCpeRPYyHcPFGTH
4lU9zuQSjtIq/+bP9FRPXWkS8bi6GAVEAUtvLvpGYuoGyidTTVPrgLORo5ncUnjq
KwebRimlBuBLIR/Zboery5VGthoc+h4JwniMnQ6JIAoIOSDZODA5DSPYeb58n15V
uBbNHkOiH/eoHsG/nOAtnctN/cXYPenkCfeLXa3se9EzkcmpNGhqCBL/awtLU17P
Iw7XxsJsRMBOst4Aqiri1GQI8wqjtXWLyfjMpPR8Sqb4UpTDmU1wHhE/w/+2lahC
Tu0/+sCWj7TlafYkT28+4pAMyMqUT6MjqdmGw8lD7/vXv8TF15NU1cUv3QSKpVGe
50vlB1QpAoGBAO1BU1evrNvA91q1bliFjxrH3MzkTQAJRMn9PBX29XwxVG7/HlhX
0tZRSR92ZimT2bAu7tH0Tcl3Bc3NwEQrmqKlIMqiW+1AVYtNjuipIuB7INb/TUM3
smEh+fn3yhMoVxbbh/klR1FapPUFXlpNv3DJHYM+STqLMhl9tEc/I7bLAoGBANqt
zR6Kovf2rh7VK/Qyb2w0rLJE7Zh/WI+r9ubCba46sorqkJclE5cocxWuTy8HWyQp
spxzLP1FQlsI+MESgRLueoH3HtB9lu/pv6/8JlNjU6SzovfUZ0KztVUyUeB4vAcH
pGcf2CkUtoYc8YL22Ybck3s8ThIdnY5zphCF55PtAoGAf46Go3c05XVKx78R05AD
D2/y+0mnSGSzUjHPMzPyadIPxhltlCurlERhnwPGC4aNHFcvWTwS8kUGns6HF1+m
JNnI1okSCW10UI/jTJ1avfwU/OKIBKKWSfi9cDJTt5cRs51V7pKnVEr6sy0uvDhe
u+G091HuhwY9ak0WNtPwfJ8CgYEAuRdoyZQQso7x/Bj0tiHGW7EOB2n+LRiErj6g
odspmNIH8zrtHXF9bnEHT++VCDpSs34ztuZpywnHS2SBoHH4HD0MJlszksbqbbDM
1bk3+1bUIlEF/Hyk1jljn3QTB0tJ4y1dwweaH9NvVn7DENW9cr/aePGnJwA4Lq3G
fq/IPlUCgYAuqgJQ4ztOq0EaB75xgqtErBM57A/+lMWS9eD/euzCEO5UzWVaiIJ+
nNDmx/jvSrxA1Ih8TEHjzv4ezLFYpaJrTst4Mjhtx+csXRJU9a2W6HMXJ4Kdn8rk
PBziuVURslNyLdlFsFlm/kfvX+4Cxrbb+pAGETtRTgmAoCDbvuDGRQ==
-----END RSA PRIVATE KEY-----
    ";

    const KEY_ID: &str = "12345";

    const RSA_MOD: &str = r"yqq0N5u8Jvl-BLH2VMP_NAv_zY9T8mSq0V2Gk5Ql5H1a-4qi3viorUXG3AvIEEccpLsW85ps5-I9itp74jllRjA5HG5smbb-Oym0m2Hovfj6qP_1m1drQg8oth6tNmupNqVzlGGWZLsSCBLuMa3pFaPhoxl9lGU3XJIQ1_evMkOb98I3hHb4ELn3WGtNlAVkbP20R8sSii_zFjPqrG_NbSPLyAl1ctbG2d8RllQF1uRIqYQj85yx73hqQCMpYWU3d9QzpkLf_C35_79qNnSKa3t0cyDKinOY7JGIwh8DWAa4pfEzgg56yLcilYSSohXeaQV0nR8-rm9J8GUYXjPK7w";

    #[async_test]
    async fn can_verify_token() -> Result<()> {
        let mut server = mockito::Server::new_async().await;
        let key_pair = RS256KeyPair::from_pem(RSA_KP_PEM)?.with_key_id(KEY_ID);
        let jsonwk = Jwk {
            kty: "RSA".to_string(),
            alg: "RS256".to_string(),
            kid: KEY_ID.to_string(),
            uses: "sig".to_string(),
            e: "AQAB".to_string(),
            n: RSA_MOD.to_string(),
        };
        let claims = Claims::create(Duration::from_hours(2))
            .with_issuer(server.url())
            .with_subject("test");
        let token = key_pair.sign(claims)?;
        let res = Res { keys: vec![jsonwk] };
        let m = server
            .mock("GET", DEFAULT_ENDPOINT)
            .with_status(200)
            .with_body(serde_json::to_string(&res)?)
            .create();
        let verifier = Verifier::new(&server.url()).await?;
        m.assert();
        verifier.verify::<DefaultClaims>(&token).await?;
        Ok(())
    }

    #[async_test]
    async fn can_verify_token_with_config() -> Result<()> {
        let mut server = mockito::Server::new_async().await;
        let key_pair = RS256KeyPair::from_pem(RSA_KP_PEM)?.with_key_id(KEY_ID);
        let jsonwk = Jwk {
            kty: "RSA".to_string(),
            alg: "RS256".to_string(),
            kid: KEY_ID.to_string(),
            uses: "sig".to_string(),
            e: "AQAB".to_string(),
            n: RSA_MOD.to_string(),
        };
        let config: Config =
            Config { keys_endpoint: Some("/oauth2/v1/keys".to_owned()) };
        let claims = Claims::create(Duration::from_hours(2))
            .with_issuer(server.url())
            .with_subject("test");
        let token = key_pair.sign(claims)?;
        let res = Res { keys: vec![jsonwk] };
        let m = server
            .mock("GET", "/oauth2/v1/keys")
            .with_status(200)
            .with_body(serde_json::to_string(&res)?)
            .create();
        let verifier = Verifier::new_with_config(&server.url(), config).await?;
        m.assert();
        verifier.verify::<DefaultClaims>(&token).await?;
        Ok(())
    }

    #[async_test]
    async fn can_verify_token_with_empty_config() -> Result<()> {
        let mut server = mockito::Server::new_async().await;
        let key_pair = RS256KeyPair::from_pem(RSA_KP_PEM)?.with_key_id(KEY_ID);
        let jsonwk = Jwk {
            kty: "RSA".to_string(),
            alg: "RS256".to_string(),
            kid: KEY_ID.to_string(),
            uses: "sig".to_string(),
            e: "AQAB".to_string(),
            n: RSA_MOD.to_string(),
        };
        let config: Config = Config::default();
        let claims = Claims::create(Duration::from_hours(2))
            .with_issuer(server.url())
            .with_subject("test");
        let token = key_pair.sign(claims)?;
        let res = Res { keys: vec![jsonwk] };
        let m = server
            .mock("GET", DEFAULT_ENDPOINT)
            .with_status(200)
            .with_body(serde_json::to_string(&res)?)
            .create();
        let verifier = Verifier::new_with_config(&server.url(), config).await?;
        m.assert();
        verifier.verify::<DefaultClaims>(&token).await?;
        Ok(())
    }
}
