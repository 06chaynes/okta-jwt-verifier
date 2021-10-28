use jsonwebkey::JsonWebKey;
use jsonwebtoken::TokenData;
use okta_jwt_verifier::{key, token, Keys, JWK};
use redis::{Client, Commands, Connection, RedisError};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::env;
use tide::{http::mime::JSON, Request, Response, Result, Server, StatusCode};
use tide_http_auth::{Authentication, BearerAuthRequest, BearerAuthScheme, Storage};

fn connect() -> std::result::Result<Connection, RedisError> {
    let client = Client::open("redis://:password@host:port")?;
    Ok(client.get_connection()?)
}

pub fn get_jwks() -> std::result::Result<Option<String>, RedisError> {
    let mut conn = connect()?;
    let jwks: Option<String> = conn.get("jwks")?;
    Ok(jwks)
}

pub fn set_jwks(jwks: &str, expire: u32) -> std::result::Result<(), RedisError> {
    let mut conn = connect()?;
    let _: () = conn.set_ex("jwks", jwks, expire as usize)?;
    Ok(())
}

#[derive(Debug, PartialEq)]
pub enum Authenticated {
    User,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    iss: String,
    sub: String,
    scp: Vec<String>,
    cid: String,
    uid: String,
    exp: u64,
    iat: u64,
}

#[async_trait::async_trait]
impl Storage<Authenticated, BearerAuthRequest> for State {
    async fn get_user(&self, req: BearerAuthRequest) -> tide::Result<Option<Authenticated>> {
        let issuer = env::var("ISSUER").expect("You need to provide the ISSUER env variable!");
        let _data: TokenData<Claims>;
        let kid: String = token::key_id(&req.token)?;
        let cached_keys = match get_jwks() {
            Ok(cache) => cache,
            Err(_e) => None,
        };
        let keys: Keys;
        match cached_keys {
            Some(k) => {
                keys = serde_json::from_str(&k)?;
            }
            None => {
                keys = key::get(&issuer).await?;
                let s = serde_json::to_string(&keys)?;
                if let Some(age) = keys.max_age {
                    set_jwks(&s, age)?;
                };
            }
        }
        let jwk: Option<&JWK> = keys.jwks.where_id(&kid);
        match jwk {
            Some(key_jwk) => {
                let key: JsonWebKey = serde_json::to_string(&key_jwk)?.parse()?;
                _data = match token::decode::<Claims>(&req.token, key).await {
                    Ok(d) => d,
                    Err(_e) => {
                        return Ok(None);
                    }
                };
            }
            None => {
                return Ok(None);
            }
        }

        Ok(Some(Authenticated::User))
    }
}

#[derive(Clone)]
pub struct State {}

pub async fn protected(req: Request<State>) -> tide::Result {
    if let Some(_authenticated) = req.ext::<Authenticated>() {
        Ok(Response::builder(StatusCode::Ok)
            .body(json!({
                "message": "Here I am!"
            }))
            .content_type(JSON)
            .build())
    } else {
        Ok(Response::builder(StatusCode::Forbidden)
            .body(json!({
                "message": "Unauthenticated"
            }))
            .content_type(JSON)
            .build())
    }
}

#[async_std::main]
async fn main() -> Result<()> {
    let state = State {};
    tide::log::start();
    let mut app = Server::with_state(state);
    app.with(Authentication::new(BearerAuthScheme::default()));
    app.at("/").get(|_| async {
        Ok(json!({
            "message": "Hello World!"
        }))
    });
    app.at("/protected").get(protected);

    app.listen("0.0.0.0:8080").await?;
    Ok(())
}
