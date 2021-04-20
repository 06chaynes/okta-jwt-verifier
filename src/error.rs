use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("general io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("env error: {0}")]
    Env(#[from] dotenv::Error),
    #[error("uri error: {0}")]
    Uri(#[from] surf::http::url::ParseError),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("jwk error: {0}")]
    Jwk(#[from] jsonwebkey::Error),
    #[error("jwt error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),
    #[error("{0}")]
    Custom(String),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}
