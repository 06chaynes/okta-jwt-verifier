use okta_jwt_verifier::{DefaultClaims, Verifier};
use serde_json::json;
use std::env;
use tide::{http::mime::JSON, Request, Response, Result, Server, StatusCode};
use tide_http_auth::{
    Authentication, BearerAuthRequest, BearerAuthScheme, Storage,
};

#[derive(Debug, PartialEq)]
pub enum Authenticated {
    User,
}

#[async_trait::async_trait]
impl Storage<Authenticated, BearerAuthRequest> for State {
    async fn get_user(
        &self,
        req: BearerAuthRequest,
    ) -> tide::Result<Option<Authenticated>> {
        let issuer = env::var("ISSUER")
            .expect("You need to provide the ISSUER env variable!");
        let _tokendata = Verifier::new(&issuer, None, None)
            .await?
            .verify::<DefaultClaims>(&req.token)
            .await?;
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
