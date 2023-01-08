use crate::db::Pool;
use crate::user::{AuthenticationMethod, UserDTO};
use axum::async_trait;
use axum::extract::{FromRef, FromRequestParts};
use axum::http::request::Parts;
use axum::response::Redirect;
use axum::RequestPartsExt;
use axum_extra::extract::CookieJar;

use axum_sessions::async_session::chrono::{Duration, Utc};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation};
use lazy_static::lazy_static;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::{env, error::Error};

lazy_static! {
    static ref JWT_SECRET: String = env::var("JWT_SECRET").expect("JWT_SECRET must be set");
}

#[derive(Deserialize, Serialize)]
pub struct LoginClaims {
    pub sub: String,
    pub exp: i64,
    pub iat: i64,
    pub auth_method: AuthenticationMethod,
}

#[derive(Deserialize, Serialize)]
pub struct VerificationClaims {
    pub sub: String,
    pub exp: i64,
    pub iat: i64,
}

impl LoginClaims {
    pub fn new(user: UserDTO, duration: Duration) -> Self {
        let iat = Utc::now();
        let exp = iat + duration;

        Self {
            sub: user.email,
            iat: iat.timestamp(),
            exp: exp.timestamp(),
            auth_method: user.auth_method,
        }
    }
}

impl VerificationClaims {
    pub fn new(email: &str, duration: Duration) -> Self {
        let iat = Utc::now();
        let exp = iat + duration;

        Self {
            sub: email.to_string(),
            iat: iat.timestamp(),
            exp: exp.timestamp(),
        }
    }
}

pub fn sign<T: Serialize>(claims: T) -> Result<String, Box<dyn Error>> {
    Ok(jsonwebtoken::encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(JWT_SECRET.as_bytes()),
    )?)
}

pub fn verify<T: DeserializeOwned>(token: &str) -> Result<T, Box<dyn Error>> {
    Ok(jsonwebtoken::decode(
        token,
        &DecodingKey::from_secret(JWT_SECRET.as_bytes()),
        &Validation::default(),
    )
    .map(|data| data.claims)?)
}

const REDIRECT_URL: &str = "/home";

/// Retrieves a UserDTO from request parts if a user is currently authenticated.
#[async_trait]
impl<S> FromRequestParts<S> for UserDTO
where
    Pool: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Redirect;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // TODO: You have to read the auth cookie and verify the JWT to ensure the user is
        //       authenticated.
        let jar = parts
            .extract::<CookieJar>()
            .await
            .expect("Could not get CookieJar from request parts");
        let _jwt = jar
            .get(crate::web_auth::COOKIE_AUTH.as_str())
            .ok_or_else(|| Redirect::to(REDIRECT_URL))?
            .value();

        verify::<LoginClaims>(_jwt)
            .map(|c| UserDTO {
                email: c.sub,
                auth_method: c.auth_method,
            })
            .map_err(|_| Redirect::to(REDIRECT_URL))
    }
}
