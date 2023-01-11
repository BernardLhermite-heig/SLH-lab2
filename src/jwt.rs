use crate::user::{AuthenticationMethod, UserDTO};
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
    pub fn new(user: UserDTO) -> Self {
        let iat = Utc::now();
        let exp = iat + Duration::hours(1);

        Self {
            sub: user.email,
            iat: iat.timestamp(),
            exp: exp.timestamp(),
            auth_method: user.auth_method,
        }
    }
}

impl VerificationClaims {
    pub fn new(email: &str) -> Self {
        let iat = Utc::now();
        let exp = iat + Duration::hours(24);

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
