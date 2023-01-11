use crate::db::Pool;
use crate::jwt::{self, LoginClaims};
use crate::user::UserDTO;
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::async_trait;
use axum::extract::{FromRef, FromRequestParts};
use axum::http::request::Parts;
use axum::response::Redirect;
use axum::RequestPartsExt;
use axum_extra::extract::CookieJar;

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

        jwt::verify::<LoginClaims>(_jwt)
            .map(|c| Self {
                email: c.sub,
                auth_method: c.auth_method,
            })
            .map_err(|_| Redirect::to(REDIRECT_URL))
    }
}

/// Checks that the given password matches the given hash
pub fn compare_hash(hash: &str, password: &str) -> Result<(), argon2::password_hash::Error> {
    let argon2 = Argon2::default();
    let parsed_hash = PasswordHash::new(hash).unwrap();
    argon2.verify_password(password.as_bytes(), &parsed_hash)
}

/// Creates a new Argon2 hash from the given password
pub fn create_hash(password: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    argon2
        .hash_password(password.as_bytes(), &salt)
        .unwrap()
        .to_string()
}
