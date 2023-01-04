use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use log::{error, info};

use crate::{
    auth,
    db::update_password,
    models::{AppState, LoginRequest, OAuthRedirect, PasswordUpdateRequest, RegisterRequest},
};
use crate::{
    db::set_user_verified,
    user::{AuthenticationMethod, User, UserDTO},
};
use crate::{
    db::{get_user, save_user, user_exists, DbConn},
    mailer::{send_email, SmtpConfig},
};
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use axum_extra::extract::cookie::Cookie;
use axum_extra::extract::CookieJar;
use axum_sessions::{async_session::MemoryStore, async_session::Session};
use lazy_static::lazy_static;
use serde_json::json;
use std::{borrow::Borrow, collections::HashMap, env, error::Error};

lazy_static! {
    static ref DEFAULT_PASSWORD: String = "Mr6XpGiKR8aMfr".to_string();
    static ref APP_URL: String = {
        let mut url = env::var("APP_URL").expect("APP_URL must be set");
        if url.ends_with('/') {
            url = url[0..url.len() - 1].to_string();
        }
        url
    };
}

/// Declares the different endpoints
/// state is used to pass common structs to the endpoints
pub fn stage(state: AppState) -> Router {
    Router::new()
        .route("/login", post(login))
        .route("/register", post(register))
        .route("/oauth/google", get(google_oauth))
        .route("/_oauth", get(oauth_redirect))
        .route("/password_update", post(password_update))
        .route("/logout", get(logout))
        .route("/verify", get(verify_email))
        .with_state(state)
}

/// Endpoint handling login
/// POST /login
/// BODY { "login_email": "email", "login_password": "password" }
async fn login(
    mut _conn: DbConn,
    jar: CookieJar,
    Json(login): Json<LoginRequest>,
) -> Result<(CookieJar, AuthResult), Response> {
    // TODO: Implement the login function. You can use the functions inside db.rs to check if
    //       the user exists and get the user info.
    let _email = login.login_email.to_lowercase();
    let _password = login.login_password;
    let argon2 = Argon2::default();
    let default_salt = SaltString::generate(&mut OsRng);

    let user_dto = match get_user(&mut _conn, _email.as_str()) {
        Ok(user) => {
            let parsed_hash = PasswordHash::new(&user.password).unwrap();
            if argon2
                .verify_password(_password.as_bytes(), &parsed_hash)
                .is_ok()
            {
                if !user.email_verified {
                    info!("Failed to login user: {}, email not verified", _email);
                    return Ok((jar, AuthResult::UnverifiedAccount));
                }

                user.to_dto()
            } else {
                info!("Failed to login user: {}, wrong password", _email);
                return Ok((jar, AuthResult::AuthFailed));
            }
        }
        Err(_) => {
            let parsed_hash = argon2
                .hash_password(DEFAULT_PASSWORD.as_bytes(), &default_salt)
                .unwrap();
            _ = argon2.verify_password(_password.as_bytes(), &parsed_hash);
            info!("Failed to login user: {}, not found", _email);
            return Ok((jar, AuthResult::AuthFailed));
        }
    };

    info!("User logged in: {}", _email);

    // Once the user has been created, authenticate the user by adding a JWT cookie in the cookie jar
    // let jar = add_auth_cookie(jar, &user_dto)
    //     .or(Err(StatusCode::INTERNAL_SERVER_ERROR.into_response()))?;

    let jar = add_auth_cookie(jar, &user_dto)
        .or(Err(StatusCode::INTERNAL_SERVER_ERROR.into_response()))?;

    Ok((jar, AuthResult::Success))
}

/// Endpoint used to register a new account
/// POST /register
/// BODY { "register_email": "email", "register_password": "password", "register_password2": "password" }
async fn register(
    mut conn: DbConn,
    State(_session_store): State<MemoryStore>,
    State(smtp_config): State<SmtpConfig>,
    Json(register): Json<RegisterRequest>,
) -> Result<AuthResult, Response> {
    // TODO: Implement the register function. The email must be verified by sending a link.
    //       You can use the functions inside db.rs to add a new user to the DB.
    if register.register_password != register.register_password2 {
        info!(
            "Failed to register user: {}, passwords don't match",
            register.register_email
        );
        return Ok(AuthResult::PasswordMismatch);
    }

    let email = register.register_email.to_lowercase();
    let password = register.register_password;
    let argon2 = Argon2::default();
    let salt = SaltString::generate(&mut OsRng);

    let user = match user_exists(&mut conn, email.as_str()) {
        Err(_) => {
            let password_hash = argon2
                .hash_password(password.as_bytes(), &salt)
                .unwrap()
                .to_string();

            let new_user = User::new(
                email.as_str(),
                password_hash.as_str(),
                AuthenticationMethod::Password,
                false,
            );

            let user = new_user.to_dto();

            if let Err(e) = save_user(&mut conn, new_user) {
                error!("Failed to save user: {}", e);
                return Err(StatusCode::INTERNAL_SERVER_ERROR.into_response());
            }

            user
        }
        Ok(_) => {
            _ = argon2.hash_password(DEFAULT_PASSWORD.as_bytes(), &salt);
            info!("Failed to register user: {}, already exists", email);
            return Ok(AuthResult::AccountAlreadyExists);
        }
    };

    info!("User registered: {}", email);

    let token = auth::sign(user).or(Err(StatusCode::INTERNAL_SERVER_ERROR.into_response()))?;

    send_email(
        &smtp_config,
        email.as_str(),
        "Account verification",
        &format!(
            "Please verify your account by clicking on the following <a href=\"{}/verify?token={}\">link</a>",
            *APP_URL, token
        ),
    )
    .or(Err(StatusCode::INTERNAL_SERVER_ERROR.into_response()))?;

    Ok(AuthResult::Success)
    // Once the user has been created, send a verification link by email
    // If you need to store data between requests, you may use the session_store. You need to first
    // create a new Session and store the variables. Then, you add the session to the session_store
    // to get a session_id. You then store the session_id in a cookie.
}

// TODO: Create the endpoint for the email verification function.
/// Endpoint used to verify an email address
/// GET /verify_email?token={token}
async fn verify_email(
    mut conn: DbConn,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Redirect, StatusCode> {
    let token = match params.get("token") {
        Some(token) => token,
        None => {
            info!("Failed to verify email: no token provided");
            return Err(StatusCode::BAD_REQUEST);
        }
    };
    let claims = match auth::verify(token) {
        Ok(claims) => claims,
        Err(_) => {
            info!("Failed to verify email: invalid token");
            return Err(StatusCode::BAD_REQUEST);
        }
    };

    set_user_verified(&mut conn, &claims.sub)
        .and(Ok(Redirect::to("login")))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

/// Endpoint used for the first OAuth step
/// GET /oauth/google
async fn google_oauth(
    jar: CookieJar,
    State(_session_store): State<MemoryStore>,
) -> Result<(CookieJar, Redirect), StatusCode> {
    // TODO: This function is used to authenticate a user with Google's OAuth2 service.
    //       We want to use a PKCE authentication flow, you will have to generate a
    //       random challenge and a CSRF token. In order to get the email address of
    //       the user, use the following scope: https://www.googleapis.com/auth/userinfo.email
    //       Use Redirect::to(url) to redirect the user to Google's authentication form.

    // let client = crate::oauth::OAUTH_CLIENT.todo();

    // If you need to store data between requests, you may use the session_store. You need to first
    // create a new Session and store the variables. Then, you add the session to the session_store
    // to get a session_id. You then store the session_id in a cookie.
    Ok((jar, Redirect::to("myurl")))
}

/// Endpoint called after a successful OAuth login.
/// GET /_oauth?state=x&code=y
async fn oauth_redirect(
    jar: CookieJar,
    State(_session_store): State<MemoryStore>,
    _conn: DbConn,
    _params: Query<OAuthRedirect>,
) -> Result<(CookieJar, Redirect), StatusCode> {
    // TODO: The user should be redirected to this page automatically after a successful login.
    //       You will need to verify the CSRF token and ensure the authorization code is valid
    //       by interacting with Google's OAuth2 API (use an async request!). Once everything
    //       was verified, get the email address with the provided function (get_oauth_email)
    //       and create a JWT for the user.

    // If you need to recover data between requests, you may use the session_store to load a session
    // based on a session_id.

    // Once the OAuth user is authenticated, create the user in the DB and add a JWT cookie
    // let jar = add_auth_cookie(jar, &user_dto).or(Err(StatusCode::INTERNAL_SERVER_ERROR))?;
    Ok((jar, Redirect::to("/home")))
}

/// Endpoint handling login
/// POST /password_update
/// BODY { "old_password": "pass", "new_password": "pass" }
async fn password_update(
    mut _conn: DbConn,
    State(smtp_config): State<SmtpConfig>,
    _user: UserDTO,
    Json(_update): Json<PasswordUpdateRequest>,
) -> Result<AuthResult, Response> {
    if _update.old_password == _update.new_password {
        return Ok(AuthResult::PasswordIdentical);
    }

    let argon2 = Argon2::default();

    match get_user(&mut _conn, &_user.email) {
        Ok(user) => {
            let password_hash = PasswordHash::new(&user.password).unwrap();
            if argon2
                .verify_password(_update.old_password.as_bytes(), &password_hash)
                .is_err()
            {
                return Ok(AuthResult::WrongPassword);
            }
        }
        Err(_) => {
            error!("Failed to get user for password update: {}", &_user.email);
            return Err(StatusCode::INTERNAL_SERVER_ERROR.into_response());
        }
    }

    let salt = SaltString::generate(&mut OsRng);
    let password_hash = argon2
        .hash_password(_update.new_password.as_bytes(), &salt)
        .unwrap()
        .to_string();

    match update_password(&mut _conn, &_user.email, &password_hash) {
        Ok(_) => {
            send_email(&smtp_config, &_user.email, "Password updated", "Your password was updated successfully.")
                .and(Ok(AuthResult::Success))
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
        },
        Err(_) => {
            error!("Failed to update password for user: {}", &_user.email);
            Err(StatusCode::INTERNAL_SERVER_ERROR.into_response())
        }
    }
}

/// Endpoint handling the logout logic
/// GET /logout
async fn logout(jar: CookieJar) -> impl IntoResponse {
    let new_jar = jar.remove(Cookie::named("auth"));
    (new_jar, Redirect::to("/home"))
}

#[allow(dead_code)]
fn add_auth_cookie(jar: CookieJar, _user: &UserDTO) -> Result<CookieJar, Box<dyn Error>> {
    // TODO: You have to create a new signed JWT and store it in the auth cookie.
    //       Careful with the cookie options.
    let token = auth::sign(_user.clone())?;
    Ok(jar.add(Cookie::build("auth", token).secure(true).finish()))
}

enum AuthResult {
    Success,
    AuthFailed,
    UnverifiedAccount,
    AccountAlreadyExists,
    PasswordMismatch,
    PasswordIdentical,
    WrongPassword,
}

/// Returns a status code and a JSON payload based on the value of the enum
impl IntoResponse for AuthResult {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            Self::Success => (StatusCode::OK, "Success"),
            Self::AuthFailed => (StatusCode::UNAUTHORIZED, "Authentication failed"),
            Self::UnverifiedAccount => (StatusCode::UNAUTHORIZED, "Email is not verified"),
            Self::AccountAlreadyExists => (
                StatusCode::CONFLICT,
                "An account with this email already exists",
            ),
            Self::PasswordMismatch => (StatusCode::BAD_REQUEST, "Both passwords must be the same"),
            Self::PasswordIdentical => (StatusCode::BAD_REQUEST, "Passwords must be different"),
            Self::WrongPassword => (StatusCode::BAD_REQUEST, "Wrong password"),
        };
        (status, Json(json!({ "res": message }))).into_response()
    }
}
