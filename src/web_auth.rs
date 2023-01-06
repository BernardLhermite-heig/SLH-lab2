use crate::{
    auth,
    db::{self, DbConn},
    mailer::{self, SmtpConfig},
    models::{AppState, LoginRequest, OAuthRedirect, PasswordUpdateRequest, RegisterRequest},
    oauth,
    user::{AuthenticationMethod, User, UserDTO},
};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use axum_extra::extract::cookie::Cookie;
use axum_extra::extract::CookieJar;
use axum_sessions::{
    async_session::MemoryStore,
    async_session::{Session, SessionStore},
};
use lazy_static::lazy_static;
use oauth2::{reqwest::async_http_client, AuthorizationCode, CsrfToken, PkceCodeChallenge, Scope};
use serde_json::json;
use std::{collections::HashMap, env, error::Error};

lazy_static! {
    pub static ref COOKIE_AUTH: String = "auth".to_string();
    static ref COOKIE_SESSION: String = "session".to_string();
    static ref CSRF_KEY: String = "csrf_token".to_string();
    static ref PKCE_KEY: String = "pkce_verifier".to_string();
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

    let user_dto = match db::get_user(&mut _conn, _email.as_str()) {
        Ok(user) => {
            let parsed_hash = PasswordHash::new(&user.password).unwrap();
            if argon2
                .verify_password(_password.as_bytes(), &parsed_hash)
                .is_ok()
            {
                if !matches!(user.get_auth_method(), AuthenticationMethod::Password) {
                    log::info!(
                        "Failed to login user: {}, wrong authentication method",
                        _email
                    );
                    return Ok((jar, AuthResult::AuthFailed));
                }

                if !user.email_verified {
                    log::info!("Failed to login user: {}, email not verified", _email);
                    return Ok((jar, AuthResult::UnverifiedAccount));
                }

                user.to_dto()
            } else {
                log::info!("Failed to login user: {}, wrong password", _email);
                return Ok((jar, AuthResult::AuthFailed));
            }
        }
        Err(_) => {
            let parsed_hash = argon2
                .hash_password(DEFAULT_PASSWORD.as_bytes(), &default_salt)
                .unwrap();
            _ = argon2.verify_password(_password.as_bytes(), &parsed_hash);
            log::info!("Failed to login user: {}, not found", _email);
            return Ok((jar, AuthResult::AuthFailed));
        }
    };

    log::info!("User logged in: {}", _email);

    // Once the user has been created, authenticate the user by adding a JWT cookie in the cookie jar
    // let jar = add_auth_cookie(jar, &user_dto)
    //     .or(Err(StatusCode::INTERNAL_SERVER_ERROR.into_response()))?;

    let jar = add_auth_cookie(jar, &user_dto)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())?;

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
        log::info!(
            "Failed to register user: {}, passwords don't match",
            register.register_email
        );
        return Ok(AuthResult::PasswordMismatch);
    }

    let email = register.register_email.to_lowercase();
    let password = register.register_password;
    let argon2 = Argon2::default();
    let salt = SaltString::generate(&mut OsRng);

    let user = match db::user_exists(&mut conn, email.as_str()) {
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

            if let Err(e) = db::save_user(&mut conn, new_user) {
                log::error!("Failed to save user: {}", e);
                return Err(StatusCode::INTERNAL_SERVER_ERROR.into_response());
            }

            user
        }
        Ok(_) => {
            _ = argon2.hash_password(DEFAULT_PASSWORD.as_bytes(), &salt);
            log::info!("Failed to register user: {}, already exists", email);
            return Ok(AuthResult::AccountAlreadyExists);
        }
    };

    log::info!("User registered: {}", email);

    let token = auth::sign(user).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())?;

    mailer::send_email(
        &smtp_config,
        email.as_str(),
        "Account verification",
        &format!(
            "Please verify your account by clicking on the following <a href=\"{}/verify?token={}\">link</a>",
            *APP_URL, token
        ),
    ).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())?;

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
            log::info!("Failed to verify email: no token provided");
            return Err(StatusCode::BAD_REQUEST);
        }
    };
    let claims = match auth::verify(token) {
        Ok(claims) => claims,
        Err(_) => {
            log::info!("Failed to verify email: invalid token");
            return Err(StatusCode::BAD_REQUEST);
        }
    };

    db::set_user_verified(&mut conn, &claims.sub)
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

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    let (auth_url, csrf_token) = oauth::OAUTH_CLIENT
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new(
            "https://www.googleapis.com/auth/userinfo.email".to_string(),
        ))
        .set_pkce_challenge(pkce_challenge)
        .url();

    let mut session = Session::new();
    session
        .insert(CSRF_KEY.as_str(), csrf_token.secret().to_string())
        .or(Err(StatusCode::INTERNAL_SERVER_ERROR))?;
    session
        .insert(PKCE_KEY.as_str(), pkce_verifier)
        .or(Err(StatusCode::INTERNAL_SERVER_ERROR))?;
    let session_id = _session_store
        .store_session(session)
        .await
        .map_err(|_| {
            log::error!("Failed to store session");
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .unwrap();

    let jar = jar.add(
        Cookie::build(COOKIE_SESSION.as_str(), session_id)
            .path("/")
            .max_age(time::Duration::days(1))
            .finish(),
    );

    // If you need to store data between requests, you may use the session_store. You need to first
    // create a new Session and store the variables. Then, you add the session to the session_store
    // to get a session_id. You then store the session_id in a cookie.
    Ok((jar, Redirect::to(auth_url.as_str())))
}

/// Endpoint called after a successful OAuth login.
/// GET /_oauth?state=x&code=y
async fn oauth_redirect(
    jar: CookieJar,
    State(_session_store): State<MemoryStore>,
    mut _conn: DbConn,
    _params: Query<OAuthRedirect>,
) -> Result<(CookieJar, Redirect), StatusCode> {
    // TODO: The user should be redirected to this page automatically after a successful login.
    //       You will need to verify the CSRF token and ensure the authorization code is valid
    //       by interacting with Google's OAuth2 API (use an async request!). Once everything
    //       was verified, get the email address with the provided function (get_oauth_email)
    //       and create a JWT for the user.

    // If you need to recover data between requests, you may use the session_store to load a session
    // based on a session_id.
    let session_id = jar
        .get(COOKIE_SESSION.as_str())
        .ok_or(StatusCode::BAD_REQUEST)?
        .value()
        .to_string();
    log::info!("Session id: {}", session_id);
    let session = _session_store
        .load_session(session_id)
        .await
        .map_err(|_| {
            log::error!("Failed to load session");
            StatusCode::UNAUTHORIZED
        })?
        .unwrap();

    let csrf_token: String = session
        .get(CSRF_KEY.as_str())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    if !csrf_token.eq(&_params.state) {
        log::error!("Invalid CSRF token");
        return Err(StatusCode::UNAUTHORIZED);
    }

    let pkce_verifier = session
        .get(PKCE_KEY.as_str())
        .ok_or(StatusCode::BAD_REQUEST)?;

    let token = oauth::OAUTH_CLIENT
        .exchange_code(AuthorizationCode::new(_params.code.clone()))
        // Set the PKCE code verifier.
        .set_pkce_verifier(pkce_verifier)
        .request_async(async_http_client)
        .await
        .map_err(|_| {
            log::error!("Failed to get token");
            StatusCode::UNAUTHORIZED
        })?;

    let email = oauth::get_google_oauth_email(&token).await?;

    // Once the OAuth user is authenticated, create the user in the DB and add a JWT cookie
    // let jar = add_auth_cookie(jar, &user_dto).or(Err(StatusCode::INTERNAL_SERVER_ERROR))?;
    let user_dto = match db::get_user(&mut _conn, email.as_str()) {
        Ok(user) => user.to_dto(),
        Err(_) => {
            let user = User::new(email.as_str(), "oauth", AuthenticationMethod::OAuth, true);
            let user_dto = user.to_dto();

            if let Err(e) = db::save_user(&mut _conn, user) {
                log::error!("Failed to save user: {}", e);
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }

            user_dto
        }
    };

    let jar = add_auth_cookie(jar, &user_dto)
        .or(Err(StatusCode::INTERNAL_SERVER_ERROR))?
        .remove(Cookie::build("name", "").path("/").finish());

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

    match db::get_user(&mut _conn, &_user.email) {
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
            log::error!("Failed to get user for password update: {}", &_user.email);
            return Err(StatusCode::INTERNAL_SERVER_ERROR.into_response());
        }
    }

    let salt = SaltString::generate(&mut OsRng);
    let password_hash = argon2
        .hash_password(_update.new_password.as_bytes(), &salt)
        .unwrap()
        .to_string();

    match db::update_password(&mut _conn, &_user.email, &password_hash) {
        Ok(_) => mailer::send_email(
            &smtp_config,
            &_user.email,
            "Password updated",
            "Your password was updated successfully.",
        )
        .and(Ok(AuthResult::Success))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response()),
        Err(_) => {
            log::error!("Failed to update password for user: {}", &_user.email);
            Err(StatusCode::INTERNAL_SERVER_ERROR.into_response())
        }
    }
}

/// Endpoint handling the logout logic
/// GET /logout
async fn logout(jar: CookieJar) -> impl IntoResponse {
    let new_jar = jar.remove(Cookie::named(COOKIE_AUTH.as_str()));
    (new_jar, Redirect::to("/home"))
}

#[allow(dead_code)]
fn add_auth_cookie(jar: CookieJar, _user: &UserDTO) -> Result<CookieJar, Box<dyn Error>> {
    // TODO: You have to create a new signed JWT and store it in the auth cookie.
    //       Careful with the cookie options.
    let token = auth::sign(_user.clone())?;
    Ok(jar.add(
        Cookie::build(COOKIE_AUTH.as_str(), token)
            .secure(true)
            .max_age(time::Duration::hours(1))
            .finish(),
    ))
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
