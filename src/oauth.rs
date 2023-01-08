use lazy_static::lazy_static;
use oauth2::basic::{BasicClient, BasicTokenResponse};
use oauth2::{AuthUrl, ClientId, ClientSecret, RedirectUrl, TokenResponse, TokenUrl};
use once_cell::sync::Lazy;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use std::env;

lazy_static! {
    static ref OAUTH_ID: String = env::var("OAUTH_ID").expect("OAUTH_ID must be set");
    static ref OAUTH_SECRET: String = env::var("OAUTH_SECRET").expect("OAUTH_SECRET must be set");
}

/// Lazy is used to initialize a complex static variable as it is currently not supported in native Rust.
/// The initialization is done only once when the variable is used for the first time.  
pub static OAUTH_CLIENT: Lazy<BasicClient> = Lazy::new(|| {
    // TODO: We currently hardcode the credentials, try to improve it.
    let google_client_id = ClientId::new(OAUTH_ID.to_string());
    let google_client_secret = ClientSecret::new(OAUTH_SECRET.to_string());

    let auth_url = AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string())
        .expect("Invalid authorization endpoint URL");
    let token_url = TokenUrl::new("https://www.googleapis.com/oauth2/v3/token".to_string())
        .expect("Invalid token endpoint URL");

    // TODO: Set redirect URI, be careful to use the same as the one configured in Google Cloud.
    BasicClient::new(
        google_client_id,
        Some(google_client_secret),
        auth_url,
        Some(token_url),
    )
    .set_redirect_uri(
        RedirectUrl::new("http://localhost:8000/_oauth".to_string()).expect("Invalid redirect URL"),
    )
});

static REQW_CLIENT: Lazy<reqwest::Client> = Lazy::new(reqwest::Client::new);

/// Structure returned by Google API when requesting the email address
#[derive(Serialize, Deserialize, Debug)]
struct UserInfoEmail {
    id: String,
    email: String,
    verified_email: bool,
    picture: String,
}

/// Returns the email address associated with the token
pub async fn get_google_oauth_email(token: &BasicTokenResponse) -> Result<String, StatusCode> {
    REQW_CLIENT
        .get("https://www.googleapis.com/oauth2/v1/userinfo")
        .query(&[("access_token", token.access_token().secret())])
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .send()
        .await.map(|r| r.json::<UserInfoEmail>()).map_err(|_| StatusCode::UNAUTHORIZED)?
        .await.map(|user_info| user_info.email).map_err(|_| StatusCode::UNAUTHORIZED)
}
