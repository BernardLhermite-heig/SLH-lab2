use lettre::message::header;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use log::{error, info};
use std::error::Error;

#[derive(Clone)]
pub struct SmtpConfig {
    pub url: String,
    credentials: Credentials,
    pub from: String,
}

impl SmtpConfig {
    pub fn new(url: &str, username: &str, password: &str, from: &str) -> Self {
        Self {
            url: url.to_string(),
            credentials: Credentials::new(username.to_string(), password.to_string()),
            from: from.to_string(),
        }
    }
}

/// Sends an email to the given address
pub fn send_email(
    config: &SmtpConfig,
    to: &str,
    subject: &str,
    body: &str,
) -> Result<(), Box<dyn Error>> {
    let email = Message::builder()
        .from(format!("<{}>", config.from).parse().unwrap())
        .to(format!("<{}>", to).parse().unwrap())
        .subject(subject)
        .header(header::ContentType::TEXT_HTML)
        .body(body.to_string())
        .unwrap();

    // Open a remote connection to gmail
    let mailer = SmtpTransport::relay(&config.url)
        .unwrap()
        .credentials(config.credentials.clone())
        .build();

    match mailer.send(&email) {
        Ok(_) => {
            info!("Email sent to {}", to);
            Ok(())
        }
        Err(e) => {
            error!("Could not send email: {}", e);
            Err(Box::new(e))
        }
    }
}
