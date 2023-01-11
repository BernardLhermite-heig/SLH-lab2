use lazy_static::lazy_static;
use regex::Regex;
use zxcvbn::zxcvbn;

// Checks that the given email is valid
pub fn email_regex_validator(email: &str) -> bool {
    lazy_static! {
        static ref MAIL_REGEX: Regex = Regex::new(r#"(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])"#).unwrap();
    }
    MAIL_REGEX.is_match(email)
}

/// Checks that the given password is strong enough
pub fn check_password_strength(password: &str) -> bool {
    let estimate = match zxcvbn(password, &[]) {
        Ok(entropy) => entropy,
        Err(_) => return false,
    };

    return password.chars().count() >= 8
        && password.chars().count() <= 64
        && estimate.score() >= 3;
}
