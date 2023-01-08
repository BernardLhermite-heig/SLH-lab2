use crate::schema::*;
use crate::user::User;
use axum::async_trait;
use axum::extract::{FromRef, FromRequestParts};
use axum::http::request::Parts;
use diesel::prelude::*;
use diesel::r2d2::{ConnectionManager, PooledConnection};
use std::error::Error;

type Conn = ConnectionManager<PgConnection>;
pub type Pool = diesel::r2d2::Pool<Conn>;
pub struct DbConn(PooledConnection<Conn>);

/// Retrieves a DbConn from request parts. This allows to directly retrieve a DbConn instance
/// inside of an axum endpoint.
#[async_trait]
impl<S> FromRequestParts<S> for DbConn
where
    Pool: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = ();

    async fn from_request_parts(_parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let pool = Pool::from_ref(state);
        pool.get().map(DbConn).or(Err(()))
    }
}

/// Get the user with the corresponding email from the DB.
pub fn get_user(conn: &mut DbConn, email: &str) -> Result<User, Box<dyn Error>> {
    users::table
        .filter(users::email.eq(email.to_string()))
        .first(&mut conn.0).map_err(|e| e.into())
}

/// Save a user inside the DB
pub fn save_user(conn: &mut DbConn, user: User) -> Result<(), Box<dyn Error>> {
    diesel::insert_into(users::table)
        .values(user)
        .execute(&mut conn.0)
        .and(Ok(())).map_err(|e| e.into())
}

/// Update the password of a user in the DB
pub fn update_password(
    conn: &mut DbConn,
    email: &str,
    password: &str,
) -> Result<(), Box<dyn Error>> {
    diesel::update(users::table.filter(users::email.eq(email.to_string())))
        .set(users::password.eq(password.to_string()))
        .execute(&mut conn.0)
        .and(Ok(())).map_err(|e| e.into())
}

/// Checks whether a user with that email exists in the DB. Returns Ok(()) if the user exists.
pub fn user_exists(conn: &mut DbConn, email: &str) -> Result<(), Box<dyn Error>> {
    get_user(conn, email).and(Ok(()))
}

/// Sets the email_verified field of a user to true.
pub fn set_user_verified(conn: &mut DbConn, email: &str) -> Result<(), Box<dyn Error>> {
    diesel::update(users::table.filter(users::email.eq(email.to_string())))
        .set(users::email_verified.eq(true))
        .execute(&mut conn.0)
        .and(Ok(()))
        .map_err(|e| e.into())
}
