use crate::db::Pool;
use crate::mailer::SmtpConfig;
use crate::models::AppState;
use axum::Router;
use axum_sessions::async_session::MemoryStore;
use diesel::r2d2::ConnectionManager;
use diesel::PgConnection;
use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
use dotenv::dotenv;
use handlebars::Handlebars;
use std::env;
use std::net::SocketAddr;

mod auth;
mod db;
mod mailer;
mod models;
mod oauth;
mod schema;
mod user;
mod web_auth;
mod web_pages;

use env_logger::Env;

/// Executes the SQL instructions in the migrations folder. This creates the users table.
fn run_migrations(pool: Pool) {
    const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");
    pool.get()
        .unwrap()
        .run_pending_migrations(MIGRATIONS)
        .expect("Failed to init database");
}

#[tokio::main]
async fn main() {
    // Read variables in .env file
    dotenv().ok();

    let env = Env::default()
        .filter_or("MY_LOG_LEVEL", "info")
        .write_style_or("MY_LOG_STYLE", "always");

    env_logger::init_from_env(env);

    let smtp_config = SmtpConfig::new(
        &env::var("SMPT_URL").expect("Could not get SMPT_URL from ENV"),
        &env::var("SMTP_USERNAME").expect("Could not get SMTP_USERNAME from ENV"),
        &env::var("SMTP_PASS").expect("Could not get SMTP_PASS from ENV"),
        &env::var("SMTP_FROM").expect("Could not get SMTP_FROM from ENV"),
    );

    // Reads the postgres url from an the POSTGRES_URL env variable
    let url = env::var("POSTGRES_URL").expect("Could not get POSTGRES_URL from ENV");
    let manager = ConnectionManager::<PgConnection>::new(url);
    println!("Setting up DB pool...");
    let pool = Pool::builder()
        .build(manager)
        .expect("Could not create DB pool");

    // Init database
    println!("Executing DB migrations");
    run_migrations(pool.clone());
    println!("DB migrations successful");

    // Register the handlebars templates
    let mut hbs = Handlebars::new();
    hbs.register_templates_directory(".hbs", "templates/")
        .expect("Could not register template directory");

    // Initialize the app state with the DB connector, the memory store and handlebars
    let app_state = AppState {
        pool,
        session_store: MemoryStore::new(),
        hbs,
        smtp_config,
    };

    // Setup the endpoints
    let router = Router::new()
        .merge(web_pages::stage(app_state.clone()))
        .merge(web_auth::stage(app_state.clone()));

    let addr = SocketAddr::from(([127, 0, 0, 1], 8000));
    println!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(router.into_make_service())
        .await
        .unwrap();
}
