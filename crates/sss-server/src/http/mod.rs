use anyhow::Context;
use axum::{Extension, Router};
use sqlx::PgPool;
use std::env;
use tokio::net::TcpListener;
use tower_http::cors;

mod error;
mod secret;
mod user;

pub use self::error::Error;

pub type Result<T, E = Error> = ::std::result::Result<T, E>;

fn app(db: PgPool) -> Router {
    Router::new()
        .merge(user::router())
        .merge(secret::router())
        .layer(cors::CorsLayer::new().allow_origin(cors::Any))
        .layer(Extension(db))
}

pub async fn serve(db: PgPool) -> anyhow::Result<()> {
    let host = env::var("HOST").unwrap_or("127.0.0.1".to_owned());
    let port = env::var("PORT").map_or(3000, |p| p.parse().expect("PORT must be a number"));
    let server_url = format!("{}:{}", host, port);
    let listener = TcpListener::bind(&server_url).await.unwrap();

    println!("Listening on: http://{}", server_url);
    axum::serve(listener, app(db).into_make_service())
        .await
        .context("Failed to serve API")
}
