use std::collections::HashSet;

use axum::{routing::get, Extension, Json, Router};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use uuid::Uuid;
use validator::Validate;

use crate::http::user::UserAuth;
use crate::http::Result;

mod share;

pub fn router() -> Router {
    Router::new()
        .route("/v1/secret", get(get_secrets).post(create_secret))
        .merge(share::router())
}

#[derive(Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
struct CreateSecretRequest {
    auth: UserAuth,
    #[validate(length(min = 3, max = 50))]
    label: String,
    #[validate(length(min = 3, max = 64))]
    secret: Option<String>,
    #[validate(range(min = 3, max = 10))]
    n: i32,
    #[validate(range(min = 2, max = 10))]
    k: i32,
    #[validate(length(min = 2, max = 10))]
    keepers: Vec<String>,
}

#[serde_with::serde_as]
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Secret {
    id: Uuid,
    label: String,
    email: String,
    n: i32,
    k: i32,
    // `OffsetDateTime`'s default serialization format is not standard.
    #[serde_as(as = "Rfc3339")]
    created_at: OffsetDateTime,
}

#[derive(Serialize)]
struct CreateSecretResponse {
    secret: Secret,
    shares: Vec<share::Share>,
}

// #[axum::debug_handler] // very useful!
async fn create_secret(
    db: Extension<PgPool>,
    Json(req): Json<CreateSecretRequest>,
) -> Result<Json<CreateSecretResponse>> {
    req.validate()?;
    let user_id = req.auth.verify(&*db).await?;
    let nonce = req.secret.map_or(0, |_| 1);
    let keepers_len = req.keepers.len();
    let keepers = req.keepers.into_iter().collect::<HashSet<_>>();

    if keepers.len() != keepers_len {
        return Err(crate::http::Error::Anyhow(anyhow::anyhow!(
            "duplicate keepers in request"
        )));
    }

    if keepers.len() != req.n as usize {
        return Err(crate::http::Error::Anyhow(anyhow::anyhow!(
            "n must equal the number of keepers",
        )));
    }

    let keeper_ids: Vec<_> = sqlx::query_scalar!(
        r#"
            SELECT id FROM "user" WHERE email = ANY($1)
        "#,
        // a bug of the parameter typechecking code requires all array parameters to be slices
        &keepers.into_iter().collect::<Vec<_>>()[..]
    )
    .fetch_all(&*db)
    .await?;

    if keeper_ids.len() != keepers_len {
        return Err(crate::http::Error::Anyhow(anyhow::anyhow!(
            "some keepers do not exist"
        )));
    }

    let mut tx = db.begin().await?;

    let secret = sqlx::query_as!(
        Secret,
        r#"
            WITH inserted_secret AS (
                INSERT INTO secret(creator_id, label, n, k, nonce)
                VALUES ($1, $2, $3, $4, $5)
                RETURNING id, creator_id, label, n, k, created_at
            )
            SELECT u.email, s.id, s.label, s.n, s.k, s.created_at
            FROM inserted_secret s
            JOIN "user" u ON s.creator_id = u.id
        "#,
        user_id,
        req.label,
        req.n,
        req.k,
        nonce
    )
    .fetch_one(&mut *tx)
    .await?;

    let shares = share::create_shares(&mut tx, secret.id, &keeper_ids, nonce).await?;

    tx.commit().await?;

    Ok(Json(CreateSecretResponse { secret, shares }))
}

async fn get_secrets(db: Extension<PgPool>) -> Result<Json<Vec<Secret>>> {
    let posts = sqlx::query_as!(
        Secret,
        r#"
            SELECT s.id, u.email, s.label, s.created_at, s.n, s.k
            FROM secret s
            JOIN "user" u ON s.creator_id = u.id
            ORDER BY created_at DESC
        "#
    )
    .fetch_all(&*db)
    .await?;

    Ok(Json(posts))
}
