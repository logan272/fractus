use axum::{extract::Path, routing::get, Extension, Json, Router};
use serde::Serialize;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use uuid::Uuid;

use crate::http::Result;

pub fn router() -> Router {
    Router::new().route("/v1/secret/{secret_id}/share", get(get_shares))
}

#[serde_with::serde_as]
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Share {
    pub id: Uuid,
    pub email: String,
    pub secret_label: String,
    // `OffsetDateTime`'s default serialization format is not standard.
    #[serde_as(as = "Rfc3339")]
    pub updated_at: OffsetDateTime,
    #[serde_as(as = "Rfc3339")]
    pub created_at: OffsetDateTime,
}

pub async fn create_shares(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    secret_id: Uuid,
    keepers: Vec<Uuid>,
    shares_data: Option<Vec<String>>,
    nonce: i64,
) -> Result<Vec<Share>> {
    let mut shares = Vec::with_capacity(keepers.len());

    for (idx, keeper) in keepers.iter().enumerate() {
        let share = sqlx::query_as!(
            Share,
            r#"
                WITH inserted_share AS (
                    INSERT INTO share(keeper_id, secret_id, share_data, secret_nonce)
                    VALUES ($1, $2, $3, $4)
                    RETURNING id, keeper_id, secret_id, updated_at, created_at 
                )
                SELECT s.id, u.email, secret.label as secret_label, s.updated_at, s.created_at
                FROM inserted_share s
                JOIN "user" u ON s.keeper_id = u.id
                JOIN secret ON s.secret_id = secret.id
            "#,
            keeper,
            secret_id,
            shares_data.as_ref().map(|data| &data[idx]),
            nonce
        )
        .fetch_one(&mut **tx)
        .await?;
        shares.push(share);
    }

    Ok(shares)
}

/// Returns comments in ascending chronological order.
async fn get_shares(
    db: Extension<sqlx::PgPool>,
    Path(secret_id): Path<Uuid>,
) -> Result<Json<Vec<Share>>> {
    let shares = sqlx::query_as!(
        Share,
        r#"
            SELECT s.id, u.email, secret.label as secret_label, s.updated_at, s.created_at
            FROM share s
            JOIN "user" u ON s.keeper_id = u.id
            JOIN secret ON s.secret_id = secret.id
            WHERE s.secret_id = $1
            ORDER BY s.created_at DESC
        "#,
        secret_id
    )
    .fetch_all(&*db)
    .await?;

    Ok(Json(shares))
}
