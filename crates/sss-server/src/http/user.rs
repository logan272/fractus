use axum::{http::StatusCode, routing::post, Extension, Json, Router};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::Deserialize;
use sqlx::{PgExecutor, PgPool};
use uuid::Uuid;
use validator::Validate;

use crate::http::{Error, Result};

pub type UserId = Uuid;

pub fn router() -> Router {
    Router::new().route("/v1/user", post(create_user))
}

/// 8-32 characters, any of A-Z, a-z, 0-9, and @$!%*#?&.
static RE_PASSWORD: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[A-Za-z\d@$!%*#?&]{8,32}$").unwrap());

#[derive(Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
pub struct UserAuth {
    #[validate(email)]
    email: String,
    #[validate(regex(path = *RE_PASSWORD))]
    password: String,
}

async fn create_user(db: Extension<PgPool>, Json(req): Json<UserAuth>) -> Result<StatusCode> {
    req.validate()?;

    let UserAuth { email, password } = req;

    // It would be irresponsible to store passwords in plaintext, however.
    let password_hash = crate::password::hash(password).await?;

    sqlx::query!(
        r#"
            INSERT INTO "user"(email, password_hash)
            VALUES ($1, $2)
        "#,
        email,
        password_hash
    )
    .execute(&*db)
    .await
    .map_err(|e| match e {
        sqlx::Error::Database(dbe) if dbe.constraint() == Some("user_email_key") => {
            Error::Conflict("email taken".into())
        }
        _ => e.into(),
    })?;

    Ok(StatusCode::NO_CONTENT)
}

impl UserAuth {
    // NOTE: normally we wouldn't want to verify the username and password every time,
    // but persistent sessions would have complicated the example.
    pub async fn verify(self, db: impl PgExecutor<'_> + Send) -> Result<UserId> {
        self.validate()?;

        let maybe_user = sqlx::query!(
            r#"SELECT id, password_hash from "user" WHERE email = $1"#,
            self.email
        )
        .fetch_optional(db)
        .await?;

        if let Some(user) = maybe_user {
            if let Some(password_hash) = user.password_hash {
                let verified = crate::password::verify(self.password, password_hash).await?;

                if verified {
                    return Ok(user.id);
                }
            }
        }

        Err(Error::UnprocessableEntity("invalid email/password".into()))
    }
}
