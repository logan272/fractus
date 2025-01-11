CREATE TABLE
    SHARE (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
        keeper_id UUID NOT NULL REFERENCES "user" (id),
        secret_id UUID NOT NULL REFERENCES secret (id) ON DELETE CASCADE,
        share_data TEXT,
        secret_nonce BIGINT NOT NULL,
        created_at timestamptz NOT NULL DEFAULT NOW(),
        updated_at timestamptz NOT NULL DEFAULT NOW()
    );

CREATE INDEX ON SHARE (keeper_id, secret_id);