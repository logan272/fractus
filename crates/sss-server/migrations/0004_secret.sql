CREATE TABLE
    secret (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
        creator_id UUID NOT NULL REFERENCES "user" (id),
        LABEL VARCHAR(255) UNIQUE NOT NULL,
        n INT NOT NULL,
        k INT NOT NULL,
        nonce BIGINT NOT NULL DEFAULT 0,
        created_at timestamptz NOT NULL DEFAULT NOW(),
        updated_at timestamptz NOT NULL DEFAULT NOW()
    );

CREATE INDEX ON secret (creator_id);