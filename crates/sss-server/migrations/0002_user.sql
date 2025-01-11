CREATE TABLE
    "user" (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
        email VARCHAR(100) UNIQUE NOT NULL,
        password_hash VARCHAR(255),
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

CREATE INDEX ON "user" (email);