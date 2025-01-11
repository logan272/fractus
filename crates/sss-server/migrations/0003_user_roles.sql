CREATE TABLE
    user_roles (
        user_id UUID,
        role_id BIGINT,
        PRIMARY KEY (user_id, role_id),
        CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES "user" (id) ON DELETE CASCADE,
        CONSTRAINT fk_role FOREIGN KEY (role_id) REFERENCES "role" (id) ON DELETE CASCADE
    );

CREATE INDEX ON user_roles (user_id, role_id);