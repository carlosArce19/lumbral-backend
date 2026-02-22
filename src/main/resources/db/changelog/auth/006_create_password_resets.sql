--liquibase formatted sql

--changeset app:auth-006
--comment: Create password_resets table — reset-by-link flow (Tenant & User Model Spec §9)
CREATE TABLE password_resets (
    id          UUID        NOT NULL DEFAULT gen_random_uuid(),
    user_id     UUID        NOT NULL,
    token_hash  TEXT        NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    used_at     TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT pk_password_resets PRIMARY KEY (id),
    CONSTRAINT uq_password_resets_token_hash UNIQUE (token_hash),
    CONSTRAINT fk_password_resets_user FOREIGN KEY (user_id)
        REFERENCES users (id) ON DELETE CASCADE
);

CREATE INDEX idx_password_resets_user_id ON password_resets (user_id);
