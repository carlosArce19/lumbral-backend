--liquibase formatted sql

--changeset app:auth-001
--comment: Create users table — global identities (Tenant & User Model Spec §3.1)
CREATE TABLE users (
    id          UUID        NOT NULL DEFAULT gen_random_uuid(),
    email       TEXT        NOT NULL,
    password_hash TEXT      NOT NULL,
    status      TEXT        NOT NULL DEFAULT 'ACTIVE'
                            CHECK (status IN ('ACTIVE', 'DISABLED')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT pk_users PRIMARY KEY (id),
    CONSTRAINT uq_users_email UNIQUE (email)
);

CREATE UNIQUE INDEX idx_users_email_lower ON users (LOWER(email));
