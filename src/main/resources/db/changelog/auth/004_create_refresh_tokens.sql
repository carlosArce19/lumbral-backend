--liquibase formatted sql

--changeset app:auth-004
--comment: Create refresh_tokens table — session tracking and rotation (Tenant & User Model Spec §5.1)
CREATE TABLE refresh_tokens (
    id               UUID        NOT NULL DEFAULT gen_random_uuid(),
    user_id          UUID        NOT NULL,
    tenant_id        UUID        NOT NULL,
    token_hash       TEXT        NOT NULL,
    expires_at       TIMESTAMPTZ NOT NULL,
    revoked_at       TIMESTAMPTZ,
    rotated_from_id  UUID,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT pk_refresh_tokens PRIMARY KEY (id),
    CONSTRAINT uq_refresh_tokens_token_hash UNIQUE (token_hash),
    CONSTRAINT fk_refresh_tokens_user FOREIGN KEY (user_id)
        REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT fk_refresh_tokens_tenant FOREIGN KEY (tenant_id)
        REFERENCES tenants (id) ON DELETE CASCADE,
    CONSTRAINT fk_refresh_tokens_rotated_from FOREIGN KEY (rotated_from_id)
        REFERENCES refresh_tokens (id) ON DELETE SET NULL
);

CREATE INDEX idx_refresh_tokens_user_tenant ON refresh_tokens (user_id, tenant_id);
CREATE INDEX idx_refresh_tokens_tenant_id ON refresh_tokens (tenant_id);
CREATE INDEX idx_refresh_tokens_expires_at ON refresh_tokens (expires_at);
