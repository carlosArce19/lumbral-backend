--liquibase formatted sql

--changeset app:auth-005
--comment: Create invites table — invite-by-link flow (Tenant & User Model Spec §8.1)
CREATE TABLE invites (
    id                  UUID        NOT NULL DEFAULT gen_random_uuid(),
    tenant_id           UUID        NOT NULL,
    email               TEXT        NOT NULL,
    role                TEXT        NOT NULL
                                    CHECK (role IN ('STAFF', 'EDITOR')),
    token_hash          TEXT        NOT NULL,
    expires_at          TIMESTAMPTZ NOT NULL,
    accepted_at         TIMESTAMPTZ,
    created_by_user_id  UUID,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT pk_invites PRIMARY KEY (id),
    CONSTRAINT uq_invites_token_hash UNIQUE (token_hash),
    CONSTRAINT fk_invites_tenant FOREIGN KEY (tenant_id)
        REFERENCES tenants (id) ON DELETE CASCADE,
    CONSTRAINT fk_invites_created_by FOREIGN KEY (created_by_user_id)
        REFERENCES users (id) ON DELETE SET NULL
);

CREATE INDEX idx_invites_tenant_id ON invites (tenant_id);
CREATE INDEX idx_invites_email ON invites (email);
CREATE INDEX idx_invites_created_by_user_id ON invites (created_by_user_id);
