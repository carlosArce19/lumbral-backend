--liquibase formatted sql

--changeset app:auth-003
--comment: Create tenant_memberships table — user-to-tenant role bindings (Tenant & User Model Spec §3.3)
CREATE TABLE tenant_memberships (
    id          UUID        NOT NULL DEFAULT gen_random_uuid(),
    tenant_id   UUID        NOT NULL,
    user_id     UUID        NOT NULL,
    role        TEXT        NOT NULL
                            CHECK (role IN ('ADMIN', 'STAFF', 'EDITOR')),
    status      TEXT        NOT NULL DEFAULT 'INVITED'
                            CHECK (status IN ('INVITED', 'ACTIVE', 'DISABLED')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT pk_tenant_memberships PRIMARY KEY (id),
    CONSTRAINT uq_tenant_memberships_tenant_user UNIQUE (tenant_id, user_id),
    CONSTRAINT fk_tenant_memberships_tenant FOREIGN KEY (tenant_id)
        REFERENCES tenants (id) ON DELETE CASCADE,
    CONSTRAINT fk_tenant_memberships_user FOREIGN KEY (user_id)
        REFERENCES users (id) ON DELETE CASCADE
);

CREATE INDEX idx_tenant_memberships_tenant_id ON tenant_memberships (tenant_id);
CREATE INDEX idx_tenant_memberships_user_id ON tenant_memberships (user_id);
