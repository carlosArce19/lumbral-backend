--liquibase formatted sql

--changeset app:observability-001
--comment: Create audit_logs table — sensitive action audit trail (Observability Basics §3)
CREATE TABLE audit_logs (
    id              UUID        NOT NULL DEFAULT gen_random_uuid(),
    tenant_id       UUID,
    user_id         UUID,
    action          TEXT        NOT NULL,
    resource_type   TEXT        NOT NULL,
    resource_id     UUID        NOT NULL,
    detail          JSONB       NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT pk_audit_logs PRIMARY KEY (id),
    CONSTRAINT fk_audit_logs_tenant FOREIGN KEY (tenant_id)
        REFERENCES tenants (id) ON DELETE SET NULL,
    CONSTRAINT fk_audit_logs_user FOREIGN KEY (user_id)
        REFERENCES users (id) ON DELETE SET NULL
);

CREATE INDEX idx_audit_logs_tenant_created ON audit_logs (tenant_id, created_at);
CREATE INDEX idx_audit_logs_user_id ON audit_logs (user_id);
CREATE INDEX idx_audit_logs_action ON audit_logs (action);
CREATE INDEX idx_audit_logs_resource ON audit_logs (resource_type, resource_id);
