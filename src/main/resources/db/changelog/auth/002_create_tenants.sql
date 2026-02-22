--liquibase formatted sql

--changeset app:auth-002
--comment: Create tenants table — business accounts (Tenant & User Model Spec §3.2)
CREATE TABLE tenants (
    id          UUID        NOT NULL DEFAULT gen_random_uuid(),
    name        TEXT        NOT NULL,
    code        TEXT        NOT NULL,
    plan        TEXT        NOT NULL DEFAULT 'BASIC'
                            CHECK (plan IN ('BASIC', 'MID', 'PRO')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT pk_tenants PRIMARY KEY (id),
    CONSTRAINT uq_tenants_code UNIQUE (code)
);
