--liquibase formatted sql

--changeset app:observability-002
--comment: Create event_consumptions table — idempotency dedup (Internal Event Model §4.3)
CREATE TABLE event_consumptions (
    id              UUID        NOT NULL DEFAULT gen_random_uuid(),
    consumer_name   TEXT        NOT NULL,
    event_id        UUID        NOT NULL,
    processed_at    TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT pk_event_consumptions PRIMARY KEY (id),
    CONSTRAINT uq_event_consumptions_consumer_event UNIQUE (consumer_name, event_id)
);
