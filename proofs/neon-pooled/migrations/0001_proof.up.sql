CREATE SCHEMA %s;
CREATE TABLE %s."migration_probe" (
    "id" bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    "proof_value" text NOT NULL,
    "created_at" timestamp with time zone NOT NULL DEFAULT now()
);
