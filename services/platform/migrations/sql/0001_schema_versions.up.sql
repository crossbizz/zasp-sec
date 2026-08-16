CREATE TABLE "public"."zasp_schema_versions" (
    "version" bigint PRIMARY KEY,
    "name" text NOT NULL UNIQUE CHECK (char_length("name") BETWEEN 1 AND 63),
    "checksum" text NOT NULL CHECK ("checksum" ~ '^[a-f0-9]{64}$'),
    "applied_at" timestamp with time zone NOT NULL DEFAULT transaction_timestamp()
);
