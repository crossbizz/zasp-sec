"""Prepare operator inputs for a new OpenFGA database; never contacts a cluster."""
import argparse
import json
import os
from pathlib import Path
import re
import secrets
from urllib.parse import quote


def prepare(directory, image):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]*@sha256:[0-9a-f]{64}", image):
        raise ValueError("supply a PostgreSQL 18 operand image pinned by SHA-256 digest")
    # Each credential stays in a local 0600 file.
    # Reserve the destination exclusively before generation.
    directory.mkdir(mode=0o700)
    created = []
    try:
        password = secrets.token_urlsafe(48)
        hostname = "openfga-db-rw.zasp-data.svc.cluster.local"
        uri = ("postgresql://openfga:" + quote(password, safe="") + "@" + hostname +
               ":5432/openfga?sslmode=verify-full&sslrootcert=/etc/database-ca/ca.crt")
        catalog = {"apiVersion": "postgresql.cnpg.io/v1", "kind": "ImageCatalog",
                   "metadata": {"name": "pilot-database-images", "namespace": "zasp-data"},
                   "spec": {"images": [{"major": 18, "image": image}]}}
        for name, value in (("username", "openfga"), ("password", password), ("uri", uri),
                            ("catalog.json", json.dumps(catalog, indent=2) + "\n")):
            with open(directory / name, "x", opener=lambda path, flags: os.open(path, flags, 0o600)) as output:
                created.append(directory / name)
                output.write(value)
    except BaseException:
        # A partial directory can never be mistaken for a completed generation.
        # No existing directory is touched: mkdir succeeded exclusively above.
        for file in created:
            file.unlink()
        directory.rmdir()
        raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, help="verified CNPG-compatible PostgreSQL 18 operand image digest")
    parser.add_argument("--output", type=Path, required=True, help="new private directory on encrypted storage")
    args = parser.parse_args()
    try:
        prepare(args.output, args.image)
    except (OSError, ValueError) as error:
        parser.exit(1, str(error) + "\n")
