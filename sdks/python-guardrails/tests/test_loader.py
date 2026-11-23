import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from zasp_guardrails.loader import AdmissionDenied, LocalReviews, Review, Source, load_reviewed


ORIGIN = "private-artifact-store:ticket-helper"
ENV = "staging"
ENTRY = b"# Ticket helper\n"
# The same one-file manifest vector is checked by cmd/zaspctl/internal/addons.
DIGEST = "sha256:e103709f3188881a19797e525c4ca56ca415bb7c99a8a300ead5797f56ce3d11"


class LoaderTest(unittest.TestCase):
    def setUp(self):
        self.bundle = {"SKILL.md": ENTRY}
        self.source = Source(ORIGIN, lambda: self.bundle)
        self.reviews = LocalReviews()
        self.approved = Review(ENV, ORIGIN, DIGEST, 1, "approved", datetime.now(timezone.utc) + timedelta(hours=1))
        self.reviews.install(self.approved)

    def load(self):
        return load_reviewed(self.source, environment=ENV, lookup=self.reviews.lookup)

    def test_dispatch_receives_exact_reviewed_bytes(self):
        def mutate_after_snapshot(env, origin, digest):
            self.bundle["SKILL.md"] = b"New content from an update"
            return self.reviews.lookup(env, origin, digest)

        admitted = load_reviewed(self.source, environment=ENV, lookup=mutate_after_snapshot)
        observed_by_application = []
        observed_by_application.append(admitted.instructions)
        self.assertEqual(observed_by_application, [ENTRY])
        self.assertEqual((admitted.digest, admitted.review_revision), (DIGEST, 1))
        with self.assertRaises(TypeError):
            admitted.files["SKILL.md"] = b"later"
        with self.assertRaisesRegex(AdmissionDenied, "version_unreviewed"):
            self.load()

    def test_revocation_precedes_next_load(self):
        observed = [self.load().instructions]
        revoked = replace(self.approved, revision=2, state="revoked")
        self.reviews.install(revoked)
        self.reviews.install(revoked)  # idempotent same revision
        with self.assertRaisesRegex(ValueError, "stale_review_revision"):
            self.reviews.install(self.approved)
        with self.assertRaisesRegex(AdmissionDenied, "version_revoked"):
            observed.append(self.load().instructions)
        self.assertEqual(observed, [ENTRY])

    def test_require_binding_freshness_and_current_authority(self):
        def unavailable(*args):
            raise ConnectionError("test lookup unavailable")

        for review, reason in (
            (replace(self.approved, environment="other"), "review_binding_mismatch"),
            (replace(self.approved, origin="other"), "review_binding_mismatch"),
            (replace(self.approved, digest="sha256:" + "0" * 64), "review_binding_mismatch"),
            (replace(self.approved, expires_at=datetime.now(timezone.utc) - timedelta(minutes=1)), "review_expired"),
            (None, "version_unreviewed"),
        ):
            with self.subTest(reason=reason), self.assertRaisesRegex(AdmissionDenied, reason):
                load_reviewed(self.source, environment=ENV, lookup=lambda *args: review)
        with self.assertRaisesRegex(AdmissionDenied, "review_unavailable"):
            load_reviewed(self.source, environment=ENV, lookup=unavailable)

    def test_added_resource_changes_version_and_path_collisions_fail(self):
        self.bundle["notes/README.txt"] = b"private supporting resource"
        with self.assertRaisesRegex(AdmissionDenied, "version_unreviewed"):
            self.load()
        self.bundle["Notes/guide.txt"] = b"ambiguous source"
        with self.assertRaisesRegex(AdmissionDenied, "ambiguous_manifest_path"):
            self.load()
        for path in ("../elsewhere", "dir\\entry", "/outside", "line\nbreak"):
            with self.subTest(path=path), self.assertRaisesRegex(AdmissionDenied, "invalid_manifest_path"):
                load_reviewed(Source(ORIGIN, lambda: {"SKILL.md": ENTRY, path: b"unused"}),
                              environment=ENV, lookup=self.reviews.lookup)
