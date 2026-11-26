import unittest

from verify_locations import summarize


class VerifyLocationsTest(unittest.TestCase):
    def test_reports_tracked_locations_from_vitest_and_github_without_payloads(self):
        paths = {"app/view.test.tsx", "apps/cli.spec.ts"}
        lines = [
            "\x1b[31m FAIL \x1b[0m app/view.test.tsx > private description",
            " ❯ app/view.test.tsx:35:9 user data",
            "::error file=apps/cli.spec.ts,line=9,col=1::exception with secret values",
            "    at verifyReleaseSources (file:///home/runner/repo/deploy/production/release-gates.mjs:82:5)",
        ]
        self.assertEqual(summarize(lines, paths), "app/view.test.tsx:35, apps/cli.spec.ts:9, release-gates:82")

    def test_ignores_passed_and_untracked_tests(self):
        self.assertEqual(summarize([" ✓ app/view.test.tsx", "FAIL private/untracked.test.ts"], {"app/view.test.tsx"}), "")
