from __future__ import annotations

import io
import unittest

from security_worker import __main__ as health


class SecurityWorkerHealthTests(unittest.TestCase):
    def test_exact_health_output(self) -> None:
        output = io.StringIO()

        self.assertEqual(health.run(["health"], output), 0)
        self.assertEqual(output.getvalue(), "security-worker health ok\n")

    def test_invalid_arguments_fail_without_output(self) -> None:
        for arguments in ([], ["ready"], ["health", "extra"]):
            with self.subTest(arguments=arguments):
                output = io.StringIO()

                self.assertEqual(health.run(arguments, output), 2)
                self.assertEqual(output.getvalue(), "")

    def test_writer_failure_is_contained_by_main(self) -> None:
        output = FailingWriter()

        with self.assertRaisesRegex(OSError, "write failed"):
            health.run(["health"], output)
        self.assertEqual(health.main(["health"], output), 1)


class FailingWriter:
    def write(self, _: str) -> int:
        raise OSError("write failed")


if __name__ == "__main__":
    unittest.main()
