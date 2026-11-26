import ssl
import unittest
from unittest import mock
from urllib.error import HTTPError, URLError

from restore_drill import Client, NoRedirect


def http_error(code):
    return HTTPError("https://loopback.invalid", code, "fixture response", {}, None)


class RestoreReadinessTest(unittest.TestCase):
    active = {"initialized": True, "sealed": False, "standby": False}
    leader = {"ha_enabled": True, "is_self": True}

    def setUp(self):
        self.client = Client.__new__(Client)
        self.client.request = mock.Mock()

    @mock.patch("restore_drill.time.sleep")
    def test_unseal_once_and_wait_for_local_leadership_and_token(self, sleep):
        self.client.request.side_effect = [
            {"sealed": False},  # Final unseal share has been accepted.
            http_error(429),
            {**self.active, "standby": True},
            self.active, {"ha_enabled": True},
            self.active, self.leader, http_error(503),
            self.active, self.leader, {"data": {"policies": ["root"]}},
        ]
        self.client.unseal("disposable share", "restored credential")
        self.assertEqual(self.client.request.call_args_list, [
            mock.call("sys/unseal", {"key": "disposable share"}, method="PUT"),
            mock.call("sys/health", timeout=3), mock.call("sys/health", timeout=3),
            mock.call("sys/health", timeout=3), mock.call("sys/leader", timeout=3),
            mock.call("sys/health", timeout=3), mock.call("sys/leader", timeout=3),
            mock.call("auth/token/lookup-self", token="restored credential", timeout=3),
            mock.call("sys/health", timeout=3), mock.call("sys/leader", timeout=3),
            mock.call("auth/token/lookup-self", token="restored credential", timeout=3),
        ])
        self.assertEqual(sleep.call_count, 4)

    @mock.patch("restore_drill.time.sleep")
    def test_invalid_credential_and_tls_fail_immediately(self, sleep):
        for responses, error_type in [
            ([self.active, self.leader, http_error(403)], HTTPError),
            ([self.active, self.leader, {"data": {"policies": ["default"]}}], AssertionError),
            ([URLError(ssl.SSLCertVerificationError("untrusted fixture"))], URLError),
        ]:
            with self.subTest(error_type=error_type):
                self.client.request.side_effect = responses
                with self.assertRaises(error_type):
                    self.client.wait_for_active("restored credential")
        sleep.assert_not_called()

    @mock.patch("restore_drill.time.monotonic", side_effect=[0, 0, 61])
    @mock.patch("restore_drill.time.sleep")
    def test_standby_deadline_names_waited_state(self, sleep, monotonic):
        self.client.request.side_effect = http_error(307)
        with self.assertRaisesRegex(RuntimeError, "authenticated local Raft leadership"):
            self.client.wait_for_active("restored credential")
        self.client.request.assert_called_once_with("sys/health", timeout=3)
        sleep.assert_called_once()

    def test_redirect_does_not_send_authority_to_another_server(self):
        self.assertIsNone(NoRedirect().redirect_request(None, None, 307, "", {}, "https://other.invalid"))


if __name__ == "__main__":
    unittest.main()
