"""Bounded JSON requests to the configured Zasp origin."""
from __future__ import annotations

import http.client
import ipaddress
import json
import math
import re
import ssl
from collections.abc import Callable
from urllib.parse import urlsplit


class DecisionUnavailable(RuntimeError):
    """The service could not provide a decision. The configured fallback applies."""


class ProtocolError(RuntimeError):
    """The server rejected the credential/request or returned an invalid receipt."""


class Transport:
    def __init__(self, base_url: str, token: str | Callable[[], str], timeout: float):
        url = urlsplit(base_url)
        if (
            url.scheme not in ("https", "http") or not url.hostname or url.username is not None
            or url.password is not None or url.path not in ("", "/") or url.query or url.fragment
        ):
            raise ValueError("base_url must be a Zasp HTTPS origin")
        if url.scheme == "http":
            try:
                loopback = ipaddress.ip_address(url.hostname).is_loopback
            except ValueError:
                loopback = False
            if not loopback:
                raise ValueError("HTTP is supported only on a loopback IP address")
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("timeout must be a positive finite number")
        self._scheme = url.scheme
        self._host = url.hostname
        self._port = url.port
        self._token = token
        self._timeout = timeout

    def post(self, path: str, payload: dict, key: str) -> dict:
        try:
            token = self._token() if callable(self._token) else self._token
        except Exception:
            raise ProtocolError("Unable to retrieve workload credential") from None
        if not isinstance(token, str) or not re.fullmatch(r"[!-~]{1,8192}", token):
            raise ProtocolError("Invalid workload credential")
        connection_type = http.client.HTTPSConnection if self._scheme == "https" else http.client.HTTPConnection
        connection = connection_type(self._host, self._port, timeout=self._timeout)
        try:
            connection.request("POST", path, json.dumps(payload, separators=(",", ":")), {
                "Content-Type": "application/json", "Accept": "application/json",
                "Authorization": f"Bearer {token}", "Idempotency-Key": key,
            })
            response = connection.getresponse()
            if response.status in (408, 429) or 500 <= response.status < 600:
                raise DecisionUnavailable(f"Zasp runtime unavailable (HTTP {response.status})")
            if not 200 <= response.status < 300:
                raise ProtocolError(f"Zasp runtime rejected request (HTTP {response.status})")
            data = response.read(16385)
            if len(data) > 16384:
                raise ProtocolError("Decision receipt exceeds size limit")
            if response.headers.get_content_type() != "application/json":
                raise ProtocolError("Expected a JSON decision receipt")
            result = json.loads(data)
            if not isinstance(result, dict):
                raise ProtocolError("Invalid decision receipt")
            return result
        except ssl.SSLError:
            raise ProtocolError("Unable to authenticate TLS transport") from None
        except (UnicodeError, ValueError, RecursionError):
            raise ProtocolError("Invalid JSON decision receipt") from None
        except (OSError, http.client.HTTPException):
            raise DecisionUnavailable("Zasp runtime connection unavailable") from None
        finally:
            connection.close()
