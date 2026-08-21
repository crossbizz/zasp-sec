from __future__ import annotations

import sys
from io import BytesIO
from collections.abc import Sequence
from typing import BinaryIO, TextIO

from . import cartography_aws, protocol, prowler_aws


_FAILURE_STATUS = {
    "retryable": 10,
    "rate_limited": 11,
    "denied": 12,
    "malformed": 13,
}


def run(arguments: Sequence[str], output: TextIO) -> int:
    if list(arguments) != ["health"]:
        return 2
    output.write("security-worker health ok\n")
    return 0


def run_binary(
    arguments: Sequence[str], input_stream: BinaryIO, output: BinaryIO
) -> int:
    selected = list(arguments)
    if selected == [protocol.MODE_CARTOGRAPHY]:
        request = protocol.read_request(input_stream, protocol.MODE_CARTOGRAPHY)
        authority = request["authority"]
        result = cartography_aws.transform(
            {
                "authority": {
                    "phase": authority["phase"],
                    "remaining_bytes": authority["remaining_bytes"],
                    "remaining_entities": authority["remaining_entities"],
                    "remaining_relationships": authority["remaining_relationships"],
                    "source_digest": authority["source_digest"],
                    "subject_id": authority["subject_id"],
                },
                "source": request["source"],
            }
        )
    elif selected == [protocol.MODE_PROWLER]:
        request = protocol.read_request(input_stream, protocol.MODE_PROWLER)
        authority = request["authority"]
        result = prowler_aws.scan(
            {
                "authority": {
                    "credential_expires_at": authority["credential_expires_at"],
                    "phase": authority["phase"],
                    "remaining_bytes": authority["remaining_bytes"],
                    "remaining_entities": authority["remaining_entities"],
                    "remaining_relationships": authority["remaining_relationships"],
                    "source_digest": authority["source_digest"],
                    "subject_id": authority["subject_id"],
                },
                "credential": request["credential"],
                "source": request["source"],
            }
        )
        request["credential"] = ""
    else:
        return 2
    staged = BytesIO()
    protocol.write_response(
        staged,
        {
            "authority": authority,
            "protocol_version": 1,
            "result": result,
            "source_digest": authority["source_digest"],
        },
    )
    payload = staged.getvalue()
    if output.write(payload) != len(payload):
        raise OSError("write failed")
    return 0


def main(
    arguments: Sequence[str] | None = None,
    output: TextIO | None = None,
    input_stream: BinaryIO | None = None,
    binary_output: BinaryIO | None = None,
) -> int:
    selected_arguments = sys.argv[1:] if arguments is None else arguments
    try:
        if list(selected_arguments) == ["health"]:
            return run(selected_arguments, sys.stdout if output is None else output)
        return run_binary(
            selected_arguments,
            sys.stdin.buffer if input_stream is None else input_stream,
            sys.stdout.buffer if binary_output is None else binary_output,
        )
    except protocol.ProtocolError:
        return _FAILURE_STATUS["malformed"]
    except (cartography_aws.CollectionError, prowler_aws.CollectionError) as exc:
        return _FAILURE_STATUS.get(exc.code, _FAILURE_STATUS["malformed"])
    except Exception:
        return 1


def cli() -> None:
    raise SystemExit(main())


if __name__ == "__main__":
    cli()
