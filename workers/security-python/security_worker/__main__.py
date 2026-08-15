from __future__ import annotations

import sys
from collections.abc import Sequence
from typing import TextIO


def run(arguments: Sequence[str], output: TextIO) -> int:
    if list(arguments) != ["health"]:
        return 2
    output.write("security-worker health ok\n")
    return 0


def main(arguments: Sequence[str] | None = None, output: TextIO | None = None) -> int:
    selected_arguments = sys.argv[1:] if arguments is None else arguments
    selected_output = sys.stdout if output is None else output
    try:
        return run(selected_arguments, selected_output)
    except Exception:
        return 1


def cli() -> None:
    raise SystemExit(main())


if __name__ == "__main__":
    cli()
