from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

from harness.providers.health_cli import check_provider_health
from harness.providers.config import load_provider_configs


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vulstrip",
        description="VulStrip CLI",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=False,
    )

    # providers subcommand
    _add_providers_subcommand(subparsers)

    return parser


def _add_providers_subcommand(subparsers: argparse._SubParsersAction) -> None:
    providers_parser = subparsers.add_parser(
        "providers",
        help="Manage and diagnose AI providers.",
    )

    providers_sub = providers_parser.add_subparsers(
        dest="providers_command",
        required=False,
    )

    # providers check
    check_parser = providers_sub.add_parser(
        "check",
        help="Check connectivity and capabilities for configured providers.",
    )

    check_parser.add_argument(
        "--provider",
        dest="provider_name",
        help="Check only this provider (e.g., 'ollama'). If omitted, checks all enabled providers.",
    )

    check_parser.set_defaults(command="providers_check")


def _cmd_providers_check(args: argparse.Namespace) -> int:
    # Use current working directory as repo root
    root = Path.cwd()
    providers_path = root / "providers.yaml"

    providers = load_provider_configs(providers_path)

    all_results = []

    for provider in providers:
        if not getattr(provider, "enabled", True):
            continue

        result = check_provider_health(provider)
        all_results.append(result)

    # Print results in a simple table-like format
    all_ok = True

    for res in all_results:
        # available is the health flag
        is_healthy = getattr(res, "available", False)
        if not is_healthy:
            all_ok = False

        status = "OK" if is_healthy else "FAIL"
        provider_id = getattr(res, "provider_id", "unknown")
        provider_type = getattr(res, "provider_type", "unknown")
        message = getattr(res, "message", "")

        print(f"[{status}] {provider_id} ({provider_type})")
        if message:
            print(f"  {message}")

    return 0 if all_ok else 1


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "providers_check":
        return _cmd_providers_check(args)

    # If no known command is specified, print help
    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())