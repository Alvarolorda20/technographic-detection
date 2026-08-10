"""Command-line interface.

Exit codes: 0 = run completed (per-domain failures are expected operation,
not process failure), 1 = fatal setup error, 2 = usage error (argparse).
All logs go to stderr; only JSON is ever written to stdout.
"""

from __future__ import annotations

import argparse
import asyncio
import dataclasses
import json
import logging
import math
import sys
import time
from pathlib import Path

from techdetect import __version__
from techdetect.engine import (
    DEFAULT_CONFIDENCE,
    DEFAULT_FINGERPRINTS_PATH,
    FingerprintError,
    load_fingerprints,
)
from techdetect.scanner import DEFAULT_CONCURRENCY, read_domains, scan_all

logger = logging.getLogger("techdetect")


def positive_int(value: str) -> int:
    """argparse type: an integer strictly greater than zero."""
    try:
        parsed = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{value!r} is not an integer") from None
    if parsed < 1:
        raise argparse.ArgumentTypeError(f"must be greater than 0, got {parsed}")
    return parsed


def positive_float(value: str) -> float:
    """argparse type: a finite float strictly greater than zero.

    ``float()`` happily parses ``nan``, ``inf`` and overflowing literals such
    as ``1e309``; none of those are usable timeouts, so finiteness is checked
    explicitly.
    """
    try:
        parsed = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{value!r} is not a number") from None
    if not math.isfinite(parsed):
        raise argparse.ArgumentTypeError(f"must be a finite number, got {value!r}")
    if parsed <= 0:
        raise argparse.ArgumentTypeError(f"must be greater than 0, got {parsed}")
    return parsed


def confidence_int(value: str) -> int:
    """argparse type: an integer percentage from 0 to 100 inclusive."""
    try:
        parsed = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{value!r} is not an integer") from None
    if not 0 <= parsed <= 100:
        raise argparse.ArgumentTypeError(f"must be between 0 and 100, got {parsed}")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="techdetect",
        description="Detect the technologies a domain uses from public HTTP and DNS signals.",
    )
    parser.add_argument(
        "domains_file",
        help="plain-text file with one domain per line ('-' reads from stdin)",
    )
    parser.add_argument("-o", "--output", help="write results JSON to this file (default: stdout)")
    parser.add_argument(
        "--fingerprints",
        help="Wappalyzer-format fingerprint JSON (default: bundled fingerprints.json, "
        "validated strictly; external files may skip unsupported patterns with warnings)",
    )
    parser.add_argument(
        "--evidence",
        help="also write per-domain match evidence (sanitized) to this JSON file",
    )
    parser.add_argument(
        "--min-confidence",
        type=confidence_int,
        default=DEFAULT_CONFIDENCE,
        metavar="0-100",
        help="confidence total a technology must reach to be reported (default: %(default)s)",
    )
    parser.add_argument(
        "--concurrency",
        type=positive_int,
        default=DEFAULT_CONCURRENCY,
        help="concurrent domain scans (default: %(default)s)",
    )
    parser.add_argument(
        "--timeout",
        type=positive_float,
        default=8.0,
        help="per-request timeout in seconds (default: %(default)s)",
    )
    verbosity = parser.add_mutually_exclusive_group()
    verbosity.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    verbosity.add_argument("-q", "--quiet", action="store_true", help="errors only")
    parser.add_argument("--version", action="version", version=f"techdetect {__version__}")
    return parser


def _read_domain_lines(source: str) -> list[str]:
    if source == "-":
        return sys.stdin.read().splitlines()
    return Path(source).read_text(encoding="utf-8").splitlines()


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    level = logging.DEBUG if args.verbose else logging.ERROR if args.quiet else logging.INFO
    logging.basicConfig(stream=sys.stderr, level=level, format="%(levelname)s %(message)s")
    if not args.verbose:  # per-request noise only at -v
        logging.getLogger("httpx").setLevel(logging.WARNING)
        logging.getLogger("httpcore").setLevel(logging.WARNING)

    fingerprints_path = args.fingerprints or DEFAULT_FINGERPRINTS_PATH
    try:
        fingerprints = load_fingerprints(fingerprints_path, strict=args.fingerprints is None)
    except FingerprintError as exc:
        logger.error("%s", exc)
        return 1
    if fingerprints.skipped:
        logger.warning("%s", fingerprints.skipped_summary())
    logger.info(
        "loaded %d patterns for %d technologies from %s",
        fingerprints.pattern_count,
        fingerprints.technology_count,
        fingerprints_path,
    )

    try:
        domains = read_domains(_read_domain_lines(args.domains_file))
    except OSError as exc:
        logger.error("cannot read domains from %s: %s", args.domains_file, exc)
        return 1
    if not domains:
        logger.error("no domains found in %s", args.domains_file)
        return 1

    started = time.perf_counter()
    reports = asyncio.run(
        scan_all(
            domains,
            fingerprints,
            concurrency=args.concurrency,
            timeout=args.timeout,
            min_confidence=args.min_confidence,
        )
    )
    elapsed = time.perf_counter() - started

    results = {report.domain: report.technologies for report in reports}
    rendered = json.dumps(results, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        Path(args.output).write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)

    if args.evidence:
        evidence = {
            report.domain: [dataclasses.asdict(record) for record in report.evidence]
            for report in reports
        }
        Path(args.evidence).write_text(
            json.dumps(evidence, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )

    ok = sum(1 for r in reports if r.status and r.status < 400 and not r.blocked)
    blocked = sum(1 for r in reports if r.blocked)
    failed = sum(1 for r in reports if not r.status)
    logger.info(
        "Scanned %d domain(s) in %.1fs (%d ok, %d blocked, %d no response)",
        len(reports),
        elapsed,
        ok,
        blocked,
        failed,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
