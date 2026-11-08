"""Command line for icstriage.

    python -m icstriage logic-diff --baseline good.L5X --current suspect.L5X \
        [--format md|json] [--out report.md] [--max-size-mb 200]

Inputs are Rockwell L5X or L5K, PLCopen TC6 XML or Siemens SimaticML files, or
a directory of SimaticML files (TIA Portal Openness writes one file per block).
The format is detected from the content, not the extension.

Exit codes: 0 no counted differences, 10 differences found, 1 error (refused
or unreadable input, unsupported or mismatched formats, bad arguments).
"""
from __future__ import annotations

import argparse
import os
import sys

from . import __version__

EXIT_NONE, EXIT_DIFF, EXIT_ERROR = 0, 10, 1


class _Parser(argparse.ArgumentParser):
    def error(self, message):  # argparse exits 2 by default; this tool promises 1 for every error
        self.print_usage(sys.stderr)
        print(f"{self.prog}: error: {message}", file=sys.stderr)
        raise SystemExit(EXIT_ERROR)


def _parser() -> argparse.ArgumentParser:
    p = _Parser(prog="icstriage", description="Offline ICS/OT triage helpers. Never connects to a controller.")
    p.add_argument("--version", action="version", version=f"icstriage {__version__}")
    sub = p.add_subparsers(dest="command", required=True, parser_class=_Parser)
    d = sub.add_parser("logic-diff", help="compare two exported controller projects (L5X, L5K, PLCopen TC6 XML or SimaticML)",
                       description="Compare a known-good export with an export under review. Verdicts: "
                                   "DIFFERENCES-FOUND or NO-DIFFERENCES-FOUND (with stated limits).")
    d.add_argument("--baseline", required=True,
                   help="known-good export: L5X, L5K, PLCopen TC6 XML or SimaticML file, or a directory of SimaticML files")
    d.add_argument("--current", required=True, help="export under review, same format as the baseline")
    d.add_argument("--format", choices=("md", "json"), default="md", help="report format (default md)")
    d.add_argument("--out", help="write the report here instead of standard output")
    d.add_argument("--max-size-mb", type=int, default=200, help="refuse inputs larger than this (default 200)")
    return p


def _logic_diff(args) -> int:
    from .logic import (FormatMismatch, InputFormatError, UnsafeInputError, build_report, compare, load_model,
                        to_json, to_markdown)
    if args.max_size_mb <= 0:
        print("icstriage: error: --max-size-mb must be positive", file=sys.stderr)
        return EXIT_ERROR
    if args.out:
        out_real = os.path.realpath(args.out)
        if out_real in (os.path.realpath(args.baseline), os.path.realpath(args.current)):
            print("icstriage: error: --out would overwrite an input file", file=sys.stderr)
            return EXIT_ERROR
        for src in (args.baseline, args.current):
            if os.path.isdir(src) and os.path.commonpath([out_real, os.path.realpath(src)]) == os.path.realpath(src):
                print("icstriage: error: --out must not be inside an input directory", file=sys.stderr)
                return EXIT_ERROR
    try:
        limit = args.max_size_mb * 1024 * 1024
        base = load_model(args.baseline, max_bytes=limit)
        cur = load_model(args.current, max_bytes=limit)
        result = compare(base, cur)
    except UnsafeInputError as exc:
        print(f"icstriage: refused: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except (InputFormatError, FormatMismatch) as exc:
        print(f"icstriage: error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    report = build_report(base, cur, result)
    text = to_json(report) if args.format == "json" else to_markdown(report)
    if args.out:
        try:
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write(text)
        except OSError as exc:
            print(f"icstriage: error: cannot write {args.out}: {exc.strerror}", file=sys.stderr)
            return EXIT_ERROR
        counted = sum(report["summary"]["counted"].values())
        print(f"{report['verdict']}: {counted} counted, {report['summary']['total']} total; report written to {args.out}")
    else:
        sys.stdout.write(text)
    return EXIT_DIFF if report["verdict"] == "DIFFERENCES-FOUND" else EXIT_NONE


def main(argv=None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "logic-diff":
        return _logic_diff(args)
    return EXIT_ERROR
