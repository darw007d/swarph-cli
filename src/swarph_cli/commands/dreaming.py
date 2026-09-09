"""``swarph dreaming`` — between-sessions memory verify / organize / enrich (#684 / #656).

Distribution surface for the dreaming pass that lives as plain modules under
``swarph_cli.dreaming``. This verb does NOT schedule anything and does NOT
write the live corpus: it clones, reports, and exits with the GC4i contract.

Exit codes (unchanged from #656 — do not collapse to 0/1):
  0  adjudicated >0 claims AND no disagreements
  1  disagreements / surface_disagreements found
  2  refused to run (e.g. dirty destination)
  3  ran but adjudicated nothing

Scope: SINGLE-CELL. Runs against THIS cell's own corpus. It is not the
cross-agent multi-transcript dreaming from the Anthropic talk; transcripts
are not a shared mesh surface in v1.
"""

from __future__ import annotations

import argparse
import sys


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="swarph dreaming",
        description=(
            "Periodic memory dreaming pass: VERIFY, ORGANIZE, ENRICH against a "
            "CLONE of your corpus. Never writes the live store. Never scheduled "
            "by install — an option you run deliberately.\n\n"
            "SINGLE-CELL SCOPE: operates on one cell's own memory + local "
            "transcripts. Not cross-agent dreaming.\n\n"
            "Exit codes:\n"
            "  0  adjudicated >0 claims AND no disagreements\n"
            "  1  findings (disagree / surface_disagreement)\n"
            "  2  refused to run\n"
            "  3  ran but adjudicated nothing\n\n"
            "Enrich: when the SLM client (workers.slm_client) is absent — the\n"
            "normal installed-wheel case — enrich is skipped and the report\n"
            "says 'enrich skipped: no SLM client' (never exit 1 as findings).\n"
            "Pass --enrich to require it (rc=2 if unavailable)."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = p.add_subparsers(dest="action", required=True)

    run = sub.add_parser(
        "run",
        help="clone corpus to --out, verify/organize/enrich, print report",
        description=(
            "Clone --corpus into --out, then VERIFY / ORGANIZE / ENRICH the "
            "clone. The live corpus is left byte-identical. Propagate the exit "
            "code if you schedule this — do not wrap with `exit 0`."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    run.add_argument("--corpus", required=True, help="path to the live memory corpus directory")
    run.add_argument("--out", required=True, help="empty destination for the clone + report")
    run.add_argument(
        "--cursor",
        default=None,
        help="transcript cursor JSON (default: ~/.dreaming-cursor.json)",
    )
    run.add_argument("--no-enrich", action="store_true", help="skip transcript enrich stage")
    run.add_argument(
        "--enrich", action="store_true",
        help="require enrich; refuse (rc=2) if SLM client unavailable (#734)",
    )
    run.add_argument("--verify-only", action="store_true", help="verify only; skip organize/enrich")
    run.add_argument(
        "--slice", choices=("all", "scheduled"), default="all",
        help="scheduled = rule-selected live memories (no backups / MEMORY_FULL). "
             "That is the timer input — not a hand-picked file list (card #656).",
    )
    return p


def run_dreaming(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    # Allow `swarph dreaming --help` without a subcommand.
    if not argv or argv[0] in ("-h", "--help"):
        _build_parser().print_help()
        return 0
    args = _build_parser().parse_args(argv)
    if args.action != "run":
        _build_parser().print_help()
        return 2

    from pathlib import Path
    from swarph_cli.dreaming import run as dreaming_run

    forwarded = ["--corpus", args.corpus, "--out", args.out]
    if args.cursor:
        forwarded.extend(["--cursor", args.cursor])
    else:
        forwarded.extend(["--cursor", str(Path.home() / ".dreaming-cursor.json")])
    if args.no_enrich:
        forwarded.append("--no-enrich")
    if getattr(args, "enrich", False):
        forwarded.append("--enrich")
    if args.verify_only:
        forwarded.append("--verify-only")
    if getattr(args, "slice", "all") != "all":
        forwarded.extend(["--slice", args.slice])
    return dreaming_run.main(forwarded)
