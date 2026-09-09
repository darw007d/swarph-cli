"""Entry point. Emits a diff and a report; applies NOTHING (GC1)."""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path
from swarph_cli.dreaming.clone import clone_corpus
from swarph_cli.dreaming.verify import verify
from swarph_cli.dreaming.organize import organize
from swarph_cli.dreaming.report import render


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", required=True); ap.add_argument("--out", required=True)
    ap.add_argument("--cursor", default=str(Path.home() / ".dreaming-cursor.json"))
    ap.add_argument("--no-enrich", action="store_true")
    ap.add_argument(
        "--enrich", action="store_true",
        help="require enrich; refuse (rc=2) if SLM client is unavailable (#734)",
    )
    ap.add_argument("--verify-only", action="store_true")
    ap.add_argument(
        "--slice", choices=("all", "scheduled"), default="all",
        help="all=every *.md (compat). scheduled=the timer input: live "
             "memories only, no .bak* / MEMORY_FULL.md (card #656).",
    )
    a = ap.parse_args(argv)
    if a.enrich and a.no_enrich:
        print("dreaming: refusing to run -- --enrich and --no-enrich conflict",
              file=sys.stderr)
        return 2
    corpus, out = Path(a.corpus), Path(a.out)
    try:
        manifest = clone_corpus(corpus, out, slice=a.slice)
    except FileExistsError as e:
        print("dreaming: refusing to run -- %s" % e, file=sys.stderr)
        return 2
    verdicts = verify(out, manifest)
    organized = {"index_bytes_before": 0, "index_bytes_after": 0, "trimmed": [], "findings": []}
    proposals = []
    enrich_note = None
    if not a.verify_only:
        organized = organize(out)
        from swarph_cli.dreaming.enrich import (
            ENRICH_SKIPPED_NO_SLM, enrich, slm_client_available,
        )
        available = slm_client_available()
        # Default: enrich when SLM present; skip (do not crash) when absent (#734).
        # Explicit --enrich with no client → refuse rc=2 (not findings rc=1).
        # Explicit --no-enrich → skip always.
        if a.no_enrich:
            do_enrich = False
        elif a.enrich:
            if not available:
                print("dreaming: refusing to run -- %s (explicit --enrich)" %
                      ENRICH_SKIPPED_NO_SLM, file=sys.stderr)
                return 2
            do_enrich = True
        elif not available:
            do_enrich = False
            enrich_note = ENRICH_SKIPPED_NO_SLM
        else:
            do_enrich = True
        if do_enrich:
            from swarph_cli.dreaming.transcripts import read_new
            records, cursor = read_new(Path(a.corpus).parent, Path(a.cursor))
            proposals = enrich(out, records)
            Path(a.cursor).write_text(json.dumps(cursor))   # only after success
    (out / "findings.json").write_text(json.dumps(verdicts, indent=2, default=str), encoding="utf-8")
    (out / "proposals.json").write_text(json.dumps(proposals, indent=2), encoding="utf-8")
    text = render(verdicts, organized, proposals, corpus, out, enrich_note=enrich_note)
    (out / "dreaming-report.md").write_text(text, encoding="utf-8")
    print(text)
    # >>> THE EXIT CODE CARRIES THE SAME THREE-WAY DISTINCTION AS THE REPORT, OR
    # IT LIES TO WHATEVER SCHEDULES THIS. <<< An earlier draft was
    # `return 1 if bad else 0`, which exits 0 for a run that ADJUDICATED NOTHING —
    # coverage zero, every claim unprobeable, no findings because nothing was
    # checked. That is indistinguishable from a clean corpus in the one signal a
    # cron/systemd caller reads.
    #
    # LIVED SPECIMEN, 2026-09-04: the EOD-highlights runner captured `RC=$?` from a
    # crashed spawn, wrote "done rc=1" into its own log, and then `exit 0`. The
    # dispatcher recorded "fired OK (rc=0)", `last_status=fired_exec`,
    # `fire_count=73`, watermark advancing nightly — 14 nights dead, every layer
    # green, and the only true line sat in a 147 KB log nobody reads. Dreaming is
    # the same shape of job: scheduled, unattended, reporting to a machine.
    #
    #   0  adjudicated >0 claims AND no disagreements   — a real clean run
    #   1  disagreements or surface_disagreements found — findings to read
    #   2  refused to run (dirty destination)
    #   3  RAN BUT ADJUDICATED NOTHING                  — not clean, not findings
    # `mention` is adjudicated (the artifact WAS compared to the world) but never
    # `bad`: the memory asserted nothing, so there is no finding to read.
    adjudicated = sum(1 for v in verdicts if v["verdict"] in ("agree", "disagree", "mention"))
    bad = [v for v in verdicts if v["verdict"] in ("disagree", "surface_disagreement")]
    if bad:
        return 1
    if adjudicated == 0:
        print("dreaming: RAN BUT ADJUDICATED NOTHING — %d claims extracted, 0 concluded. "
              "This is NOT a clean corpus; see the coverage block above." % len(verdicts),
              file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
