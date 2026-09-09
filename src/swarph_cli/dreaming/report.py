"""R6. What was examined, what changed, and the resulting index size."""
from __future__ import annotations
import collections


def render(verdicts, organized, proposals, corpus, clone, enrich_note: str | None = None) -> str:
    counts = collections.Counter(v["verdict"] for v in verdicts)
    # GC4g: coverage FIRST, because a finding count without a denominator
    # cannot tell "checked and fine" from "could not check", and the second
    # gets quieter exactly as coverage degrades.
    probed = sum(1 for v in verdicts if v["verdict"] in ("agree", "disagree", "mention",
                                                        "surface_disagreement"))
    by_kind = collections.Counter(v["kind"] for v in verdicts)
    probed_by_kind = collections.Counter(
        v["kind"] for v in verdicts
        if v["verdict"] in ("agree", "disagree", "mention", "surface_disagreement"))
    reasons = collections.Counter(v.get("reason") for v in verdicts
                                 if v["verdict"] == "unprobeable")
    # >>> NO SINGLE NUMBER MAY SUMMARISE THE RUN. <<< One fraction cannot carry
    # two questions, and a report that CAN print one figure a reader could quote
    # as "the pass was N% good" WILL be quoted that way -- on the run where
    # everything disagreed. Three numbers, each labelled with the question it
    # answers, and no ratios of ratios.
    adjudicated = sum(1 for v in verdicts if v["verdict"] in ("agree", "disagree", "mention"))
    infra = sum(1 for v in verdicts if v["verdict"] == "surface_disagreement")
    mentions = [v for v in verdicts if v["verdict"] == "mention"]
    L = ["# dreaming report", "",
         "DID WE LOOK?      probed %d of %d extracted claims (%.0f%%)" % (
             probed, len(verdicts), 100 * probed / max(len(verdicts), 1)),
         "DID WE CONCLUDE?  adjudicated %d of %d probed (%d of them mentions: absence "
         "observed, nothing accused) — surface_disagreement and unprobeable are NOT "
         "conclusions" % (adjudicated, probed, len(mentions)),
         "INFRA FINDINGS    %d surface_disagreement — a PRODUCT of the run, not a gap "
         "in it" % infra,
         # GC4h: a mentions-only run and an agree-only run must not print the
         # same headline. Without this line they did (both rc 0, both
         # "adjudicated 1 of 1").
         "MENTIONS          %d absent artifacts the memory NAMES without claiming — "
         "listed below, never findings" % len(mentions),
         "  by kind: " + ", ".join("%s %d/%d" % (k, probed_by_kind.get(k, 0), by_kind[k])
                                   for k in sorted(by_kind)),
         "  refusals: " + (", ".join("%s %d" % (r, c) for r, c in reasons.most_common())
                           or "none"),
         "",
         "examined: %d claims across %d memory files (corpus %s)" % (
             len(verdicts), len({v["file"] for v in verdicts}), corpus),
         "clone: %s -- the live corpus was not written to" % clone, "",
         "| verdict | n |", "|---|---|"]
    for k in ("disagree", "surface_disagreement", "mention", "unprobeable", "agree"):
        L.append("| %s | %d |" % (k, counts.get(k, 0)))
    verified = [v for v in verdicts if v["verdict"] == "agree"]
    flagged = [v for v in verdicts if v["verdict"] in ("disagree", "surface_disagreement")]
    L += ["", "BRANCHES  verified=%d (agree)  flagged=%d (disagree+surface_disagreement)"
          % (len(verified), len(flagged))]
    if verified:
        v = verified[0]
        L.append("  verified  %s:%d [%s] %s" % (
            v["file"], v["line"], v["kind"], v.get("ref") or v.get("asserted") or ""))
    if flagged:
        v = flagged[0]
        L.append("  flagged   %s:%d [%s] %s — %s says %s" % (
            v["file"], v["line"], v["kind"], v.get("asserted") or v.get("ref") or "",
            v.get("surface") or "?", v.get("observed") or ""))
    if not verified or not flagged:
        L.append("  BOTH-BRANCHES: MISSING — a single-branch run is #689's defect")
    L += ["", "MEMORY.md: %d bytes before, %d bytes after (budget 24985)" % (
        organized["index_bytes_before"], organized["index_bytes_after"])]
    if organized["trimmed"]:
        L.append("trimmed %d index line(s) to stay under budget" % len(organized["trimmed"]))
    L += ["", "enrichment proposals (all marked derived, none applied): %d" % len(proposals)]
    if enrich_note:
        L.append(enrich_note)
    L += [""]
    for v in verdicts:
        if v["verdict"] in ("disagree", "surface_disagreement"):
            L.append("- **%s** %s:%d [%s] asserted `%s` -- %s says `%s`" % (
                v["verdict"], v["file"], v["line"], v["kind"],
                v["asserted"] or "(present)", v["surface"], v["observed"]))
    if counts.get("disagree", 0) == 0 and counts.get("surface_disagreement", 0) == 0:
        L.append("_no disagreements among the %d claims ADJUDICATED. This is NOT a clean bill "
                 "of health: %d extracted claims were never probed, and a run can probe "
                 "everything while concluding nothing._"
                 % (adjudicated, len(verdicts) - probed))
    if mentions:
        # A mention is LISTED, not concluded: the memory named the artifact and
        # the extractor carried no value for it, so its absence is something to
        # read, never a correction to apply. Kept out of the findings list
        # above, below the trailer, and out of the exit code (run.py).
        L += ["", "mentions of ABSENT artifacts: %d -- the memory names it without a value "
              "(path, listen_addr and http_endpoint carry none), so the extractor cannot "
              "tell a claim from a mention; absence is listed, never concluded. Read, do "
              "not correct" % len(mentions)]
        for v in mentions:
            L.append("- mention %s:%d [%s] `%s` -- %s says `%s`" % (
                v["file"], v["line"], v["kind"], v["ref"], v["surface"], v["observed"]))
    return "\n".join(L) + "\n"
