"""#656 — scheduled slice is a RULE, not a hand-picked file list."""
from pathlib import Path

from swarph_cli.dreaming.clone import clone_corpus, in_scheduled_slice
from swarph_cli.dreaming.report import render


def test_scheduled_slice_drops_backups_and_full_dump(tmp_path):
    mem = tmp_path / "mem"
    mem.mkdir()
    (mem / "MEMORY.md").write_text("# i\n- [[fact]]\n")
    (mem / "fact.md").write_text("a path /etc/hosts exists\n")
    (mem / "note.bak.md").write_text("old\n")
    (mem / "MEMORY_FULL.md").write_text("dump\n")
    out = tmp_path / "out"
    man = clone_corpus(mem, out, slice="scheduled")
    names = set(man["files"])
    assert names == {"MEMORY.md", "fact.md"}
    assert not (out / "MEMORY_FULL.md").exists()
    assert "note.bak.md" not in names


def test_all_slice_keeps_full_dump(tmp_path):
    mem = tmp_path / "mem"
    mem.mkdir()
    (mem / "MEMORY.md").write_text("# i\n")
    (mem / "MEMORY_FULL.md").write_text("dump\n")
    man = clone_corpus(mem, tmp_path / "out", slice="all")
    assert "MEMORY_FULL.md" in man["files"]


def test_in_scheduled_slice_is_a_name_rule():
    assert in_scheduled_slice("feedback_x.md") is True
    assert in_scheduled_slice("MEMORY_FULL.md") is False
    assert in_scheduled_slice("MEMORY.md.bak-20260909T1556Z") is False


def test_report_names_both_branches_or_says_missing():
    agree = {"verdict": "agree", "file": "a.md", "line": 1, "kind": "path",
             "ref": "/etc/hosts", "asserted": None, "surface": "fs", "observed": "present"}
    flag = {"verdict": "surface_disagreement", "file": "b.md", "line": 2,
            "kind": "unit_bind", "ref": "u.service", "asserted": "x",
            "surface": "systemd", "observed": "mismatch", "reason": None}
    organized = {"index_bytes_before": 0, "index_bytes_after": 0, "trimmed": [],
                 "findings": []}
    both = render([agree, flag], organized, [], "c", "o")
    assert "BRANCHES  verified=1" in both and "flagged=1" in both
    assert "verified  a.md:1 [path]" in both
    assert "flagged   b.md:2 [unit_bind]" in both
    assert "BOTH-BRANCHES: MISSING" not in both
    one = render([agree], organized, [], "c", "o")
    assert "BOTH-BRANCHES: MISSING" in one
