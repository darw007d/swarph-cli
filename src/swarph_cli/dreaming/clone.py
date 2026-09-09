"""Clone the memory corpus. R1: the pass writes here, never to the live store."""
from __future__ import annotations
import hashlib, json, shutil, time
from pathlib import Path

def in_scheduled_slice(name: str) -> bool:
    """The daily-timer input: live memories, not backups or the flattened dump.

    A hand-picked file list is refused by the caller; this is the RULE that
    selects the slice (#656 / #124).
    """
    n = name.lower()
    if n.endswith(".bak") or ".bak-" in n or n.endswith(".bak.md"):
        return False
    if n == "memory_full.md":
        return False
    return n.endswith(".md")


def clone_corpus(mem: Path, out: Path, slice: str = "all") -> dict:
    if out.exists() and any(out.iterdir()):
        # A dirty destination silently mixes two runs' proposals. GC2's hashes
        # would then stamp this run's manifest onto last run's files.
        raise FileExistsError(f"{out} is not empty -- refusing to mix runs")
    out.mkdir(parents=True, exist_ok=True)
    files = {}
    for p in sorted(mem.glob("*.md")):
        if slice == "scheduled" and not in_scheduled_slice(p.name):
            continue
        data = p.read_bytes()
        shutil.copy2(p, out / p.name)
        st = p.stat()
        files[p.name] = {"sha256": hashlib.sha256(data).hexdigest(),
                         "size": st.st_size, "mtime": st.st_mtime}
    manifest = {"cloned_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "source": str(mem), "files": files}
    (out / "clone-manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest
