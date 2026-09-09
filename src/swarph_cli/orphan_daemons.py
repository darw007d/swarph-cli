"""Orphan ``claude daemon run --origin transient`` detector (#666).

Enumerate Anthropic's ``claude daemon run`` processes, classify each as
LIVE / ORPHANED / UNKNOWN from ``--spawned-by`` + tmux-scope evidence.

UNKNOWN must never be treated as ORPHANED
([[feedback_absent_feature_looks_like_broken_feature]]). T1 prints only.
T3 ``--reap`` is opt-in, PID-only, and kills only the 09-03 four-clause
matches (transient|fork AND ppid=1 AND not a live pane AND
childless-or-stale). ``--origin transient`` alone is never enough.
Re-verifies identity before each signal. Never ``pkill -f``.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import signal
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Optional

# Exactly three states. Do not invent a fourth that collapses into ORPHANED.
STATE_LIVE = "LIVE"
STATE_ORPHANED = "ORPHANED"
STATE_UNKNOWN = "UNKNOWN"

_SPAWNED_BY_RE = re.compile(
    r"--spawned-by\s+(\{.*?\})(?:\s+--|\s*$)",
    re.DOTALL,
)
_ORIGIN_RE = re.compile(r"--origin\s+(\S+)")
_TMUX_SCOPE_RE = re.compile(r"(tmux-spawn-[^/\s]+\.scope)")


# 09-03 four-clause reap predicate (#123). ALL four must hold to kill.
# An --origin-transient-only match is not enough (that would have killed
# a working daemon on 2026-09-03).
CLAUSE_ORIGIN = "origin_or_fork"
CLAUSE_PPID = "ppid_init"
CLAUSE_PANE = "not_live_pane"
CLAUSE_STALE = "childless_or_stale"
REAP_CLAUSES = (CLAUSE_ORIGIN, CLAUSE_PPID, CLAUSE_PANE, CLAUSE_STALE)

_FORK_RE = re.compile(r"--fork-session\b")
_VER_RE = re.compile(r"\bv?(\d+)\.(\d+)\.(\d+)\b")


@dataclass
class DaemonReport:
    pid: int
    cmdline: str
    state: str
    spawner_pid: Optional[int] = None
    spawner_alive: Optional[bool] = None
    origin: Optional[str] = None
    scope: Optional[str] = None
    scope_live: Optional[bool] = None
    child_count: int = 0
    rss_kb: int = 0
    reason: str = ""
    self_excluded: bool = False
    ppid: Optional[int] = None
    sid: Optional[int] = None
    version: Optional[str] = None
    clauses: dict = field(default_factory=dict)
    spared_by: Optional[str] = None
    reapable: bool = False


@dataclass
class ScanResult:
    daemons: list[DaemonReport] = field(default_factory=list)

    @property
    def orphans(self) -> list[DaemonReport]:
        return [d for d in self.daemons if d.state == STATE_ORPHANED]

    @property
    def reapable(self) -> list[DaemonReport]:
        """Four-clause matches only. T2 ORPHANED is not a kill list."""
        return [d for d in self.daemons if d.reapable]

    @property
    def unknowns(self) -> list[DaemonReport]:
        return [d for d in self.daemons if d.state == STATE_UNKNOWN]


def is_claude_daemon_cmdline(cmdline: str) -> bool:
    """True when argv looks like Anthropic's ``claude daemon run``."""
    # Avoid matching shells/scripts that merely mention the string.
    parts = cmdline.split()
    try:
        i = next(i for i, p in enumerate(parts) if p.endswith("claude") or p == "claude")
    except StopIteration:
        return False
    return (
        i + 2 < len(parts)
        and parts[i + 1] == "daemon"
        and parts[i + 2] == "run"
    )


def parse_spawned_by(cmdline: str) -> Optional[dict]:
    """Return the ``--spawned-by`` JSON object, or None if absent/unparseable."""
    m = _SPAWNED_BY_RE.search(cmdline)
    if not m:
        return None
    raw = m.group(1)
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError:
        return None
    return obj if isinstance(obj, dict) else None


def parse_origin(cmdline: str) -> Optional[str]:
    m = _ORIGIN_RE.search(cmdline)
    return m.group(1) if m else None


def is_transient_or_fork(cmdline: str) -> bool:
    """Clause 1: `--origin transient` OR `--fork-session`."""
    return parse_origin(cmdline) == "transient" or bool(_FORK_RE.search(cmdline))


def parse_version(text: Optional[str]) -> Optional[tuple[int, int, int]]:
    if not text:
        return None
    m = _VER_RE.search(text)
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


def version_string(triple: Optional[tuple[int, int, int]]) -> Optional[str]:
    if not triple:
        return None
    return f"{triple[0]}.{triple[1]}.{triple[2]}"


def read_sid(pid: int, *, proc_root: Path = Path("/proc")) -> Optional[int]:
    """/proc/<pid>/stat session id (field 6)."""
    after = _stat_after_comm(pid, proc_root=proc_root)
    if after is None or len(after) < 4:
        return None
    try:
        return int(after[3])
    except ValueError:
        return None


def live_pane_pids(
    sessions: Optional[Iterable[str]],
    run: Callable[..., subprocess.CompletedProcess] = subprocess.run,
) -> Optional[set[int]]:
    """None if tmux is unreachable (cannot prove 'not a live pane')."""
    if sessions is None:
        return None
    out: set[int] = set()
    for session in sessions:
        out.update(pane_pids_for_session(session, run=run))
    return out


def evaluate_reap_clauses(
    *,
    cmdline: str,
    ppid: Optional[int],
    pid: int,
    sid: Optional[int],
    pane_pids: Optional[set[int]],
    child_count: int,
    daemon_ver: Optional[tuple[int, int, int]],
    installed_ver: Optional[tuple[int, int, int]],
    self_related: bool = False,
) -> tuple[dict, Optional[str], bool]:
    """Return (clauses, spared_by, reapable).

    All four clauses must be True. Incomplete pane evidence (tmux down)
    fails clause 3 rather than failing open into a kill.
    Self-related daemons are never reapable.
    """
    clauses = {
        CLAUSE_ORIGIN: is_transient_or_fork(cmdline),
        CLAUSE_PPID: ppid == 1,
        CLAUSE_PANE: False,
        CLAUSE_STALE: False,
    }
    if pane_pids is not None:
        clauses[CLAUSE_PANE] = (
            pid not in pane_pids
            and (sid is None or sid not in pane_pids)
        )
    stale = (
        daemon_ver is not None
        and installed_ver is not None
        and daemon_ver < installed_ver
    )
    clauses[CLAUSE_STALE] = (child_count == 0) or stale
    if self_related:
        return clauses, "self-exclusion", False
    for name in REAP_CLAUSES:
        if not clauses[name]:
            return clauses, name, False
    return clauses, None, True


def extract_tmux_scope(cgroup_text: Optional[str]) -> Optional[str]:
    if not cgroup_text:
        return None
    m = _TMUX_SCOPE_RE.search(cgroup_text)
    return m.group(1) if m else None


def classify_daemon(
    *,
    spawner_pid: Optional[int],
    spawner_alive: Optional[bool],
    scope: Optional[str],
    scope_live: Optional[bool],
    self_related: bool = False,
) -> tuple[str, str]:
    """Return ``(state, reason)``. Pure: no /proc, no signals.

    Rules (card #666 T2):
      LIVE      spawner alive → leave alone
                (also: spawner dead but scope still live → leave alone)
      ORPHANED  spawner dead AND scope has no live tmux session
      UNKNOWN   spawner pid missing / unparseable, OR evidence incomplete

    UNKNOWN is never ORPHANED. Self-related daemons (A3) are never ORPHANED.
    """
    if self_related:
        return STATE_LIVE, "self-exclusion: caller is in this daemon's ancestry"
    if spawner_pid is None or spawner_alive is None:
        return STATE_UNKNOWN, "spawned-by pid missing or unparseable"
    if spawner_alive:
        return STATE_LIVE, "spawner alive"
    # spawner dead — need affirmative scope-dead evidence to orphan
    if scope is None or scope_live is None:
        return STATE_UNKNOWN, "spawner dead but scope evidence incomplete"
    if scope_live:
        return STATE_LIVE, "spawner dead but scope still maps to a live tmux session"
    return STATE_ORPHANED, "spawner dead and scope has no live tmux session"


def pid_alive(pid: int, *, proc_root: Path = Path("/proc")) -> Optional[bool]:
    """True/False if determinable; None if we cannot tell (not Linux, etc.)."""
    if pid <= 0:
        return False
    try:
        (proc_root / str(pid)).stat()
        return True
    except FileNotFoundError:
        return False
    except OSError:
        return None


def read_cmdline(pid: int, *, proc_root: Path = Path("/proc")) -> Optional[str]:
    try:
        raw = (proc_root / str(pid) / "cmdline").read_bytes()
    except OSError:
        return None
    return raw.replace(b"\x00", b" ").decode("utf-8", "replace").strip() or None


def read_cgroup(pid: int, *, proc_root: Path = Path("/proc")) -> Optional[str]:
    try:
        return (proc_root / str(pid) / "cgroup").read_text(encoding="utf-8")
    except OSError:
        return None


def read_rss_kb(pid: int, *, proc_root: Path = Path("/proc")) -> int:
    try:
        text = (proc_root / str(pid) / "status").read_text(encoding="utf-8")
    except OSError:
        return 0
    for line in text.splitlines():
        if line.startswith("VmRSS:"):
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                return int(parts[1])
    return 0


def _stat_after_comm(pid: int, *, proc_root: Path = Path("/proc")) -> Optional[list[str]]:
    try:
        data = (proc_root / str(pid) / "stat").read_text(encoding="utf-8")
        return data[data.rfind(")") + 2:].split()
    except (OSError, ValueError, IndexError):
        return None


def read_ppid(pid: int, *, proc_root: Path = Path("/proc")) -> Optional[int]:
    after = _stat_after_comm(pid, proc_root=proc_root)
    if after is None or len(after) < 2:
        return None
    try:
        return int(after[1])
    except ValueError:
        return None


def read_starttime(pid: int, *, proc_root: Path = Path("/proc")) -> Optional[int]:
    """/proc/<pid>/stat field 22 — starttime in clock ticks. Identity, not age."""
    after = _stat_after_comm(pid, proc_root=proc_root)
    if after is None or len(after) < 20:
        return None
    try:
        return int(after[19])
    except ValueError:
        return None


def list_children(pid: int, *, proc_root: Path = Path("/proc")) -> list[int]:
    """Direct children of ``pid`` (one level)."""
    out: list[int] = []
    try:
        entries = list(proc_root.iterdir())
    except OSError:
        return out
    for entry in entries:
        if not entry.name.isdigit():
            continue
        child = int(entry.name)
        if read_ppid(child, proc_root=proc_root) == pid:
            out.append(child)
    return out


def process_tree(root: int, *, proc_root: Path = Path("/proc"), limit: int = 256) -> list[int]:
    """BFS descendants of ``root`` (excluding root). Bounded."""
    seen: set[int] = set()
    queue = list(list_children(root, proc_root=proc_root))
    while queue and len(seen) < limit:
        cur = queue.pop(0)
        if cur in seen or cur == root:
            continue
        seen.add(cur)
        queue.extend(list_children(cur, proc_root=proc_root))
    return sorted(seen)


def ancestry_pids(pid: int, *, proc_root: Path = Path("/proc"), max_depth: int = 40) -> set[int]:
    """``pid`` plus every PPID up to init."""
    out: set[int] = set()
    cur = pid
    for _ in range(max_depth):
        if cur in out or cur <= 0:
            break
        out.add(cur)
        ppid = read_ppid(cur, proc_root=proc_root)
        if ppid is None or ppid == cur:
            break
        cur = ppid
    return out


def self_related(
    daemon_pid: int,
    caller_pid: int,
    *,
    proc_root: Path = Path("/proc"),
) -> bool:
    """A3: True if the caller sits in the daemon's ancestry or process tree.

    The session that runs the detector must never classify its own serving
    daemon as ORPHANED.
    """
    if daemon_pid == caller_pid:
        return True
    caller_anc = ancestry_pids(caller_pid, proc_root=proc_root)
    if daemon_pid in caller_anc:
        return True
    daemon_tree = set(process_tree(daemon_pid, proc_root=proc_root)) | {daemon_pid}
    if caller_pid in daemon_tree:
        return True
    if caller_anc & daemon_tree:
        return True
    return False


def list_tmux_sessions(
    run: Callable[..., subprocess.CompletedProcess] = subprocess.run,
) -> Optional[list[str]]:
    """Session names from ``tmux list-sessions``, or None if tmux unreachable."""
    try:
        r = run(
            ["tmux", "list-sessions", "-F", "#{session_name}"],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if r.returncode != 0:
        return None
    return [ln.strip() for ln in r.stdout.splitlines() if ln.strip()]


def pane_pids_for_session(
    session: str,
    run: Callable[..., subprocess.CompletedProcess] = subprocess.run,
) -> list[int]:
    try:
        r = run(
            ["tmux", "list-panes", "-t", session, "-F", "#{pane_pid}"],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    if r.returncode != 0:
        return []
    return [int(p) for p in r.stdout.split() if p.strip().isdigit()]


def live_scopes(
    sessions: Iterable[str],
    *,
    proc_root: Path = Path("/proc"),
    run: Callable[..., subprocess.CompletedProcess] = subprocess.run,
) -> set[str]:
    """tmux-spawn-*.scope names still hosting at least one live tmux pane."""
    scopes: set[str] = set()
    for session in sessions:
        for pane in pane_pids_for_session(session, run=run):
            # Pane shell + a few descendants — enough to catch the agent.
            candidates = [pane] + process_tree(pane, proc_root=proc_root, limit=64)
            for pid in candidates:
                scope = extract_tmux_scope(read_cgroup(pid, proc_root=proc_root))
                if scope:
                    scopes.add(scope)
    return scopes


def enumerate_claude_daemon_pids(
    *,
    proc_root: Path = Path("/proc"),
) -> list[tuple[int, str]]:
    out: list[tuple[int, str]] = []
    try:
        entries = list(proc_root.iterdir())
    except OSError:
        return out
    for entry in entries:
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        cmdline = read_cmdline(pid, proc_root=proc_root)
        if cmdline and is_claude_daemon_cmdline(cmdline):
            out.append((pid, cmdline))
    return sorted(out, key=lambda t: t[0])


def scan_orphan_daemons(
    *,
    proc_root: Path = Path("/proc"),
    caller_pid: Optional[int] = None,
    run: Callable[..., subprocess.CompletedProcess] = subprocess.run,
    installed_ver: Optional[tuple[int, int, int]] = None,
) -> ScanResult:
    """Walk /proc, classify every ``claude daemon run``, return the report."""
    if caller_pid is None:
        caller_pid = os.getpid()

    sessions = list_tmux_sessions(run=run)
    # None → tmux unreachable: scope_live becomes None → UNKNOWN, never ORPHANED.
    scopes: Optional[set[str]]
    if sessions is None:
        scopes = None
    else:
        scopes = live_scopes(sessions, proc_root=proc_root, run=run)
    panes = live_pane_pids(sessions, run=run)

    result = ScanResult()
    for pid, cmdline in enumerate_claude_daemon_pids(proc_root=proc_root):
        spawned = parse_spawned_by(cmdline)
        origin = parse_origin(cmdline)
        scope = extract_tmux_scope(read_cgroup(pid, proc_root=proc_root))

        spawner_pid: Optional[int] = None
        spawner_alive: Optional[bool] = None
        if isinstance(spawned, dict) and "pid" in spawned:
            try:
                spawner_pid = int(spawned["pid"])
            except (TypeError, ValueError):
                spawner_pid = None
            if spawner_pid is not None:
                spawner_alive = pid_alive(spawner_pid, proc_root=proc_root)

        if scopes is None:
            scope_live: Optional[bool] = None
        elif scope is None:
            scope_live = None
        else:
            scope_live = scope in scopes

        related = self_related(pid, caller_pid, proc_root=proc_root)
        state, reason = classify_daemon(
            spawner_pid=spawner_pid,
            spawner_alive=spawner_alive,
            scope=scope,
            scope_live=scope_live,
            self_related=related,
        )

        tree = process_tree(pid, proc_root=proc_root)
        rss = read_rss_kb(pid, proc_root=proc_root) + sum(
            read_rss_kb(c, proc_root=proc_root) for c in tree
        )
        ppid = read_ppid(pid, proc_root=proc_root)
        sid = read_sid(pid, proc_root=proc_root)
        daemon_ver = parse_version(cmdline)
        clauses, spared_by, reapable = evaluate_reap_clauses(
            cmdline=cmdline,
            ppid=ppid,
            pid=pid,
            sid=sid,
            pane_pids=panes,
            child_count=len(tree),
            daemon_ver=daemon_ver,
            installed_ver=installed_ver,
            self_related=related,
        )
        result.daemons.append(
            DaemonReport(
                pid=pid,
                cmdline=cmdline,
                state=state,
                spawner_pid=spawner_pid,
                spawner_alive=spawner_alive,
                origin=origin,
                scope=scope,
                scope_live=scope_live,
                child_count=len(tree),
                rss_kb=rss,
                reason=reason,
                self_excluded=related,
                ppid=ppid,
                sid=sid,
                version=version_string(daemon_ver),
                clauses=clauses,
                spared_by=spared_by,
                reapable=reapable,
            )
        )
    return result


def format_report(result: ScanResult) -> str:
    lines: list[str] = []
    if not result.daemons:
        # Explicit none — distinguishable from "did not run" (T1 accept).
        lines.append("orphan-daemons: none")
        lines.append("  (no `claude daemon run` processes found)")
        return "\n".join(lines)

    n_orph = len(result.orphans)
    n_unk = len(result.unknowns)
    n_live = sum(1 for d in result.daemons if d.state == STATE_LIVE)
    lines.append(
        f"orphan-daemons: {len(result.daemons)} daemon(s) — "
        f"{n_orph} ORPHANED, {n_live} LIVE, {n_unk} UNKNOWN"
    )
    for d in result.daemons:
        spawner = (
            f"spawner={d.spawner_pid}"
            f"({'alive' if d.spawner_alive else 'DEAD' if d.spawner_alive is False else '?'})"
            if d.spawner_pid is not None
            else "spawner=?"
        )
        scope = d.scope or "scope=?"
        scope_bit = (
            "live" if d.scope_live else "dead" if d.scope_live is False else "?"
        )
        excl = " SELF-EXCLUDED" if d.self_excluded else ""
        clause_bits = ",".join(
            f"{k}={'T' if d.clauses.get(k) else 'F'}" for k in REAP_CLAUSES
        )
        reap_bit = "REAPABLE" if d.reapable else f"spared-by={d.spared_by or '?'}"
        lines.append(
            f"  [{d.state}] pid={d.pid} origin={d.origin or '?'} {spawner} "
            f"{scope}({scope_bit}) children={d.child_count} "
            f"rss={d.rss_kb}kB{excl}"
        )
        lines.append(f"           {d.reason}")
        lines.append(f"           clauses {clause_bits} → {reap_bit}")
    n_reap = len(result.reapable)
    if n_orph == 0:
        lines.append("orphans: none")
    lines.append(
        f"reap-predicate: {n_reap} four-clause match(es) "
        f"(origin_or_fork AND ppid=1 AND not_live_pane AND childless_or_stale)"
    )
    return "\n".join(lines)


# ── T3 reap (opt-in, by PID, re-verify) ─────────────────────────────────────

_DEFAULT_REAP_WAIT_S = 2.0
_DEFAULT_REAP_POLL_S = 0.05


@dataclass(frozen=True)
class ProcIdentity:
    """What must still match immediately before a signal (#666 T3)."""
    pid: int
    starttime: Optional[int]
    cmdline: Optional[str]
    scope: Optional[str]


@dataclass
class SignalReport:
    pid: int
    action: str  # term | kill | skipped | already-gone | survived
    reason: str


def snapshot_identity(pid: int, *, proc_root: Path = Path("/proc")) -> Optional[ProcIdentity]:
    if pid_alive(pid, proc_root=proc_root) is not True:
        return None
    return ProcIdentity(
        pid=pid,
        starttime=read_starttime(pid, proc_root=proc_root),
        cmdline=read_cmdline(pid, proc_root=proc_root),
        scope=extract_tmux_scope(read_cgroup(pid, proc_root=proc_root)),
    )


def identities_match(expected: ProcIdentity, current: Optional[ProcIdentity]) -> bool:
    if current is None:
        return False
    return (
        current.pid == expected.pid
        and current.starttime == expected.starttime
        and current.cmdline == expected.cmdline
        and current.scope == expected.scope
    )


def reap_order(root: int, *, proc_root: Path = Path("/proc")) -> list[int]:
    """Children first (reverse BFS), then the daemon. Never a pattern kill."""
    return list(reversed(process_tree(root, proc_root=proc_root))) + [root]


def _default_kill(pid: int, sig: int) -> None:
    os.kill(pid, sig)


def _wait_gone(
    pid: int,
    *,
    ident: ProcIdentity,
    proc_root: Path,
    wait_s: float,
    poll_s: float,
    sleeper: Callable[[float], None] = time.sleep,
) -> bool:
    """True if pid is gone or no longer the snapshotted identity."""
    deadline = time.monotonic() + wait_s
    while True:
        now = snapshot_identity(pid, proc_root=proc_root)
        if not identities_match(ident, now):
            return True
        if time.monotonic() >= deadline:
            return False
        sleeper(min(poll_s, max(0.0, deadline - time.monotonic())))


def signal_one(
    ident: ProcIdentity,
    *,
    proc_root: Path = Path("/proc"),
    kill: Callable[[int, int], None] = _default_kill,
    wait_s: float = _DEFAULT_REAP_WAIT_S,
    poll_s: float = _DEFAULT_REAP_POLL_S,
    sleeper: Callable[[float], None] = time.sleep,
) -> SignalReport:
    """SIGTERM, then SIGKILL if the same identity survives. Re-verify first."""
    now = snapshot_identity(ident.pid, proc_root=proc_root)
    if now is None:
        return SignalReport(ident.pid, "already-gone", "pid gone before signal")
    if not identities_match(ident, now):
        return SignalReport(
            ident.pid, "skipped",
            "identity changed (starttime/cmdline/scope) — pid recycle, not killed",
        )
    try:
        kill(ident.pid, signal.SIGTERM)
    except ProcessLookupError:
        return SignalReport(ident.pid, "already-gone", "gone at SIGTERM")
    if _wait_gone(ident.pid, ident=ident, proc_root=proc_root,
                  wait_s=wait_s, poll_s=poll_s, sleeper=sleeper):
        return SignalReport(ident.pid, "term", "SIGTERM")
    try:
        kill(ident.pid, signal.SIGKILL)
    except ProcessLookupError:
        return SignalReport(ident.pid, "term", "gone during SIGKILL")
    if _wait_gone(ident.pid, ident=ident, proc_root=proc_root,
                  wait_s=wait_s, poll_s=poll_s, sleeper=sleeper):
        return SignalReport(ident.pid, "kill", "SIGKILL after SIGTERM wait")
    return SignalReport(ident.pid, "survived", "still the same identity after SIGKILL")


def reap_orphans(
    result: ScanResult,
    *,
    proc_root: Path = Path("/proc"),
    kill: Callable[[int, int], None] = _default_kill,
    wait_s: float = _DEFAULT_REAP_WAIT_S,
    poll_s: float = _DEFAULT_REAP_POLL_S,
    sleeper: Callable[[float], None] = time.sleep,
) -> list[SignalReport]:
    """Signal only four-clause matches and their trees. T2-ORPHANED is not enough."""
    reports: list[SignalReport] = []
    seen: set[int] = set()
    for daemon in result.reapable:
        for pid in reap_order(daemon.pid, proc_root=proc_root):
            if pid in seen:
                continue
            seen.add(pid)
            ident = snapshot_identity(pid, proc_root=proc_root)
            if ident is None:
                reports.append(SignalReport(pid, "already-gone", "gone before snapshot"))
                continue
            reports.append(signal_one(
                ident, proc_root=proc_root, kill=kill,
                wait_s=wait_s, poll_s=poll_s, sleeper=sleeper,
            ))
    return reports


def format_reap_report(reports: list[SignalReport]) -> str:
    if not reports:
        return "reap: none (no four-clause match — transient-only is never enough)"
    lines = [f"reap: {len(reports)} pid(s)"]
    for r in reports:
        lines.append(f"  pid={r.pid}  {r.action}  {r.reason}")
    return "\n".join(lines)


def run_orphan_daemons_report(
    *,
    proc_root: Path = Path("/proc"),
    caller_pid: Optional[int] = None,
    run: Callable[..., subprocess.CompletedProcess] = subprocess.run,
    reap: bool = False,
    wait_s: float = _DEFAULT_REAP_WAIT_S,
) -> int:
    """Print the T1 report. With reap=True, opt-in four-clause kill after the scan."""
    result = scan_orphan_daemons(
        proc_root=proc_root, caller_pid=caller_pid, run=run,
    )
    print(format_report(result))
    if not reap:
        return 0
    reports = reap_orphans(result, proc_root=proc_root, wait_s=wait_s)
    print(format_reap_report(reports))
    return 0


def run_can_fail_healthy_pane() -> int:
    """#123 can-fail: a transient daemon that IS a live pane_pid must be spared.

    Builds a fake /proc + tmux so the live box is not touched. Prints the
    clause that spared it. Exit 0 only when that clause is not_live_pane.
    """
    import tempfile
    from types import SimpleNamespace

    tmp = Path(tempfile.mkdtemp(prefix="swarph-666-canfail-"))
    try:
        d = tmp / "42"
        d.mkdir(parents=True)
        cmd = (
            "/home/u/.local/bin/claude daemon run --origin transient "
            '--spawned-by {"label":"claude","pid":700337}'
        )
        (d / "cmdline").write_bytes(cmd.replace(" ", "\x00").encode() + b"\x00")
        (d / "stat").write_text("42 (claude) S 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n")
        (d / "status").write_text("Name:\tclaude\nPPid:\t1\nVmRSS:\t168000 kB\n")
        (d / "cgroup").write_text("0::/user.slice/tmux-spawn-alive.scope\n")

        def fake_run(cmd, **kwargs):
            if cmd[:2] == ["tmux", "list-sessions"]:
                return SimpleNamespace(returncode=0, stdout="lab-ovh\n", stderr="")
            if cmd[:2] == ["tmux", "list-panes"]:
                return SimpleNamespace(returncode=0, stdout="42\n", stderr="")
            return SimpleNamespace(returncode=1, stdout="", stderr="")

        result = scan_orphan_daemons(
            proc_root=tmp, caller_pid=99999, run=fake_run,
        )
        print(format_report(result))
        print(format_reap_report(reap_orphans(result, proc_root=tmp, kill=lambda *_: None)))
        if len(result.daemons) != 1:
            print("can-fail: FAIL expected 1 daemon", file=sys.stderr)
            return 1
        row = result.daemons[0]
        if row.reapable or row.spared_by != CLAUSE_PANE:
            print(
                f"can-fail: FAIL expected spared-by={CLAUSE_PANE} "
                f"got reapable={row.reapable} spared-by={row.spared_by}",
                file=sys.stderr,
            )
            return 1
        print(f"can-fail: PASS spared-by={row.spared_by} (healthy pane daemon not killed)")
        return 0
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)

