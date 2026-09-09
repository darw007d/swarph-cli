"""#666 T1/T2 — orphan ``claude daemon run`` detector (read-only)."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from swarph_cli.orphan_daemons import (
    STATE_LIVE,
    STATE_ORPHANED,
    STATE_UNKNOWN,
    classify_daemon,
    format_report,
    format_reap_report,
    is_claude_daemon_cmdline,
    parse_spawned_by,
    reap_orphans,
    scan_orphan_daemons,
    self_related,
    signal_one,
    snapshot_identity,
)


def test_is_claude_daemon_cmdline_requires_daemon_run():
    assert is_claude_daemon_cmdline(
        "/home/u/.local/bin/claude daemon run --origin transient "
        '--spawned-by {"label":"claude","pid":123}'
    )
    assert not is_claude_daemon_cmdline("bash -c claude something")
    assert not is_claude_daemon_cmdline("claude chat")
    assert not is_claude_daemon_cmdline("claude daemon")  # no `run`


def test_parse_spawned_by_ok_and_missing():
    cmd = (
        'claude daemon run --json-path /x --origin transient '
        '--spawned-by {"label":"claude","cwd":"/home/u","pid":700337}'
    )
    assert parse_spawned_by(cmd) == {
        "label": "claude", "cwd": "/home/u", "pid": 700337,
    }
    assert parse_spawned_by("claude daemon run --origin transient") is None
    assert parse_spawned_by(
        "claude daemon run --spawned-by {not-json}"
    ) is None


def test_classify_live_when_spawner_alive():
    state, _ = classify_daemon(
        spawner_pid=1, spawner_alive=True,
        scope="tmux-spawn-abc.scope", scope_live=False,
    )
    assert state == STATE_LIVE


def test_classify_orphaned_when_spawner_dead_and_scope_dead():
    state, _ = classify_daemon(
        spawner_pid=99, spawner_alive=False,
        scope="tmux-spawn-abc.scope", scope_live=False,
    )
    assert state == STATE_ORPHANED


def test_classify_unknown_never_orphaned_without_spawned_by():
    """T2 accept: synthetic cmdline with no --spawned-by → UNKNOWN, never ORPHANED."""
    state, reason = classify_daemon(
        spawner_pid=None, spawner_alive=None,
        scope="tmux-spawn-abc.scope", scope_live=False,
    )
    assert state == STATE_UNKNOWN
    assert "missing" in reason or "unparseable" in reason


def test_classify_unknown_when_scope_evidence_incomplete():
    state, _ = classify_daemon(
        spawner_pid=99, spawner_alive=False,
        scope=None, scope_live=None,
    )
    assert state == STATE_UNKNOWN


def test_classify_live_when_spawner_dead_but_scope_live():
    state, _ = classify_daemon(
        spawner_pid=99, spawner_alive=False,
        scope="tmux-spawn-abc.scope", scope_live=True,
    )
    assert state == STATE_LIVE


def test_classify_self_exclusion_never_orphaned():
    """A3: caller's own daemon must never be ORPHANED."""
    state, reason = classify_daemon(
        spawner_pid=99, spawner_alive=False,
        scope="tmux-spawn-abc.scope", scope_live=False,
        self_related=True,
    )
    assert state == STATE_LIVE
    assert "self-exclusion" in reason


def _write_proc(root: Path, pid: int, *, cmdline: str, ppid: int = 1,
                cgroup: str = "", rss_kb: int = 100) -> None:
    d = root / str(pid)
    d.mkdir(parents=True, exist_ok=True)
    (d / "cmdline").write_bytes(cmdline.replace(" ", "\x00").encode() + b"\x00")
    # /proc/<pid>/stat: pid (comm) state ppid ...
    (d / "stat").write_text(f"{pid} (claude) S {ppid} 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n")
    (d / "status").write_text(f"Name:\tclaude\nPPid:\t{ppid}\nVmRSS:\t{rss_kb} kB\n")
    if cgroup:
        (d / "cgroup").write_text(cgroup)


def test_scan_explicit_none_when_empty(tmp_path):
    """T1 accept: no daemons → explicit 'none', not silent empty."""
    result = scan_orphan_daemons(
        proc_root=tmp_path,
        caller_pid=1,
        run=lambda *a, **k: SimpleNamespace(returncode=0, stdout="", stderr=""),
    )
    assert result.daemons == []
    text = format_report(result)
    assert "orphan-daemons: none" in text
    assert "no `claude daemon run`" in text


def test_scan_orphaned_positive(tmp_path):
    """A1 shape: real orphan named with dead spawner pid."""
    scope = "tmux-spawn-deadbeef.scope"
    daemon_cmd = (
        "/home/u/.local/bin/claude daemon run --json-path /x "
        f"--origin transient --spawned-by {json.dumps({'label': 'claude', 'pid': 700337})}"
    )
    _write_proc(
        tmp_path, 5000, cmdline=daemon_cmd, ppid=1,
        cgroup=f"0::/user.slice/{scope}", rss_kb=168000,
    )
    # spawner 700337 deliberately absent → dead
    # a live tmux session exists but under a DIFFERENT scope
    _write_proc(
        tmp_path, 42, cmdline="/bin/bash", ppid=1,
        cgroup="0::/user.slice/tmux-spawn-alive.scope",
    )

    def fake_run(cmd, **kwargs):
        if cmd[:2] == ["tmux", "list-sessions"]:
            return SimpleNamespace(returncode=0, stdout="lab-ovh\n", stderr="")
        if cmd[:2] == ["tmux", "list-panes"]:
            return SimpleNamespace(returncode=0, stdout="42\n", stderr="")
        return SimpleNamespace(returncode=1, stdout="", stderr="")

    result = scan_orphan_daemons(
        proc_root=tmp_path, caller_pid=99999, run=fake_run,
    )
    assert len(result.daemons) == 1
    d = result.daemons[0]
    assert d.state == STATE_ORPHANED
    assert d.spawner_pid == 700337
    assert d.spawner_alive is False
    assert d.scope == scope
    assert "orphans: none" not in format_report(result)


def test_scan_live_control_zero_orphans(tmp_path):
    """A2: only LIVE daemons → zero orphans (not 'every daemon is orphan')."""
    scope = "tmux-spawn-alive.scope"
    daemon_cmd = (
        "/home/u/.local/bin/claude daemon run --origin transient "
        f"--spawned-by {json.dumps({'label': 'claude', 'pid': 100})}"
    )
    _write_proc(tmp_path, 100, cmdline="claude", ppid=1,
                cgroup=f"0::/user.slice/{scope}")
    _write_proc(
        tmp_path, 5000, cmdline=daemon_cmd, ppid=100,
        cgroup=f"0::/user.slice/{scope}",
    )
    _write_proc(
        tmp_path, 42, cmdline="/bin/bash", ppid=1,
        cgroup=f"0::/user.slice/{scope}",
    )

    def fake_run(cmd, **kwargs):
        if cmd[:2] == ["tmux", "list-sessions"]:
            return SimpleNamespace(returncode=0, stdout="lab-ovh\n", stderr="")
        if cmd[:2] == ["tmux", "list-panes"]:
            return SimpleNamespace(returncode=0, stdout="42\n", stderr="")
        return SimpleNamespace(returncode=1, stdout="", stderr="")

    result = scan_orphan_daemons(
        proc_root=tmp_path, caller_pid=99999, run=fake_run,
    )
    assert len(result.daemons) == 1
    assert result.daemons[0].state == STATE_LIVE
    assert result.orphans == []
    assert "orphans: none" in format_report(result)


def test_scan_unknown_cmdline_without_spawned_by(tmp_path):
    _write_proc(
        tmp_path, 5000,
        cmdline="/home/u/.local/bin/claude daemon run --origin transient",
        ppid=1,
        cgroup="0::/user.slice/tmux-spawn-x.scope",
    )

    def fake_run(cmd, **kwargs):
        if cmd[:2] == ["tmux", "list-sessions"]:
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        return SimpleNamespace(returncode=1, stdout="", stderr="")

    result = scan_orphan_daemons(
        proc_root=tmp_path, caller_pid=99999, run=fake_run,
    )
    assert result.daemons[0].state == STATE_UNKNOWN
    assert result.orphans == []


def test_self_related_via_ancestry(tmp_path):
    # caller 200 ← ppid 5000 (daemon)
    _write_proc(tmp_path, 5000, cmdline="claude daemon run --origin transient", ppid=1)
    _write_proc(tmp_path, 200, cmdline="swarph", ppid=5000)
    assert self_related(5000, 200, proc_root=tmp_path) is True
    assert self_related(5000, 999, proc_root=tmp_path) is False


def test_watchdog_orphan_daemons_flag_dispatches(tmp_path, monkeypatch, capsys):
    from swarph_cli.commands import watchdog

    monkeypatch.setattr(
        "swarph_cli.orphan_daemons.scan_orphan_daemons",
        lambda **kw: scan_orphan_daemons(
            proc_root=tmp_path, caller_pid=1,
            run=lambda *a, **k: SimpleNamespace(returncode=0, stdout="", stderr=""),
        ),
    )
    rc = watchdog.run_watchdog(["--orphan-daemons"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "orphan-daemons: none" in out


def test_identity_change_is_skipped_not_killed(tmp_path):
    """T3 accept: identity change between snapshot and signal → skip, no kill."""
    _write_proc(tmp_path, 5000, cmdline="claude daemon run --origin transient")
    ident = snapshot_identity(5000, proc_root=tmp_path)
    assert ident is not None
    # pid recycled: same pid, new cmdline + starttime
    _write_proc(tmp_path, 5000, cmdline="sshd")
    (tmp_path / "5000" / "stat").write_text(
        "5000 (sshd) S 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 99\n"
    )
    killed = []
    report = signal_one(
        ident, proc_root=tmp_path,
        kill=lambda pid, sig: killed.append((pid, sig)),
        wait_s=0.01, poll_s=0.001, sleeper=lambda _s: None,
    )
    assert report.action == "skipped"
    assert killed == []


def test_reap_reports_every_pid_and_never_touches_live(tmp_path):
    """A4: every signalled pid is named. LIVE is not in the reap list."""
    import json
    scope_dead = "tmux-spawn-dead.scope"
    orphan_cmd = (
        "/home/u/.local/bin/claude daemon run --origin transient "
        "v2.1.200 "
        f"--spawned-by {json.dumps({'label': 'claude', 'pid': 700337})}"
    )
    live_cmd = (
        "/home/u/.local/bin/claude daemon run --origin transient "
        f"--spawned-by {json.dumps({'label': 'claude', 'pid': 100})}"
    )
    _write_proc(tmp_path, 5000, cmdline=orphan_cmd, ppid=1,
                cgroup=f"0::/user.slice/{scope_dead}")
    _write_proc(tmp_path, 5001, cmdline="node mcp", ppid=5000,
                cgroup=f"0::/user.slice/{scope_dead}")
    _write_proc(tmp_path, 100, cmdline="claude", ppid=1,
                cgroup="0::/user.slice/tmux-spawn-alive.scope")
    _write_proc(tmp_path, 6000, cmdline=live_cmd, ppid=100,
                cgroup="0::/user.slice/tmux-spawn-alive.scope")
    _write_proc(tmp_path, 42, cmdline="/bin/bash", ppid=1,
                cgroup="0::/user.slice/tmux-spawn-alive.scope")

    def fake_run(cmd, **kwargs):
        if cmd[:2] == ["tmux", "list-sessions"]:
            return SimpleNamespace(returncode=0, stdout="lab-ovh\n", stderr="")
        if cmd[:2] == ["tmux", "list-panes"]:
            return SimpleNamespace(returncode=0, stdout="42\n", stderr="")
        return SimpleNamespace(returncode=1, stdout="", stderr="")

    result = scan_orphan_daemons(
        proc_root=tmp_path, caller_pid=99999, run=fake_run,
        installed_ver=(2, 1, 259),
    )
    assert {d.pid: d.state for d in result.daemons}[5000] == STATE_ORPHANED
    assert {d.pid: d.state for d in result.daemons}[6000] == STATE_LIVE
    assert {d.pid: d.reapable for d in result.daemons}[5000] is True
    assert {d.pid: d.reapable for d in result.daemons}[6000] is False

    killed = []

    def fake_kill(pid, sig):
        killed.append((pid, sig))
        # simulate death: remove the proc dir
        import shutil
        p = tmp_path / str(pid)
        if p.exists():
            shutil.rmtree(p)

    reports = reap_orphans(
        result, proc_root=tmp_path, kill=fake_kill,
        wait_s=0.01, poll_s=0.001, sleeper=lambda _s: None,
    )
    pids = [r.pid for r in reports]
    assert 5001 in pids and 5000 in pids
    assert pids.index(5001) < pids.index(5000), "children first, parent last"
    assert 6000 not in pids
    text = format_reap_report(reports)
    assert "pid=5000" in text and "pid=5001" in text
    assert all(r.action in ("term", "kill", "already-gone") for r in reports)


def test_reap_none_when_no_orphans():
    from swarph_cli.orphan_daemons import ScanResult
    assert "reap: none" in format_reap_report(reap_orphans(ScanResult()))


def test_watchdog_reap_requires_orphan_daemons():
    from swarph_cli.commands import watchdog
    rc = watchdog.run_watchdog(["--reap"])
    assert rc == 4


def _tmux_one_pane(pane="42"):
    def fake_run(cmd, **kwargs):
        if cmd[:2] == ["tmux", "list-sessions"]:
            return SimpleNamespace(returncode=0, stdout="lab-ovh\n", stderr="")
        if cmd[:2] == ["tmux", "list-panes"]:
            return SimpleNamespace(returncode=0, stdout=f"{pane}\n", stderr="")
        return SimpleNamespace(returncode=1, stdout="", stderr="")
    return fake_run


def test_transient_only_is_not_reapable(tmp_path):
    """#123 FAIL branch: --origin transient alone must not be enough to kill."""
    cmd = (
        "/home/u/.local/bin/claude daemon run --origin transient "
        f"--spawned-by {json.dumps({'label': 'claude', 'pid': 700337})}"
    )
    _write_proc(tmp_path, 5000, cmdline=cmd, ppid=100)  # not init
    result = scan_orphan_daemons(
        proc_root=tmp_path, caller_pid=99999, run=_tmux_one_pane(),
    )
    d = result.daemons[0]
    assert d.clauses["origin_or_fork"] is True
    assert d.reapable is False
    assert d.spared_by == "ppid_init"
    killed = []
    reports = reap_orphans(
        result, proc_root=tmp_path,
        kill=lambda pid, sig: killed.append((pid, sig)),
        wait_s=0.01, poll_s=0.001, sleeper=lambda _s: None,
    )
    assert reports == [] and killed == []
    assert "no four-clause match" in format_reap_report(reports)


def test_healthy_pane_daemon_is_spared_and_names_clause(tmp_path):
    """#123 can-fail: backing a live pane → spared, clause printed."""
    cmd = (
        "/home/u/.local/bin/claude daemon run --origin transient "
        f"--spawned-by {json.dumps({'label': 'claude', 'pid': 700337})}"
    )
    _write_proc(tmp_path, 42, cmdline=cmd, ppid=1,
                cgroup="0::/user.slice/tmux-spawn-alive.scope")
    result = scan_orphan_daemons(
        proc_root=tmp_path, caller_pid=99999, run=_tmux_one_pane("42"),
    )
    d = result.daemons[0]
    assert d.reapable is False
    assert d.spared_by == "not_live_pane"
    text = format_report(result)
    assert "spared-by=not_live_pane" in text
    assert "REAPABLE" not in text


def test_four_clauses_all_true_is_reapable(tmp_path):
    cmd = (
        "/home/u/.local/bin/claude daemon run --origin transient "
        f"--spawned-by {json.dumps({'label': 'claude', 'pid': 700337})}"
    )
    _write_proc(tmp_path, 5000, cmdline=cmd, ppid=1,
                cgroup="0::/user.slice/tmux-spawn-dead.scope")
    result = scan_orphan_daemons(
        proc_root=tmp_path, caller_pid=99999, run=_tmux_one_pane("42"),
    )
    d = result.daemons[0]
    assert d.reapable is True
    assert d.spared_by is None
    assert all(d.clauses[k] for k in (
        "origin_or_fork", "ppid_init", "not_live_pane", "childless_or_stale"))
    assert "→ REAPABLE" in format_report(result)


def test_still_running_with_fresh_heartbeat_is_still_reapable(tmp_path):
    """lab-ovh 36742: 15-day orphan still writing drain_heartbeat.json one
    minute before the kill. A reaper keyed on 'is it running' spares that
    forever. Four-clause must not grow a liveness/heartbeat spare."""
    cmd = (
        "/home/u/.local/bin/claude daemon run --origin transient "
        f"--spawned-by {json.dumps({'label': 'claude', 'pid': 700337})}"
    )
    _write_proc(tmp_path, 5000, cmdline=cmd, ppid=1,
                cgroup="0::/user.slice/tmux-spawn-dead.scope")
    (tmp_path / "5000" / "cwd").mkdir(exist_ok=True)
    (tmp_path / "5000" / "cwd" / "drain_heartbeat.json").write_text(
        '{"ts": "2026-09-09T21:23:00Z"}'
    )
    result = scan_orphan_daemons(
        proc_root=tmp_path, caller_pid=99999, run=_tmux_one_pane("42"),
    )
    d = result.daemons[0]
    assert d.reapable is True
    assert "heartbeat" not in (d.spared_by or "")
    assert "alive" not in (d.reason or "").lower() or d.reapable
    assert "liveness" not in d.clauses

