"""``swarph watchdog`` — Phase 7 / v0.7 stranded-session detection + recovery.

Designed as a cron-callable one-shot check that detects when a Claude
session has gone dark (API throttle / harness death / inbox-watcher
broken) AND has unprocessed DMs queued at the mesh-gateway, then
attempts a two-stage recovery:

* **A1 (cheap re-engage)** — `tmux send-keys` injects a wake-prompt
  into the interactive tmux session's input buffer. If the session is
  alive-but-throttled (today's failure mode), the prompt queues and
  processes on resume. If the session is dead, A1 is a no-op (no harm).
  Repeated up to N times with backoff.

* **A2 (full respawn)** — If A1 escalations exhaust without the cursor
  advancing, the original session is presumed dead. Watchdog kills the
  stale tmux session and respawns via `swarph spawn <role>` (which
  resumes the same session-id from sidecar — the dead session's UUID
  is reused, so the fresh sibling takes over the same /resume picker
  slot).

Per drop-mother review #1021 design:

* **Detection**: cursor file mtime PRIMARY + pgrep claude FALLBACK,
  AND-gate (both must be dark to fire — avoids false-positive on
  legitimate-pause noise).
* **Threshold**: 30min default — comfortably above legitimate-pause
  noise floor + comfortably below typical-stranded-session duration.
* **Production blast radius**: LOW-MODERATE. Cursor file persists
  DM-processed state across respawns (filters already-processed DMs).
  v0 does NOT yet pass `--respawn-after-time` to fresh sibling
  (queued as `swarph spawn --respawn-after-time` enhancement; v0.8+
  scope per mother #1021).

Per beta #1011 (5 primitives): this watchdog implements primitive (3)
throttle-detection + auto-respawn. Primitive (1) mesh-DM queue is
already shipping and provides the queued-context that fresh siblings
inherit on respawn.

**Per-slot cron coverage at v0.7** (beta iter-1 #1029): each
``swarph watchdog --check --cell <role>`` invocation is single-cell
scope. With v0.7 PR-B auto-suffix in play, sibling slots
(``<role>-2``, ``<role>-3``, etc.) need their own cron entries:

  */5 * * * * swarph watchdog --check --cell drop-on-meta-edge
  */5 * * * * swarph watchdog --check --cell drop-on-meta-edge-2

v0.8+ multi-cell watchdog will walk sidecars matching
``<base_role>{,-N}.session-id`` and check each per-invocation, reducing
operator-cron surface to one entry per base-role. Tracked in v0.8+
candidate queue alongside ``--respawn-after-time``, per-cell-yaml
threshold tuning, mesh-down detection, and ``swarph cleanup-sessions``
(beta #987).

Substrate-doc R7 §11.1.7 lineage: this is operator-tooling sub-layer,
not a substrate primitive. The substrate primitive that would
*prevent* the stranding (S-G spawn-context endpoint with liveness
heartbeats) is v0.8+ scope. v0.7 watchdog is the operator-discipline
gap-filler that makes the substrate-evidence event today (3hr
throttle, 6+ stranded DMs, recovered on commander manual chime)
recoverable without commander intervention next time.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional
from swarph_cli.gateway_default import env_gateway

from swarph_cli.commands.mesh import _post_json


_DEFAULT_THRESHOLD_SEC = 1800  # 30 minutes
_DEFAULT_A1_RETRIES = 3
_DEFAULT_A1_BACKOFF_SEC = 60
# NO MODULE-LEVEL GATEWAY CONSTANT (#578). #546 put the gateway's tailnet IP here,
# correctly at the time; that box was retired 2026-08-25 and the literal expired.
# The constant is gone rather than emptied: read at IMPORT time it captured whatever
# the packaging/importing shell exported, and MEASURED in seat-A review of PR #318 it
# still returned that value after the environment was cleared — the one channel by
# which a test could depend on a developer's shell. env_gateway() is called at
# parser-BUILD time instead (parsers are built per invocation).
# F3 — tmux pane_activity gate threshold. If pane has activity within this
# many seconds, suppress A1 (session is working, not stalled). 600s (10min)
# is comfortably above legitimate-pause noise + comfortably below the
# 30min cursor-staleness threshold, so the two gates compose cleanly.
_DEFAULT_PANE_ACTIVITY_THRESHOLD_SEC = 600
# Phase 4 (v0.7.6) — peer-health-event poll defaults. The recovery
# event we care about is `usage_limit_reset` (throttle cleared; session
# may be sitting idle unaware of queued DMs). 600s window catches a
# reset that fired up to 10min before this cron tick. 120s recovery
# threshold gives the session a brief grace period to notice the reset
# itself before we send-keys at it.
_DEFAULT_PEER_HEALTH_WINDOW_SEC = 600
_DEFAULT_PEER_HEALTH_RECOVERY_THRESHOLD_SEC = 120
# T4 — per-peer dm-wake cooldown. One wake-DM per peer per window so a peer
# that stays stale across many ticks is DM'd once, not every tick. Default
# 1800s (30min) mirrors the metered-fallback-alert throttle.
_DEFAULT_DM_WAKE_COOLDOWN_SEC = 1800
_RECOVERY_EVENT_TYPES = ("usage_limit_reset",)
# A1.5 — autonomous engine-swap rung. The model the watchdog injects via
# `/model <STABLE_MODEL>` when A1 has exhausted (wake fired, cursor still
# stale) but BEFORE escalating to A2 respawn. This is a hard-coded constant
# (overridable only via the `--stable-model` CLI flag — a config value, never
# network/peer/inbox-derived). The tmux payload is ALWAYS the fixed template
# `f"/model {stable_model}"`; no message content can ever be interpolated into
# it, by construction. `/model` is a CLI/TUI slash command — NOT an agent tool
# call — so it bypasses the auto-mode classifier that a classifier-degraded
# frontier-model cell has blocked, letting the swap recover the session.
_DEFAULT_STABLE_MODEL = "claude-opus-4-8"
# Allowlist shape for the injected model id (drop seat-A nit, PR #58): even
# the --stable-model CONFIG value must look like a model id before it reaches
# the TUI. A malformed override falls back to the known-good default — a
# config typo must not block recovery, and must not inject an arbitrary string.
#
# PROVIDER-NEUTRAL since #53: the safety property is the CHARSET (no
# whitespace, no shell/terminal metacharacters — the value is interpolated
# into a `/model <id>` tmux payload), not claude-ness. The claude-only shape
# rejected every legitimate non-claude id (gpt-*, grok-*, gemini-*,
# composer-*, kimi-*) and silently fell back to a claude model — a recovery
# rung that fired the WRONG provider's model into a non-claude TUI.
_STABLE_MODEL_RE = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._-]*")
# Cross-WINDOW circuit breakers (drop seat-A C1/C3, PR #58 follow-up). The
# per-window marker bounds one swap per stale window, but a FLAPPING cursor
# (turn-ends without real progress) restarts the ladder each window — A1.5
# would fire once per window forever and A2 never engages (C1). And if BOTH
# engines are degraded, each A2 respawns onto a crushed default and the whole
# ladder repeats across windows (C3). History files (timestamps, pruned to a
# window) bound both: >= max swaps in the window → escalate to A2 instead of
# swapping again; >= max respawns in the window → STOP respawning (circuit
# open, exit 6, operator attention) rather than churn the cell.
_DEFAULT_A15_MAX_SWAPS = 2
_DEFAULT_A15_SWAP_WINDOW_SEC = 21600   # 6h
_DEFAULT_A2_MAX_RESPAWNS = 3
_DEFAULT_A2_RESPAWN_WINDOW_SEC = 3600  # 1h
# A1-DM — cross-host wake. Default prompt sent as a mesh DM to a stranded
# peer on another host; the peer's sidecar/inbox-watcher then wakes it.
_DM_WAKE_PROMPT = (
    "watchdog wake — you appear throttle-stranded (node healthy, session "
    "idle). Drain your inbox and resume work."
)

_USAGE = """\
Usage:
  swarph watchdog --check [--cell ROLE] [--cursor PATH] [--threshold SEC]
                          [--gateway URL] [--tmux-session NAME]
                          [--peer NAME] [--no-respawn]
                          [--peer-health-poll] [--dm-wake]
                          [--dm-wake-cooldown-sec SEC]
                          [--peer-health-window-sec SEC]
                          [--peer-health-recovery-threshold SEC]
                          [--log PATH] [--verbose]
  swarph watchdog --orphan-daemons [--reap]
  swarph watchdog --install-service [--cell ROLE] [--dry-run]

Detects stranded Claude sessions (API throttle / harness death) and attempts
recovery via tmux send-keys A1 wake-prompt, escalating to swarph spawn
respawn (A2) on persistent darkness.

Designed for cron invocation:
  */5 * * * * swarph watchdog --check --cell lab >> ~/.local/log/swarph-watchdog.log 2>&1

OR systemd timer (v0.7.3+, closes ev_6954f748 substrate-component-installation-gap):
  sudo swarph watchdog --install-service [--cell <role>]
  # → installs /etc/systemd/system/swarph-watchdog.{service,timer}
  # → installs /etc/default/swarph-watchdog with SWARPH_CELL=<role>
  # → daemon-reload + enable --now swarph-watchdog.timer

Detection (mother #1021 AND-gate design):
  PRIMARY:  cursor file mtime — most-recent Claude action (drain script touches it)
  FALLBACK: pgrep claude on tmux session — confirms process aliveness
  AND-gate: both signals must indicate dark beyond --threshold to fire

Recovery escalation (beta #1019 two-stage):
  A1: tmux send-keys wake-prompt; queues in input buffer; processes on resume
  A2: After N×A1 fails (cursor still stale): kill stale tmux session +
      `swarph spawn <role>` to respawn (resumes same session-id from sidecar)

Flags:
  --check              one-shot check (cron-callable; exits with status code)

Exit status (--check):
  0  healthy, or verified nothing-to-do
  1  A1 wake sent
  2  A2 respawn fired (or --no-respawn dry-run)
  3  input error (cursor/activity unreadable — check could not run)
  4  recovery action attempted and failed
  5  A1.5 model-swap fired
  6  A2 circuit open (respawn churn refused — operator attention required)
  7  couldn't-verify (#401): state unknown, no action taken — NOT success
  --cell ROLE          cell-yaml role; defaults to $SWARPH_SELF, then $SWARPH_CELL, then
                       'unidentified-cell' (never a real peer's name)
  --cursor PATH        cursor JSON path; default $TMPDIR/<role>-cursor.json
                       fallback /tmp/lab-claude-cursor.json
  --threshold SEC      darkness threshold; default 1800 (30 min)
  --gateway URL        mesh-gateway URL for unread-DM check; default $MESH_GATEWAY_URL
  --tmux-session NAME  tmux session name; default = cell role
  --peer NAME          mesh peer name for unread-DM query; default = cell name
  --no-respawn         A1 only; don't escalate to A2 (dry-run mode)
  --peer-health-poll                    Phase 4: also query /peer-health-events.
                                        On recent usage_limit_reset event, treat
                                        sessions as wake-candidates even before
                                        the 30min cursor-staleness threshold.
                                        Requires MESH_GATEWAY_TOKEN in env.
  --dm-wake                             send a cross-host wake DM to a stranded
                                        peer (A1-DM) instead of only local tmux
                                        send-keys.
  --dm-wake-cooldown-sec SEC            T4 no-spam gate: DM-wake each stale peer
                                        at most once per this window, so a peer
                                        that stays stale across many ticks is
                                        woken once, not every tick; default 1800
                                        (30 min). Per-peer state lives in
                                        $XDG_STATE_HOME/swarph/dm_wake_state.json
  --peer-health-window-sec SEC          how far back to look for recovery
                                        events; default 600 (10 min)
  --peer-health-recovery-threshold SEC  min cursor staleness before a recovery
                                        event promotes the session to wake-
                                        candidate; default 120 (2 min). Avoids
                                        poking a session that JUST got reset
                                        and is already self-recovering.
  --log PATH           append diagnostic log; default $XDG_STATE_HOME/swarph/watchdog.log
  --verbose            also write diagnostics to stderr

Exit codes:
  0  no action taken (session healthy or no unread DMs queued); install ok
  1  A1 fired (wake-prompt sent)
  2  A2 fired (full respawn triggered)
  3  detection error (cursor unreadable / gateway unreachable)
  4  configuration error (invalid args, no cell.yaml resolved); install needs sudo
  5  install error (file write failed / systemctl failed)
"""


def _now() -> int:
    return int(time.time())


def _stat_mtime(path: Path) -> Optional[int]:
    try:
        return int(path.stat().st_mtime)
    except (FileNotFoundError, PermissionError, OSError):
        return None


def _resolve_cursor_path(
    role: str,
    explicit: Optional[str],
    cell_yaml_value: Optional[str] = None,
) -> Path:
    """Resolve cursor file path with documented fallback chain.

    Precedence (F4 — mother #1057/#1060 + beta #1061/#1065):
      1. Explicit ``--cursor`` CLI arg (highest)
      2. ``cell.yaml`` extra.cursor_path when --cell present
      3. ``$TMPDIR/<role>-cursor.json``
      4. ``/tmp/lab-claude-cursor.json`` (legacy lab-orchestrator default, only when role == 'lab')

    F4 closes the host-prefix-variant + sibling-instance-variant gap
    class — cell.yaml carries the canonical cursor path per-cell, watchdog
    auto-resolves when --cell is provided. Eliminates the silent-default-
    to-lab-prefix failure mode that gave droplet 23hr of cursor-unreadable
    errors before catch.
    """
    if explicit:
        return Path(explicit).expanduser()
    if cell_yaml_value:
        return Path(cell_yaml_value).expanduser()
    tmpdir = os.environ.get("TMPDIR", "/tmp")
    primary = Path(tmpdir) / f"{role}-cursor.json"
    if primary.exists():
        return primary
    # Only fall back to the legacy lab path when role is actually 'lab';
    # for any other role, return the computed path so the check fails
    # loudly instead of aliasing to lab's cursor.
    if role == "lab":
        return Path("/tmp/lab-claude-cursor.json")
    return primary


def _resolve_activity_marker_path(
    role: str,
    explicit: Optional[str],
    cell_yaml_value: Optional[str] = None,
) -> Path:
    """Resolve the turn-activity marker — the Stop-hook touches it every turn-end.

    Precedence: ``--activity-marker`` > ``cell.yaml`` extra.activity_marker_path
    > ``$TMPDIR/<role>-claude-active.txt``.

    Unlike the cursor (often the inbox-DRAIN cursor, touched only on drain and so
    STALE during active non-draining work → false-fire,
    feedback_watchdog_liveness_proxy), this marker tracks real turn activity. The
    watchdog uses the FRESHEST mtime of {cursor, marker} as the effective
    last-activity, so a fresh marker rescues a stale drain-cursor and an absent
    marker harmlessly falls back to the cursor.
    """
    if explicit:
        return Path(explicit).expanduser()
    if cell_yaml_value:
        return Path(cell_yaml_value).expanduser()
    tmpdir = os.environ.get("TMPDIR", "/tmp")
    return Path(tmpdir) / f"{role}-claude-active.txt"


def _resolve_tmux_session(
    role: str,
    explicit: Optional[str],
    cell_yaml_value: Optional[str] = None,
) -> str:
    """Resolve tmux session name with documented fallback chain.

    Precedence (F4 sibling to cursor_path):
      1. Explicit ``--tmux-session`` CLI arg
      2. ``cell.yaml`` extra.tmux_session when --cell present
      3. Role itself (convention default)

    Mother's sibling-instance variant (#1061): when slot-N siblings spawn,
    each slot needs its own tmux session name; the cell.yaml that pins the
    slot SHOULD also pin the tmux_session to keep the watchdog's reads
    consistent with the spawn's writes.
    """
    if explicit:
        return explicit
    if cell_yaml_value:
        return cell_yaml_value
    return role


def _read_cell_yaml_pins(
    role: str,
) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """Best-effort read of cell.yaml extra.cursor_path + extra.tmux_session +
    extra.activity_marker_path.

    Tries the cwd-local ``./cell.yaml`` first (matches hook_output discovery),
    falls back to ``<cells_dir>/<role>.yaml``. Returns (None, None, None) on any
    failure — F4 is additive non-breaking, malformed cell.yaml falls through
    to the legacy convention defaults.

    NOTE: ``cursor_path`` / ``tmux_session`` live in ``Cell.extra`` (forward-
    compat catch-all per swarph-shared v0.3) in v0.7.2. swarph-shared 0.4
    will graduate them to first-class typed fields on ``Cell``; this reader
    will continue to work because graduate-to-typed-field preserves the
    extra-dict reading path (per swarph-shared's documented forward-compat
    discipline).
    """
    from swarph_cli.cell import (
        cells_dir,
        discover_cell_in_cwd,
        load_cell,
        CellError,
    )

    cell_path = discover_cell_in_cwd()
    if cell_path is None:
        candidate = cells_dir() / f"{role}.yaml"
        if candidate.is_file():
            cell_path = candidate
    if cell_path is None:
        return None, None, None

    try:
        cell = load_cell(cell_path)
    except (CellError, OSError):
        return None, None, None

    extra = cell.extra or {}
    cursor_path = extra.get("cursor_path")
    tmux_session = extra.get("tmux_session")
    activity_marker = extra.get("activity_marker_path")
    return (
        str(cursor_path) if cursor_path else None,
        str(tmux_session) if tmux_session else None,
        str(activity_marker) if activity_marker else None,
    )


def _resolve_log_path(explicit: Optional[str]) -> Path:
    if explicit:
        return Path(explicit).expanduser()
    state_root = os.environ.get("XDG_STATE_HOME", "").strip()
    if state_root:
        return Path(state_root) / "swarph" / "watchdog.log"
    return Path.home() / ".local" / "state" / "swarph" / "watchdog.log"


def _resolve_dm_wake_state_path(explicit: Optional[str]) -> Path:
    """Resolve the per-peer dm-wake cooldown state file path.

    Mirrors the watchdog's existing state convention: co-located under
    ``$XDG_STATE_HOME/swarph/`` (same dir as the log + A1 marker), falling
    back to ``~/.local/state/swarph/`` when XDG_STATE_HOME is unset. An
    explicit override (e.g. ``--dm-wake-state`` / injected in tests) wins.
    """
    if explicit:
        return Path(explicit).expanduser()
    state_root = os.environ.get("XDG_STATE_HOME", "").strip()
    if state_root:
        return Path(state_root) / "swarph" / "dm_wake_state.json"
    return Path.home() / ".local" / "state" / "swarph" / "dm_wake_state.json"


def _load_dm_wake_state(path: Path) -> dict:
    """Read the ``{peer_name: last_wake_epoch}`` cooldown map.

    Returns ``{}`` on a missing or corrupt/unreadable file — never raises
    (a state-read failure must not crash the watchdog). Non-dict JSON
    payloads are also treated as empty.
    """
    try:
        with Path(path).open(encoding="utf-8") as fp:
            data = json.load(fp)
    except (FileNotFoundError, OSError, json.JSONDecodeError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _save_dm_wake_state(path: Path, state: dict) -> None:
    """Atomically persist the cooldown map; best-effort (never raises).

    Writes to a temp sibling then ``os.replace`` (atomic on POSIX), mirroring
    the cursor/marker write discipline. Any failure (unwritable dir, etc.) is
    swallowed — a state-write failure must not crash the watchdog.
    """
    path = Path(path)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        with tmp.open("w", encoding="utf-8") as fp:
            json.dump(state, fp, sort_keys=True)
        os.replace(tmp, path)
    except OSError:
        pass



def _gateway_configured(gateway: str) -> bool:
    """False when no gateway is configured — degrade, do not crash.

    #578 removed the baked-in host, so `gateway` can now be "". Every caller here
    builds `urllib.request.Request(f"{gateway}/...")` OUTSIDE its try, and
    Request() rejects a relative URL at CONSTRUCTION with ValueError, before any
    I/O — so nothing catches it.

    That matters most where it is least visible: `_run_local_check` asks for the
    unread count BEFORE the A2 "process dead -> respawn regardless of unread"
    decision, so an uncaught raise kills the tick before it can rescue anything.
    On sys3 today both `swarph-watchdog.timer` and `swarph-watchdog-science.timer`
    run every 5 minutes with `EnvironmentFile=-/etc/default/swarph-watchdog`, and
    THAT FILE DOES NOT EXIST — no MESH_GATEWAY_URL in the unit env at all.

    An unreachable gateway has always degraded to None here. An UNCONFIGURED one
    now does the same, rather than becoming a new crash class.
    Found by drop-on-meta-edge, seat-A review of PR #318.
    """
    return bool((gateway or "").strip())

def _gateway_unread_count(gateway: str, peer: str, token: Optional[str]) -> Optional[int]:
    """Query gateway for unread DM count addressed to peer.

    Returns int count on success; None on any failure — an unreachable gateway,
    a missing/rejected token (no Authorization header is sent when token is
    falsy, so the gateway 401s and that is caught here too), a malformed
    response.

    THIS DOES NOT MEAN "ASSUME UNREAD." The caller's decision matrix treats
    None as F2 FAIL-CLOSED: cursor_stale + process_alive + unread=None -> noop,
    can't verify work, don't poke. A prior version of this docstring claimed
    the opposite ("assume unread, still tries to wake") and was wrong about
    the code it was documenting — found 2026-08-12 when the contradiction
    caused a real reader to conclude a gateway/token outage makes A1 MORE
    eager, when it makes A1 permanently inert for that cell instead.
    """
    if not _gateway_configured(gateway):
        return None
    query = urllib.parse.urlencode({"to_node": peer, "unread_only": "true", "limit": 1})
    url = f"{gateway.rstrip('/')}/messages?{query}"
    req = urllib.request.Request(url)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    else:
        # A missing token and a network outage both surface as None to the
        # caller (correctly — the decision matrix treats them the same way),
        # but they are different FACTS an operator would want to know apart.
        # No token means A1 is permanently inert for this cell until one is
        # configured, not just this tick. Recurrence of the 2026-05-27
        # "watchdog inert for 12 days, no token in service env" incident —
        # loud here so it cannot silently repeat a third time.
        print(f"swarph watchdog: no MESH_GATEWAY_TOKEN for peer={peer} — "
              f"unread-count check may 401 if the gateway requires auth; "
              f"A1 stays inert until one is set",
              file=sys.stderr)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, OSError, json.JSONDecodeError):
        return None
    # Gateway shape varies — handle both list and {"messages": [...]} forms
    if isinstance(data, list):
        return len(data)
    if isinstance(data, dict) and isinstance(data.get("messages"), list):
        return len(data["messages"])
    return None


def _gateway_recent_recovery_event(
    gateway: str,
    peer: str,
    window_sec: int,
    token: Optional[str],
) -> Optional[dict]:
    """Phase 4 (v0.7.6) — query /peer-health-events for a recent recovery event.

    Returns the most recent event whose ``event_type`` is in
    ``_RECOVERY_EVENT_TYPES`` (currently just ``usage_limit_reset``) for
    this peer within the last ``window_sec`` seconds. Returns None if no
    such event exists OR if the query fails (treat absence + error as
    "no override"; the regular cursor-staleness path still applies).

    Why this matters: the lab + drop both hit ``usage_limit_reset`` from
    Claude's quota system — the throttle clears, but the session has no
    autonomous mechanism to notice. DMs queued during the throttle sit
    unread until commander manually chimes the session, OR until the
    30min cursor-staleness threshold trips A1. Phase 4 closes that gap
    by lowering the threshold to ``--peer-health-recovery-threshold``
    (default 2min) once the gateway sees the reset event.

    Detection ≠ recovery distinction: the gateway already CAPTURES these
    events (claude_session_event_logger.py + POST /peer-health-events).
    What was missing was the wake-up mechanism — this function plus the
    fall-through in run_check is the watchdog half of the loop.
    """
    if not _gateway_configured(gateway):
        return None
    since_dt = datetime.now(timezone.utc) - timedelta(seconds=window_sec)
    since_iso = since_dt.isoformat()
    query = urllib.parse.urlencode(
        {"peer": peer, "since": since_iso, "limit": 50},
    )
    url = f"{gateway.rstrip('/')}/peer-health-events?{query}"
    req = urllib.request.Request(url)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, OSError, json.JSONDecodeError):
        return None
    events = data.get("events") if isinstance(data, dict) else None
    if not isinstance(events, list):
        return None
    # Server sorts by time DESC, so the first match is the most recent.
    for ev in events:
        if isinstance(ev, dict) and ev.get("event_type") in _RECOVERY_EVENT_TYPES:
            return ev
    return None


def _parse_last_health(value) -> Optional[float]:
    """Parse a peer's ``last_health`` ISO-8601 string → epoch seconds (UTC).

    Robust to the three observed forms:
      * trailing ``Z`` (Zulu) — normalized to ``+00:00`` before parsing
      * explicit ``+00:00`` offset
      * naive (no tz) — assumed UTC

    Returns None on any failure (absent / empty / non-str / unparseable), so the
    caller can SKIP that peer rather than treat absence-of-data as staleness.
    """
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def _stale_peers(
    peers: list[dict],
    now_epoch: float,
    stale_sec: int,
    exclude: Optional[set[str]] = None,
) -> list[str]:
    """Return names of peers whose last_health is older than stale_sec (idle/stranded
    candidates), excluding any name in ``exclude`` (e.g. self + known laptop-only cells).
    A peer with no/empty/unparseable last_health is SKIPPED (not treated as stale —
    absence of data must not trigger a wake). Returns names sorted, deterministic."""
    exclude = exclude or set()
    out: list[str] = []
    for peer in peers:
        if not isinstance(peer, dict):
            continue
        name = peer.get("name")
        if not name or name in exclude:
            continue
        parsed = _parse_last_health(peer.get("last_health"))
        if parsed is None:
            continue  # absent / unparseable → skip, never treat as stale
        age = now_epoch - parsed
        if age > stale_sec:
            out.append(name)
    return sorted(out)


def _fetch_peers(gateway: str, token: str) -> list[dict]:
    """GET {gateway}/peers (Bearer token). Returns the peer list, or [] on any error
    (never raises). The response may be a bare list OR {"peers": [...]} — handle both."""
    if not _gateway_configured(gateway):
        return None
    url = f"{gateway.rstrip('/')}/peers"
    req = urllib.request.Request(url)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, OSError, json.JSONDecodeError):
        return []
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and isinstance(data.get("peers"), list):
        return data["peers"]
    return []


def _pid_under(pid: int, ancestors: set, _max_depth: int = 40) -> bool:
    """Walk the PPID chain up from ``pid``; True if any ancestor is in
    ``ancestors``. Reads ``/proc/<pid>/stat`` (Linux). The ``comm`` field can
    contain spaces/parens, so parse PPID after the final ``)``."""
    cur = pid
    for _ in range(_max_depth):
        if cur in ancestors:
            return True
        if cur <= 1:
            return False
        try:
            with open(f"/proc/{cur}/stat", encoding="utf-8") as f:
                data = f.read()
            after = data[data.rfind(")") + 2:].split()
            cur = int(after[1])  # stat field 4 (PPID): state, ppid, ...
        except (OSError, ValueError, IndexError):
            return False
    return cur in ancestors


def _process_alive(tmux_session: str, process_name: str = "claude") -> bool:
    """Detect if a `process_name` process is running INSIDE the named tmux session.

    `process_name` (default "claude") is the command the cell's agent runs —
    node/codex cells pass "node", grok cells pass "grok". Scopes to the
    session's pane PIDs (and descendants) rather than a host-wide pgrep: on a
    multi-session host, an unrelated cell's process would otherwise mask THIS
    session's death and suppress the A2 alert. Best-effort; falls back to True
    (assume alive) on detection error so a broken detector never false-fires A2.
    """
    try:
        panes = subprocess.run(
            ["tmux", "list-panes", "-t", tmux_session, "-F", "#{pane_pid}"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=5,
        )
        if panes.returncode != 0:
            # list-panes fails for TWO very different reasons:
            #   (a) the tmux server is reachable but this session is genuinely
            #       gone → really dead → False (let A2 fire).
            #   (b) there is no tmux server reachable from THIS uid (e.g. the
            #       watchdog runs as root while sessions live under ubuntu's
            #       /tmp/tmux-1000 socket) → we simply CAN'T determine liveness
            #       via tmux → must NOT false-fire A2.
            # Distinguish by probing the server itself.
            server = subprocess.run(
                ["tmux", "list-sessions"],
                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=5,
            )
            if server.returncode != 0:
                return True  # no reachable tmux server here → can't tell → assume alive
            return False     # server reachable, session absent → genuinely dead
        pane_pids = {int(p) for p in panes.stdout.split() if p.strip().isdigit()}
        if not pane_pids:
            return True  # ambiguous (session with no pane pids) → don't false-fire

        pg = subprocess.run(
            ["pgrep", "-f", process_name],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=5,
        )
        if pg.returncode != 0:
            return False  # no matching process anywhere on the host
        matched_pids = [int(p) for p in pg.stdout.split() if p.strip().isdigit()]
        # Alive only if a matching process is a descendant of THIS session's panes.
        return any(_pid_under(cpid, pane_pids) for cpid in matched_pids)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError, ValueError):
        return True  # assume alive on detection error


def _liveness_via_cmd(cmd: str) -> bool:
    """Escape-hatch liveness probe: run `cmd`; exit 0 = alive, non-zero = dead.

    For cells whose liveness a process name can't express. Bounded timeout;
    on timeout / OSError assume ALIVE — a broken or slow probe must never
    false-fire the destructive A2 respawn (same fail-safe as _process_alive).
    """
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, timeout=5,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return True


def _tmux_session_exists(name: str) -> bool:
    try:
        result = subprocess.run(
            ["tmux", "has-session", "-t", name],
            capture_output=True, timeout=5,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False


def _resolve_send_target(name: str, process_name: str = "claude") -> str:
    """Resolve a session name to the pane actually running the cell's agent.

    `send-keys -t <session>` lands on the session's ACTIVE pane — on a
    multi-pane cell that can be a bash/log pane, where an injected wake would
    execute as a SHELL command. Prefer the pane whose current command matches
    the cell's `process_name`; then fall back to the claude-CLI heuristic
    (claude runs under node); then to the session name unchanged when tmux is
    unavailable, the listing fails, or no pane matches.
    """
    try:
        result = subprocess.run(
            ["tmux", "list-panes", "-t", name, "-F",
             "#{pane_id} #{pane_current_command}"],
            capture_output=True, timeout=5, text=True, encoding="utf-8", errors="replace",
        )
        if result.returncode != 0:
            return name
        panes = [ln.split() for ln in result.stdout.splitlines()]
        for parts in panes:                       # exact process_name match wins
            if len(parts) >= 2 and parts[1] == process_name:
                return parts[0]
        for parts in panes:                       # claude-CLI fallback (node)
            if len(parts) >= 2 and parts[1] in ("claude", "node"):
                return parts[0]
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    return name


def _tmux_send_keys(
    name: str, text: str, clear_input: bool = False, process_name: str = "claude"
) -> bool:
    """Send `text` + Enter to a tmux target.

    The target is resolved to the claude-TUI pane first (_resolve_send_target,
    drop N3) so multi-pane cells never receive the payload in a shell pane.

    clear_input=True prepends C-u (clear current input line) so the payload
    can never CONCATENATE onto a half-typed buffer — required for the A1.5
    slash-command inject (drop seat-A C2): a prose wake merging into typed
    text is noise, but `/model ...` merging into typed text submits a
    corrupted command.
    """
    target = _resolve_send_target(name, process_name)
    keys = ["C-u", text, "Enter"] if clear_input else [text, "Enter"]
    try:
        result = subprocess.run(
            ["tmux", "send-keys", "-t", target, *keys],
            capture_output=True, timeout=5,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False


def _dm_wake(
    gateway: str,
    self_peer: str,
    target_peer: str,
    token: str,
    content: str,
) -> bool:
    """A1-DM: send a cross-host wake DM to a stranded peer on another host.

    POSTs a mesh DM (kind=fyi) to ``{gateway}/messages``; the target peer's
    sidecar/inbox-watcher then wakes it. Pure send action — never raises (an
    alert/wake path must not crash the watchdog); returns True iff 2xx.
    """
    try:
        body = {
            "from_node": self_peer,
            "to_node": target_peer,
            "kind": "fyi",
            "content": content,
        }
        status, _payload = _post_json(
            f"{gateway.rstrip('/')}/messages",
            body,
            token,
        )
        return 200 <= status < 300
    except Exception:
        return False


def _pane_activity_age_sec(name: str) -> Optional[int]:
    """Age in seconds since the target session's most recent tmux activity.

    Reads tmux activity-timestamp format vars and uses the MOST RECENT
    (max epoch) across pane / window / session. ``#{pane_activity}`` is only
    populated when monitor-activity is on (empty on a default tmux 3.x), so
    relying on it alone made F3 a no-op — it returned None and never
    suppressed A1 for a genuinely-active session (adversarial-deploy finding
    2026-06-02). ``#{window_activity}`` / ``#{session_activity}`` are tracked
    unconditionally and give the same "is this session alive right now" signal.

    Used by F3 (mother #1087) as a third AND-gate input to distinguish (a) a
    session genuinely stalled from (b) one actively working in a long bash
    block where cursor-mtime (last turn-end) is stale but the session is alive.

    Returns None only when NO activity timestamp is parseable (tmux missing /
    session absent), so the caller falls through to the legacy AND-gate.
    """
    try:
        result = subprocess.run(
            ["tmux", "display", "-p", "-t", name,
             "#{pane_activity}|#{window_activity}|#{session_activity}"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=5,
        )
        if result.returncode != 0:
            return None
        epochs = []
        for tok in result.stdout.strip().split("|"):
            tok = tok.strip()
            if tok.isdigit():
                epochs.append(int(tok))
        if not epochs:
            return None
        return max(0, _now() - max(epochs))
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError, ValueError):
        return None


def _tmux_kill_session(name: str) -> bool:
    try:
        result = subprocess.run(
            ["tmux", "kill-session", "-t", name],
            capture_output=True, timeout=5,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False


def _spawn_via_swarph(role: str, tmux_session: str) -> bool:
    """A2 escalation: kill stale tmux + respawn via `swarph spawn`.

    Reuses sidecar UUID (R5 fix) so fresh sibling takes over the same
    /resume picker slot. Cell-yaml-driven cwd, starter prompt, etc.
    """
    if _tmux_session_exists(tmux_session):
        _tmux_kill_session(tmux_session)

    swarph_bin = os.environ.get("SWARPH_BIN", "swarph")
    spawn_cmd = (
        f"tmux new -d -s {shlex.quote(tmux_session)} "
        f"{shlex.quote(swarph_bin)} spawn {shlex.quote(role)}"
    )
    try:
        result = subprocess.run(
            spawn_cmd, shell=True,
            capture_output=True, timeout=15,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False


def _a1_marker_path(log_path: Path, role: str, tmux_session: Optional[str] = None) -> Path:
    """Marker file recording the cursor_mtime at which A1 was last fired.

    Co-located with the watchdog log so it inherits the same XDG_STATE_HOME
    discipline. Cleared on cursor-advance OR A2 escalation. Used to suppress
    repeat A1 fires within the same stale window — fix for the spam incident
    where cron fired A1 every 5min for 65min into an active session's tmux
    input buffer (commander #1092 + droplet #1087).

    Keyed on ``(role, tmux_session)`` post-F4 so sibling-instance patterns
    (alpha+beta drop-on-meta-edge per project_drop_mitosis_to_meta_edge)
    don't clobber each other's markers — mother's flag from #1103 closed in
    v0.7.2. tmux_session is sanitized to alphanumeric + ``-_.`` for the
    filename to avoid path-traversal or weird characters from cell.yaml-
    pinned values.

    NOTE (mother #1138 sanitization edge case): two siblings whose
    ``tmux_session`` values differ ONLY in disallowed characters (e.g.,
    ``cell:a`` vs ``cell:b`` — colons sanitized to ``_`` collapsing both
    to ``cell_a`` / ``cell_b`` — fine in this example, but ``cell:a`` vs
    ``cell$a`` would both collapse to ``cell_a``) would collide post-
    sanitization. cell.yaml-pinned ``tmux_session`` values SHOULD differ
    in alphanumeric content, not just punctuation. Cosmetic in practice
    (operators don't choose session names that close), but worth knowing.
    """
    safe_tmux = "".join(
        c if (c.isalnum() or c in "-_.") else "_"
        for c in (tmux_session or role)
    )
    return log_path.parent / f"a1-fired-{role}-{safe_tmux}.marker"


def _a1_already_fired_at(marker: Path, cursor_mtime: int) -> bool:
    """Returns True if a previous A1 was fired with this exact cursor_mtime.

    Same cursor_mtime ⇒ no cursor advance since last fire ⇒ we're still in
    the same stale window ⇒ another A1 would spam. Suppresses the fire.
    """
    try:
        return int(marker.read_text().strip()) == cursor_mtime
    except (FileNotFoundError, OSError, ValueError):
        return False


def _record_a1_fired(marker: Path, cursor_mtime: int) -> None:
    """Best-effort marker write; failures are logged elsewhere but never block."""
    try:
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text(str(cursor_mtime))
    except OSError:
        pass


def _clear_a1_marker(marker: Path) -> None:
    """Idempotent marker removal. Called on A2 escalation paths."""
    try:
        marker.unlink()
    except (FileNotFoundError, OSError):
        pass


def _model_swap_marker_path(
    log_path: Path, role: str, tmux_session: Optional[str] = None
) -> Path:
    """Marker recording the cursor_mtime at which A1.5 last injected /model.

    Distinct file from the A1 marker (``a1-fired-*`` vs ``a15-model-*``) so the
    two rungs track their own same-window state independently. Same XDG_STATE_HOME
    co-location + (role, tmux_session) keying + sanitization discipline as the A1
    marker, so sibling-instance patterns don't collide and cell.yaml-pinned
    session names with odd characters can't break the filename.

    The ladder reads this marker to decide A1.5-vs-A2: if A1 has exhausted
    (its marker matches cursor_mtime) AND this A1.5 marker does NOT yet match,
    the model-swap fires (and stamps this marker); if BOTH match, the model-swap
    has already been tried this window without the cursor advancing, so the
    ladder escalates to A2. Cleared on the A2 paths alongside the A1 marker, so
    a respawned/recovered session starts the ladder fresh.
    """
    safe_tmux = "".join(
        c if (c.isalnum() or c in "-_.") else "_"
        for c in (tmux_session or role)
    )
    return log_path.parent / f"a15-model-{role}-{safe_tmux}.marker"


def _history_path(
    log_path: Path, role: str, tmux_session: Optional[str], kind: str
) -> Path:
    """Cross-window event-history file (circuit-breaker state). Same keying +
    sanitization discipline as the markers; `kind` is 'a15-swaps' or
    'a2-respawns'."""
    safe_tmux = "".join(
        c if (c.isalnum() or c in "-_.") else "_"
        for c in (tmux_session or role)
    )
    return log_path.parent / f"{kind}-{role}-{safe_tmux}.json"


def _load_recent_events(path: Path, window_sec: int, now: int) -> tuple:
    """Return (timestamps-within-window, blind).

    `blind` is True only for CHRONIC unreadability — the history file EXISTS
    but cannot be read (OSError/PermissionError: read-only rootfs, NFS perms,
    tmpfs quota). Distinct from a legit FileNotFound (first run) or a
    corrupt/empty JSON (a write overwrites it) — both return ([], False) and
    are NOT breaker-blind.

    Why the distinction matters (drop seat-A, PR #60): the breakers degrade to
    the bounded per-window baseline on a lost history (fail-open is right — a
    recovery tool must not brick a recoverable cell). BUT a PERMANENTLY
    unreadable history pins len(recent) at 0 forever, so the loud circuit-open
    can never fire — the breaker goes SILENTLY blind. Surfacing `blind` lets
    the caller emit the same loud signal the circuit-open path emits, so a
    dead breaker is visible instead of a no-op."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return [], False  # legit first run — not blind
    except (json.JSONDecodeError, ValueError):
        return [], False  # corrupt/empty — a write overwrites it; not blind
    except OSError:
        return [], True   # file exists but unreadable — BREAKER BLIND
    if not isinstance(data, list):
        return [], False
    fresh = [t for t in data if isinstance(t, (int, float)) and now - t <= window_sec]
    return fresh, False


def _signal_breaker_blind(
    args: argparse.Namespace, role: str, which: str, diag: dict
) -> None:
    """Loud signal that a cross-window circuit breaker can't read its history
    (drop seat-A, PR #60). Gives a blind breaker the SAME visibility the
    circuit-OPEN path gets: a distinct stderr line + diag flag + an N1 emit.
    Dedup across ticks is impossible by construction — the would-be dedup
    store lives in the same unwritable dir — so on a chronically-broken host
    this recurs every tick. That is the correct failure mode for a recovery
    tool: a blind breaker is a standing emergency, not a one-time blip."""
    diag["breaker_blind"] = which
    print(
        f"[watchdog] BREAKER BLIND ({which}) for {role}: circuit-breaker "
        f"history unreadable — cross-window bound degraded to per-window "
        f"baseline; the loud circuit-open can NOT fire. Check state-dir perms "
        f"(read-only rootfs / NFS / tmpfs quota).",
        file=sys.stderr,
    )
    _notify_peer_event(
        args, role, "breaker_blind",
        f"which={which} — circuit history unreadable, breaker degraded; "
        f"operator attention required", diag,
    )


def _append_event(path: Path, now: int, recent: list) -> None:
    """Persist pruned history + the new event. Best-effort by design — the
    per-window marker (verify-after-write) carries the hard bound; history
    only widens it across windows."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(recent + [now]), encoding="utf-8")
    except OSError:
        pass


def _notify_peer_event(
    args: argparse.Namespace, role: str, event: str, detail: str, diag: dict
) -> None:
    """N1 observability (drop seat-A): an autonomous engine-swap / respawn /
    circuit-open changes a cell's engine, billing, and identity surface — it
    must be VISIBLE beyond a local log file, or a silent auto-swap-to-stable
    can mask frontier-engine degradation indefinitely. Opt-in via
    --notify-peer <peer>: POSTs a mesh DM through the same gateway machinery
    as --dm-wake.

    FIXED-TEMPLATE discipline (same as the inject payload): `detail` is built
    by the call sites from config-validated values only — no peer/inbox/
    network-derived string is ever interpolated. Best-effort by construction:
    a notify failure must never block or fail the recovery ladder.
    """
    peer = getattr(args, "notify_peer", None)
    if not peer:
        return
    token = os.environ.get("MESH_GATEWAY_TOKEN")
    if not token:
        diag["notify_skipped"] = "no_token"
        return
    content = (
        f"watchdog event={event} cell={role} {detail} "
        f"(autonomous ladder action; watchdog log on host has the diag)"
    )
    diag["notify_peer"] = peer
    diag["notify_sent"] = _dm_wake(args.gateway, role, peer, token, content)


def _escalate_a2(
    args: argparse.Namespace,
    diag: dict,
    log_path: Path,
    role: str,
    tmux_session: Optional[str],
    marker: Path,
    model_marker: Path,
    a2_reason: str,
    verbose: bool,
) -> int:
    """The SINGLE A2 escalation funnel. Every rung failure lands here
    (model_rung_exhausted / a15_send_failed / a15_marker_unverified /
    a15_thrash_circuit) — fail toward respawn, never toward re-inject.

    Includes the C3 respawn circuit (drop seat-A): when BOTH engines are
    degraded, each respawn lands on a crushed default model and the whole
    ladder repeats across windows. >= max respawns within the window ⇒ STOP
    respawning (circuit open, exit 6) and demand operator attention — a held
    cell is recoverable; a respawn-churned one bleeds state every cycle.
    """
    _clear_a1_marker(marker)
    _clear_a1_marker(model_marker)
    diag["decision"] = f"a2_respawn_{a2_reason}"
    if args.no_respawn:
        diag["dry_run_skip"] = True
        _log_event(log_path, "a2_dry_run", diag, verbose)
        return 2
    respawn_hist = _history_path(log_path, role, tmux_session, "a2-respawns")
    now = _now()
    recent, respawn_blind = _load_recent_events(
        respawn_hist,
        getattr(args, "a2_respawn_window_sec", _DEFAULT_A2_RESPAWN_WINDOW_SEC),
        now,
    )
    if respawn_blind:
        _signal_breaker_blind(args, role, "a2_respawn", diag)
    diag["a2_recent_respawns"] = len(recent)
    if len(recent) >= getattr(args, "a2_max_respawns", _DEFAULT_A2_MAX_RESPAWNS):
        diag["decision"] = "a2_circuit_open"
        print(
            f"[watchdog] A2 CIRCUIT OPEN for {role}: {len(recent)} respawns "
            f"in window — refusing to respawn-churn; operator attention "
            f"required (clear {respawn_hist} to reset).",
            file=sys.stderr,
        )
        _notify_peer_event(
            args, role, "a2_circuit_open",
            f"reason={a2_reason} recent_respawns={len(recent)} — HELD, "
            f"operator attention required", diag,
        )
        _log_event(log_path, "a2_circuit_open", diag, verbose)
        return 6
    _append_event(respawn_hist, now, recent)
    spawn_ok = _spawn_via_swarph(role, tmux_session)
    diag["spawn_ok"] = spawn_ok
    _notify_peer_event(
        args, role, "a2_respawn",
        f"reason={a2_reason} spawn_ok={spawn_ok}", diag,
    )
    _log_event(log_path, "a2_respawn", diag, verbose)
    return 2 if spawn_ok else 4


# The last_health PRODUCER (mesh-hygiene #26). Set once per run by run_check when
# --emit-health is passed; a callable `(decision:str) -> None` that POSTs the verdict
# to the gateway. Process-scoped (the watchdog is a one-shot CLI invocation), so the
# gateway TOKEN lives in this closure — never in the diag dict — and cannot leak into
# the JSONL log. None = emit disabled (default, and every existing install).
_HEALTH_EMITTER = None


def _health_status_for(decision: str) -> str:
    """Map a watchdog verdict to the coarse status the gateway/consumer thresholds on.
    A healthy check or a no-op (ran, nothing to do) = 'healthy'; anything that took or
    would take a recovery action, or couldn't verify, = 'degraded'."""
    if decision.startswith("healthy") or decision.startswith("noop_no_unread") \
            or decision.startswith("noop_pane_activity") or decision.startswith("noop_a1"):
        return "healthy"
    if decision.startswith("noop"):
        # noop_unread_unknown = fail-closed couldn't-verify → not healthy, not action.
        return "degraded"
    return "degraded"


def _emit_health(gateway: str, peer: str, token, decision: str) -> None:
    """POST this cell's health verdict to the gateway. Best-effort: NEVER raises and
    NEVER affects the check's exit code — observability must not break the watchdog."""
    if not token:
        return  # can't authenticate; silently skip
    try:
        _post_json(
            f"{gateway.rstrip('/')}/peers/{peer}/health",
            {"status": _health_status_for(decision), "detail": decision},
            token,
        )
    except Exception:
        pass


def _log_event(log_path: Path, event: str, details: dict, verbose: bool = False) -> None:
    # PRODUCER hook (#26): a decision-bearing event emits this cell's health, once per
    # run (each check path logs exactly one terminal event). Guarded + swallowed so a
    # broken emitter can never stop the log line from being written.
    if _HEALTH_EMITTER is not None and details.get("decision"):
        try:
            _HEALTH_EMITTER(details["decision"])
        except Exception:
            pass
    log_path.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "ts": _now(),
        "event": event,
        "details": details,
    }
    line = json.dumps(entry, sort_keys=True) + "\n"
    try:
        with log_path.open("a", encoding="utf-8") as fp:
            fp.write(line)
    except OSError as exc:
        # Logging failure shouldn't block the watchdog itself
        print(f"swarph watchdog: log write failed: {exc}", file=sys.stderr)
    if verbose:
        print(line, file=sys.stderr, end="")


def _dm_wake_scan(
    args: argparse.Namespace,
    log_path: Path,
    now_epoch: Optional[int] = None,
) -> int:
    """A1-DM mesh-monitor scan (T3). Wakes stranded peers on OTHER hosts.

    When ``--dm-wake`` is set, the watchdog also acts as the mesh's wake
    source: it fetches the gateway peer list, finds peers whose ``last_health``
    is staler than the session staleness threshold (excluding SELF — the
    watchdog's own cell is covered by the local A1/A2 path), and sends each a
    wake DM (``_dm_wake`` → POST /messages). Reuses the SAME gateway-URL +
    token plumbing as ``--peer-health-poll`` (``args.gateway`` +
    ``MESH_GATEWAY_TOKEN``) and the SAME ``--threshold`` staleness window the
    local session check uses.

    T4 — per-peer no-spam cooldown. A peer that stays stale across many ticks
    is DM'd ONCE per ``--dm-wake-cooldown-sec`` window, not every tick. The
    cooldown state ``{peer: last_wake_epoch}`` is loaded once at scan start;
    inside the loop a peer is SKIPPED while ``now - last_wake < cooldown_sec``
    (a cooldown-skip does NOT count as a wake). Only a SUCCESSFUL ``_dm_wake``
    stamps the cooldown; the state is saved once after the loop.

    ``now_epoch`` defaults to ``_now()`` (injectable for deterministic tests).

    Returns the count of wake DMs that fired successfully THIS tick (0 if none
    / if ``--dm-wake`` is off / if every stale peer was within cooldown). Never
    raises (an alert path must not crash the watchdog).
    """
    if not args.dm_wake:
        return 0

    if now_epoch is None:
        now_epoch = _now()

    role = args.cell
    self_peer = args.peer or role
    gateway = args.gateway
    token = os.environ.get("MESH_GATEWAY_TOKEN")
    stale_sec = args.threshold
    cooldown_sec = getattr(
        args, "dm_wake_cooldown_sec", _DEFAULT_DM_WAKE_COOLDOWN_SEC
    )
    state_path = _resolve_dm_wake_state_path(
        getattr(args, "dm_wake_state_path", None)
    )

    peers = _fetch_peers(gateway, token or "")
    # Exclude SELF — never DM-wake yourself; the watchdog's own cell is
    # covered by the local A1/A2 send-keys/respawn path. Both the peer name
    # and the cell role are excluded (they coincide by default, but a custom
    # --peer must not leave the role addressable as a cross-host target).
    exclude = {self_peer, role}
    stale = _stale_peers(peers, now_epoch, stale_sec, exclude=exclude)

    # T4 — load the per-peer cooldown map once at scan start.
    state = _load_dm_wake_state(state_path)

    fired = 0
    skipped: list[str] = []
    for target in stale:
        last_wake = state.get(target, 0)
        if now_epoch - last_wake < cooldown_sec:
            # Within cooldown — already DM'd this peer recently. Skip; a
            # cooldown-skip must NOT count toward the exit-3 wake tally.
            skipped.append(target)
            continue
        if _dm_wake(gateway, self_peer, target, token or "", _DM_WAKE_PROMPT):
            # Only a SUCCESSFUL DM starts the cooldown — a failed send must
            # be retried next tick, not suppressed.
            state[target] = now_epoch
            fired += 1

    # Persist the (possibly-updated) cooldown map once after the loop.
    _save_dm_wake_state(state_path, state)

    _log_event(
        log_path,
        "dm_wake_scan",
        {
            "self_peer": self_peer,
            "stale_peers": stale,
            "skipped_cooldown": skipped,
            "wakes_fired": fired,
            "cooldown_sec": cooldown_sec,
        },
        args.verbose,
    )
    return fired


def run_check(args: argparse.Namespace) -> int:
    """Entry point. Runs the local own-session decision FIRST (A1/A2/noop,
    exit 0/1/2/3/4 — byte-for-byte unchanged), then layers the ``--dm-wake``
    mesh-monitor scan on top.

    Exit precedence (T3): the local own-session action wins. If the local
    decision took a real action or errored (rc != 0), that code is returned
    unchanged — the dm-wake scan is an ADDITIONAL mesh-monitor action and
    must not suppress or be suppressed by the local signal. ONLY when the
    local decision was a no-op (rc == 0) AND at least one cross-host wake DM
    fired do we surface exit 3 (A1-DM). When ``--dm-wake`` is off the scan is
    a pure no-op, so the 0/1/2 behavior is preserved exactly.
    """
    log_path = _resolve_log_path(args.log)
    global _HEALTH_EMITTER
    if getattr(args, "emit_health", False):
        _gw, _peer = args.gateway, (args.peer or args.cell)
        _tok = os.environ.get("MESH_GATEWAY_TOKEN")
        _HEALTH_EMITTER = lambda dec: _emit_health(_gw, _peer, _tok, dec)  # noqa: E731
    try:
        local_rc = _run_local_check(args)
        wakes_fired = _dm_wake_scan(args, log_path)
    finally:
        _HEALTH_EMITTER = None
    if local_rc == 0 and wakes_fired > 0:
        return 3
    return local_rc


def _run_local_check(args: argparse.Namespace) -> int:
    role = args.cell
    # F4 — cell.yaml-pinned cursor_path + tmux_session (mother #1057/#1060
    # + beta #1061/#1065). Reads cell.yaml `extra.cursor_path` /
    # `extra.tmux_session` when --cell is provided; explicit CLI args still
    # win. Best-effort: malformed cell.yaml falls through to legacy
    # convention defaults (additive non-breaking).
    cell_cursor, cell_tmux, cell_activity = _read_cell_yaml_pins(role)
    cursor = _resolve_cursor_path(role, args.cursor, cell_cursor)
    tmux_session = _resolve_tmux_session(role, args.tmux_session, cell_tmux)
    log_path = _resolve_log_path(args.log)
    threshold = args.threshold
    pane_activity_threshold = args.pane_activity_threshold
    peer = args.peer or role
    gateway = args.gateway
    token = os.environ.get("MESH_GATEWAY_TOKEN")
    verbose = args.verbose

    diag = {
        "role": role,
        "cursor": str(cursor),
        "threshold_sec": threshold,
        "tmux_session": tmux_session,
        "peer": peer,
        "pane_activity_threshold_sec": pane_activity_threshold,
        "cell_yaml_pinned_cursor": cell_cursor is not None,
        "cell_yaml_pinned_tmux": cell_tmux is not None,
    }

    # PRIMARY signal: liveness = FRESHEST mtime of {drain-cursor, turn-activity
    # marker}. The cursor is often the inbox-DRAIN cursor (touched only on drain)
    # → it goes stale during active non-draining work and false-fires recovery
    # (feedback_watchdog_liveness_proxy). The Stop-hook marker is touched every
    # turn-end. A fresh marker rescues a stale cursor; an absent/unreadable marker
    # harmlessly falls back to the cursor (no change for cells without it).
    activity_marker = _resolve_activity_marker_path(
        role, getattr(args, "activity_marker", None), cell_activity
    )
    diag["activity_marker"] = str(activity_marker)
    _live_mtimes = [
        m for m in (_stat_mtime(cursor), _stat_mtime(activity_marker)) if m is not None
    ]
    cursor_mtime = max(_live_mtimes) if _live_mtimes else None
    if cursor_mtime is None:
        diag["error"] = f"cursor file unreadable: {cursor} (and marker {activity_marker})"
        _log_event(log_path, "error", diag, verbose)
        return 3
    cursor_age = _now() - cursor_mtime
    diag["cursor_age_sec"] = cursor_age

    if cursor_age <= threshold:
        # Phase 4 (v0.7.6) — peer-health-event override. If the gateway
        # observed a recent recovery event (usage_limit_reset) for this
        # peer AND the cursor is at least somewhat stale, fall through
        # to the A1 path so an idle-after-reset session gets nudged.
        # When --peer-health-poll is OFF, behavior is identical to v0.7.5.
        if args.peer_health_poll:
            recovery_event = _gateway_recent_recovery_event(
                gateway, peer, args.peer_health_window_sec, token,
            )
            diag["peer_health_poll"] = True
            diag["recovery_event_seen"] = bool(recovery_event)
            if recovery_event:
                diag["recovery_event_type"] = recovery_event.get("event_type")
                diag["recovery_event_time"] = recovery_event.get("time")
            if recovery_event and cursor_age > args.peer_health_recovery_threshold:
                # Promote to wake-candidate. Don't return — fall through
                # below to the existing process_alive / unread / F1-F3
                # gates, which still get a vote. This is a threshold
                # override, not a gate bypass.
                diag["phase4_override"] = "fall_through_to_a1"
            else:
                # Either no recovery event, OR cursor is fresh enough
                # that the session is likely self-recovering. No action.
                diag["decision"] = (
                    "healthy_cursor_fresh_recovery_too_recent"
                    if recovery_event
                    else "healthy_cursor_fresh"
                )
                _log_event(log_path, "noop", diag, verbose)
                return 0
        else:
            # Cursor recent — Claude has been active. No action.
            diag["decision"] = "healthy_cursor_fresh"
            _log_event(log_path, "noop", diag, verbose)
            return 0

    # FALLBACK signal: pgrep claude (per mother #1021 AND-gate)
    if args.liveness_cmd:
        process_alive = _liveness_via_cmd(args.liveness_cmd)
    else:
        process_alive = _process_alive(tmux_session, args.process_name)
    diag["process_alive"] = process_alive

    # Check unread DM queue at gateway. If no unread DMs, no need to wake.
    unread = _gateway_unread_count(gateway, peer, token)
    diag["unread_count"] = unread

    # Decision matrix (post commander #1092 + droplet #1087 + #1089 hardening):
    # cursor_stale + not process_alive            → A2 (dead, respawn regardless of unread)
    # cursor_stale + process_alive + unread > 0   → A1 (alive but throttled, prompt may unblock)
    # cursor_stale + process_alive + unread = 0   → noop (no DMs to drain anyway)
    # cursor_stale + process_alive + unread None  → noop (F2 fail-closed: can't verify work, don't poke)
    # cursor_stale + a1_marker matches cursor_mtime → noop (F1 same-window suppression)

    marker = _a1_marker_path(log_path, role, tmux_session)
    model_marker_early = _model_swap_marker_path(log_path, role, tmux_session)
    diag["a1_marker"] = str(marker)

    if not process_alive:
        # A2 escalation — clear BOTH rung markers so the next A1 (after respawn)
        # fires and the ladder restarts cleanly from A1.
        _clear_a1_marker(marker)
        _clear_a1_marker(model_marker_early)
        diag["decision"] = "a2_respawn_process_dead"
        if args.no_respawn:
            diag["dry_run_skip"] = True
            _log_event(log_path, "a2_dry_run", diag, verbose)
            return 2
        spawn_ok = _spawn_via_swarph(role, tmux_session)
        diag["spawn_ok"] = spawn_ok
        _log_event(log_path, "a2_respawn", diag, verbose)
        return 2 if spawn_ok else 4

    # Process is alive but cursor is stale.
    # F2 — fail-closed when unread can't be verified. Trade false-negative for
    # false-positive ("respect peer-time when uncertain" per droplet #1089).
    # Production incident shape (commander #1092): gateway returned None for
    # unread; old code fell through to A1, spamming the tmux buffer for 65min.
    if unread is None:
        diag["decision"] = "noop_unread_unknown"
        _log_event(log_path, "noop", diag, verbose)
        # rc 7 = couldn't-verify (#401): distinct from healthy (0), action
        # taken (1/2/5), input error (3), action failed (4), circuit open
        # (6). Declining to act on unknown state is right; reporting SUCCESS
        # on the one channel a cron line reads is not — an exit-0 here hid a
        # fleet-wide watchdog-coverage gap for 13 days.
        return 7

    if unread == 0:
        diag["decision"] = "noop_no_unread"
        _log_event(log_path, "noop", diag, verbose)
        return 0

    if not _tmux_session_exists(tmux_session):
        # Process alive somewhere but tmux session gone — partial state.
        # Treat as A2 case: respawn fresh sibling.
        _clear_a1_marker(marker)
        _clear_a1_marker(model_marker_early)
        diag["tmux_missing"] = True
        diag["decision"] = "a2_respawn_tmux_missing"
        if args.no_respawn:
            _log_event(log_path, "a2_dry_run", diag, verbose)
            return 2
        spawn_ok = _spawn_via_swarph(role, tmux_session)
        diag["spawn_ok"] = spawn_ok
        _log_event(log_path, "a2_respawn", diag, verbose)
        return 2 if spawn_ok else 4

    # F3 — tmux pane_activity AND-gate (mother #1087). cursor-mtime measures
    # "time since last turn-end" not "time since last activity"; mid-long-
    # turn cursor is stale even though session is maximally alive. tmux's
    # `#{pane_activity}` covers the mid-turn-active case. If the pane has
    # had activity within `pane_activity_threshold_sec`, suppress ANY rung
    # (A1 *and* A1.5) — the session is working, not stalled. Falls through to
    # firing when pane_activity is None (tmux missing / older tmux without the
    # format) so F3 is a strengthening of the gate, not a hard dependency.
    #
    # F3 is evaluated BEFORE the F1/A1.5 decision so the A1.5 model-swap rung
    # also respects it (SAFETY 3: harmless-if-idle — never inject /model into a
    # session that's actively working).
    pane_age = _pane_activity_age_sec(tmux_session)
    diag["pane_activity_age_sec"] = pane_age
    if pane_age is not None and pane_age < pane_activity_threshold:
        diag["decision"] = "noop_pane_activity_recent"
        _log_event(log_path, "noop", diag, verbose)
        return 0

    # F1 / A1.5 — same-stale-window escalation. If A1 already fired at this
    # exact cursor_mtime, another A1 would only stack wake-prompts in the tmux
    # input buffer (commander #1092: 13 fires across 65min). The cursor has not
    # advanced since A1 fired ⇒ the cell is GENUINELY stalled, not merely idle.
    # This is the escalation point: A1 (wake) → A1.5 (/model-swap) → A2 (respawn).
    if _a1_already_fired_at(marker, cursor_mtime):
        model_marker = _model_swap_marker_path(log_path, role, tmux_session)
        diag["model_swap_marker"] = str(model_marker)
        # A1.5 FAIL-SAFE (2026-06-11 incident): the /model-swap rung is OPT-IN.
        # A stale cursor on a LIVE process is an AMBIGUOUS signal — an idle cell
        # waiting at a prompt is indistinguishable from a genuinely stalled one
        # by cursor-mtime + pane-activity alone. Injecting /model on that
        # ambiguity false-fired across 5 cells (lab / droplet / science-claude /
        # gpu-wsl / drop-on-meta-edge), restarting live sessions. A disruptive
        # action must never be the DEFAULT on an ambiguous signal — the recovery
        # layer fails safe to inaction. The rung now requires explicit
        # --model-rung; --no-model-rung still force-disables on top of that.
        model_rung_enabled = (
            getattr(args, "model_rung", False)
            and not getattr(args, "no_model_rung", False)
        )
        diag["model_rung_enabled"] = model_rung_enabled

        if not model_rung_enabled:
            # Rung disabled — legacy F1 behavior: A1-already-fired is a plain
            # same-window noop. The ladder falls straight A1 → A2 (A2 only
            # fires on the dead-process / tmux-missing paths above).
            diag["decision"] = "noop_a1_already_fired_this_window"
            _log_event(log_path, "noop", diag, verbose)
            return 0

        # SAFETY 4 — fail-safe-to-A2 (drop seat-A, PR #58 BLOCK-1/BLOCK-2):
        # every failure of the rung's BOUNDING mechanism below escalates to
        # A2 in the SAME tick. The once-per-window bound must never rest on
        # a best-effort marker alone — a failure in the bounding mechanism
        # fails toward respawn, never open toward unbounded /model re-inject.
        a2_reason = "model_rung_exhausted"
        if not _a1_already_fired_at(model_marker, cursor_mtime):
            if pane_age is None:
                # SAFETY 3b (drop seat-A C2): the slash-command rung requires
                # READABLE pane state. A1's prose wake falls through harmlessly
                # when tmux can't report pane_activity, but injecting `/model`
                # into an unverifiable pane (ancient tmux, missing format) is
                # actively harmful — skip the rung; this window behaves as
                # --no-model-rung. A2 remains reachable via the dead-process /
                # tmux-missing paths above.
                diag["decision"] = "noop_a15_no_pane_state"
                _log_event(log_path, "noop", diag, verbose)
                return 0
            # C1 thrash circuit (drop seat-A): a flapping cursor restarts the
            # ladder every window, so the per-window bound alone lets A1.5
            # fire forever while A2 never engages. Too many recent swaps ⇒
            # the swap demonstrably isn't recovering the cell ⇒ escalate.
            swap_hist = _history_path(log_path, role, tmux_session, "a15-swaps")
            now = _now()
            recent_swaps, swap_blind = _load_recent_events(
                swap_hist, getattr(args, "a15_swap_window_sec",
                                   _DEFAULT_A15_SWAP_WINDOW_SEC), now)
            if swap_blind:
                _signal_breaker_blind(args, role, "a15_thrash", diag)
            diag["a15_recent_swaps"] = len(recent_swaps)
            if len(recent_swaps) >= getattr(
                args, "a15_max_swaps", _DEFAULT_A15_MAX_SWAPS
            ):
                a2_reason = "a15_thrash_circuit"
                return _escalate_a2(args, diag, log_path, role, tmux_session,
                                    marker, model_marker, a2_reason, verbose)
            # A1.5 — autonomous engine-swap. A1 has exhausted but the model
            # swap has NOT yet been tried this window. Inject `/model <stable>`.
            #
            # SAFETY 1 (fixed-template injection): `stable_model` is a hard-coded
            # constant or the `--stable-model` config flag — NEVER derived from
            # peer DM / inbox / network data. `unread`, `recovery_event`, and
            # every other message-shaped value computed above are deliberately
            # NOT referenced here. The payload is the constant template only,
            # and even the config value must match the model-id allowlist
            # (_STABLE_MODEL_RE) before it reaches the TUI — a malformed
            # override falls back to the known-good default.
            # SAFETY 2 (not peer-triggerable): we reach this branch solely on
            # the LOCAL cursor-stall health signal (A1 marker matches
            # cursor_mtime). No message content gates it.
            stable_model = getattr(args, "stable_model", _DEFAULT_STABLE_MODEL)
            if not _STABLE_MODEL_RE.fullmatch(stable_model):
                diag["stable_model_rejected"] = stable_model
                stable_model = _DEFAULT_STABLE_MODEL
            model_text = f"/model {stable_model}"
            diag["stable_model"] = stable_model
            diag["model_swap_text"] = model_text
            print(
                f"[watchdog] A1.5 model-swap: injecting "
                f"{model_text} into {tmux_session}",
                file=sys.stderr,
            )
            sent = _tmux_send_keys(tmux_session, model_text, clear_input=True,
                                   process_name=args.process_name)
            diag["send_keys_ok"] = sent
            if not sent:
                # BLOCK-1 fix: a FAILED inject (wedged / timing-out pane) is
                # exactly the respawn case. Re-trying A1.5 next tick would
                # leave A2 permanently unreachable behind a pane that cannot
                # accept input. Escalate NOW.
                a2_reason = "a15_send_failed"
            else:
                _record_a1_fired(model_marker, cursor_mtime)
                if not _a1_already_fired_at(model_marker, cursor_mtime):
                    # BLOCK-2 fix: the stamp did not persist (unwritable state
                    # dir / full disk / swallowed OSError) — the once-per-window
                    # bound is GONE and the next tick would re-inject /model
                    # unboundedly. Verify-after-write; on failure escalate NOW.
                    a2_reason = "a15_marker_unverified"
                else:
                    # Marker stamped AND verified: the NEXT tick (if the cursor
                    # still hasn't advanced) escalates to A2 rather than
                    # re-injecting /model. Record the swap in the cross-window
                    # history so the C1 thrash circuit can count it.
                    _append_event(swap_hist, now, recent_swaps)
                    diag["decision"] = "a15_model_swap"
                    _notify_peer_event(
                        args, role, "a15_model_swap",
                        f"engine swapped via /model to {stable_model}", diag,
                    )
                    _log_event(log_path, "a15_model_swap", diag, verbose)
                    return 5

        # A2 — the single escalation funnel (incl. the C3 respawn circuit).
        # Reached when the model-swap was already tried this window without
        # the cursor advancing (model_rung_exhausted), OR same-tick when the
        # rung's bounding mechanism itself failed (a15_send_failed /
        # a15_marker_unverified).
        return _escalate_a2(args, diag, log_path, role, tmux_session,
                            marker, model_marker, a2_reason, verbose)

    diag["decision"] = "a1_send_keys"
    wake_text = (
        f"watchdog wake — cursor stale {cursor_age}s, "
        f"unread={unread}; please drain inbox"
    )
    sent = _tmux_send_keys(tmux_session, wake_text, process_name=args.process_name)
    diag["send_keys_ok"] = sent
    if sent:
        _record_a1_fired(marker, cursor_mtime)
    _log_event(log_path, "a1_send_keys", diag, verbose)
    return 1 if sent else 4


_SYSTEMD_UNIT_DIR = Path("/etc/systemd/system")
_SYSTEMD_DEFAULT_DIR = Path("/etc/default")
_SYSTEMD_UNIT_NAMES = ("swarph-watchdog.service", "swarph-watchdog.timer")
_SYSTEMD_DEFAULT_NAME = "swarph-watchdog"  # /etc/default/swarph-watchdog
# v0.7.3 bundled template's ExecStart placeholder — substituted at install time
# by `_resolve_swarph_bin()` to the actual binary path on the install host.
# Fixes the v0.7.3 hardcode that broke pipx-installed peers (binary at
# ~/.local/bin/swarph not /usr/local/bin/swarph).
_SWARPH_BIN_PLACEHOLDER = "/usr/local/bin/swarph"


def _resolve_swarph_bin() -> str:
    """Resolve the absolute path of the running swarph binary.

    Resolution order:
      1. ``sys.argv[0]`` if it's an absolute path — most reliable, equals
         the path the user invoked
      2. ``shutil.which(sys.argv[0])`` — bare-name invocation, look up in PATH
      3. ``shutil.which("swarph")`` — generic PATH lookup as fallback
      4. ``/usr/local/bin/swarph`` — last-resort default (matches v0.7.3
         hardcode behavior; no regression if all three above fail)

    ALWAYS returns an absolute path — systemd ExecStart requires absolute.
    Relative inputs (e.g. ``venv/bin/swarph`` from editable installs) get
    abspath'd against cwd. Never raises.
    """
    invoked = sys.argv[0] or "swarph"
    if Path(invoked).is_absolute():
        return invoked
    resolved = shutil.which(invoked) or shutil.which("swarph")
    if not resolved:
        return _SWARPH_BIN_PLACEHOLDER
    return os.path.abspath(resolved)


def _bundled_systemd_files() -> dict[str, str]:
    """Return {filename: content} for the 3 bundled systemd templates.

    Reads from the package's bundled `systemd/` data directory via
    importlib.resources. Works regardless of install method (pipx, pip,
    editable, wheel-from-PyPI).
    """
    try:
        from importlib.resources import files as _files
    except ImportError:  # pragma: no cover — Python <3.9 not supported anyway
        from importlib_resources import files as _files  # type: ignore[no-redef]

    pkg_root = _files("swarph_cli") / "systemd"
    out: dict[str, str] = {}
    for name in (*_SYSTEMD_UNIT_NAMES, "swarph-watchdog.default"):
        out[name] = (pkg_root / name).read_text(encoding="utf-8")
    return out


def _execstart_flags(args: argparse.Namespace) -> str:
    """Build the flag suffix for the generated ExecStart (#28 footgun fix).

    Two guarantees:
      1. SAFE-BY-DEFAULT: the destructive A2 respawn is DISARMED (`--no-respawn`
         baked in) unless the operator explicitly passes `--arm-respawn`. If both
         are given, safety wins. The A1.5 model-rung is already opt-in, so it only
         appears when the operator asked for it.
      2. PROPAGATION: the operator's passed runtime flags are carried into the unit,
         so the installed service does what the install command implied — the bug
         was that they were silently dropped, so `--install-service --no-respawn`
         installed an ARMED watchdog.
    """
    parts: list[str] = []

    # (1) respawn — disarmed unless explicitly armed; safety beats --arm-respawn.
    if getattr(args, "no_respawn", False) or not getattr(args, "arm_respawn", False):
        parts.append("--no-respawn")

    # (2) store_true flags — emit only when the operator set them.
    for flag, attr in (
        ("--model-rung", "model_rung"),
        ("--no-model-rung", "no_model_rung"),
        ("--emit-health", "emit_health"),
        ("--peer-health-poll", "peer_health_poll"),
        ("--dm-wake", "dm_wake"),
    ):
        if getattr(args, attr, False):
            parts.append(flag)

    # (3) value flags — emit when set / non-default. (val, default_or_None)
    for flag, attr, default in (
        ("--activity-marker", "activity_marker", None),
        ("--cursor", "cursor", None),
        ("--tmux-session", "tmux_session", None),
        ("--peer", "peer", None),
        ("--liveness-cmd", "liveness_cmd", None),
        ("--notify-peer", "notify_peer", None),
        ("--gateway", "gateway", env_gateway()),
        ("--threshold", "threshold", _DEFAULT_THRESHOLD_SEC),
        ("--pane-activity-threshold", "pane_activity_threshold",
         _DEFAULT_PANE_ACTIVITY_THRESHOLD_SEC),
        ("--a2-max-respawns", "a2_max_respawns", _DEFAULT_A2_MAX_RESPAWNS),
        ("--a2-respawn-window-sec", "a2_respawn_window_sec",
         _DEFAULT_A2_RESPAWN_WINDOW_SEC),
    ):
        val = getattr(args, attr, default)
        if val is not None and val != default:
            parts.append(f"{flag} {val}")

    # --process-name only when non-default (the default 'claude' needn't clutter);
    # --liveness-cmd is mutually exclusive with it and handled above.
    pname = getattr(args, "process_name", "claude")
    if pname and pname != "claude" and not getattr(args, "liveness_cmd", None):
        parts.append(f"--process-name {pname}")

    return (" " + " ".join(parts)) if parts else ""


def run_install_service(args: argparse.Namespace) -> int:
    """Install systemd timer + service for periodic watchdog --check.

    Idempotent: overwrites existing unit files (newer-version semantics).
    Requires sudo for /etc/systemd/system writes unless --dry-run.

    Exit codes:
      0  success (or dry-run completed)
      4  configuration error (non-root without --dry-run)
      5  install error (file write failed / systemctl failed)
    """
    files = _bundled_systemd_files()
    cell = args.cell

    # v0.10.1: units are PER-CELL — swarph-watchdog-<cell>.{service,timer} +
    # /etc/default/swarph-watchdog-<cell> — so a multi-cell host runs one
    # watchdog instance per cell side-by-side. The 0.10.0 fixed names
    # CLOBBERED the existing unit on any second-cell install, and the
    # generated ExecStart carried no --cell at all (found arming
    # science-claude's watchdog next to lab's, 2026-06-10). ExecStart now
    # carries an explicit --cell so the unit's identity never depends on the
    # env file alone. Pre-existing legacy single-cell `swarph-watchdog.*`
    # units are left untouched (a migration note is printed if one exists).
    service_name = f"swarph-watchdog-{cell}.service"
    timer_name = f"swarph-watchdog-{cell}.timer"
    default_name = f"swarph-watchdog-{cell}"

    # v0.7.4: substitute the bundled service template's ExecStart placeholder
    # with the actual swarph binary path on this host. Fixes the v0.7.3 hardcode
    # that broke pipx-installed peers (binary at ~/.local/bin/swarph not
    # /usr/local/bin/swarph). Pipx is the recommended install path on droplet
    # + lab, so the hardcode bit BOTH peers on first install attempt today.
    swarph_bin = _resolve_swarph_bin()
    service_content = (
        files[_SYSTEMD_UNIT_NAMES[0]]
        .replace(
            f"ExecStart={_SWARPH_BIN_PLACEHOLDER}",
            f"ExecStart={swarph_bin}",
            1,
        )
        .replace(
            "watchdog --check",
            f"watchdog --check --cell {cell}{_execstart_flags(args)}",
            1,
        )
        .replace(
            "EnvironmentFile=-/etc/default/swarph-watchdog",
            f"EnvironmentFile=-/etc/default/{default_name}",
            1,
        )
        .replace(
            "Swarph watchdog one-shot check",
            f"Swarph watchdog one-shot check [{cell}]",
            1,
        )
    )

    timer_content = files[_SYSTEMD_UNIT_NAMES[1]].replace(
        "Requires=swarph-watchdog.service",
        f"Requires={service_name}",
        1,
    )

    # Template the default file with the requested role
    default_content = files["swarph-watchdog.default"].replace(
        "SWARPH_CELL=lab",
        f"SWARPH_CELL={cell}",
        1,
    )

    targets = [
        (_SYSTEMD_UNIT_DIR / service_name, service_content),
        (_SYSTEMD_UNIT_DIR / timer_name, timer_content),
        (_SYSTEMD_DEFAULT_DIR / default_name, default_content),
    ]

    legacy_unit = _SYSTEMD_UNIT_DIR / _SYSTEMD_UNIT_NAMES[0]
    legacy_note = (
        f"# NOTE: legacy single-cell unit {legacy_unit} exists; it is NOT "
        f"touched by this per-cell install. Migrate it to "
        f"swarph-watchdog-<cell>.* at your convenience."
        if legacy_unit.exists()
        else None
    )

    if args.dry_run:
        print(f"# DRY RUN — cell={cell} swarph_bin={swarph_bin}", file=sys.stderr)
        for path, content in targets:
            print(f"\n# would write {path}:", file=sys.stderr)
            print(content, file=sys.stderr)
        if legacy_note:
            print(f"\n{legacy_note}", file=sys.stderr)
        print(
            "\n# would then run:\n"
            "#   sudo systemctl daemon-reload\n"
            f"#   sudo systemctl enable --now {timer_name}",
            file=sys.stderr,
        )
        return 0

    if os.geteuid() != 0:
        print(
            "ERROR: --install-service requires root. Re-run with sudo, or use "
            "--dry-run to preview the install without writing.",
            file=sys.stderr,
        )
        return 4

    try:
        for path, content in targets:
            path.write_text(content, encoding="utf-8")
            print(f"wrote {path}", file=sys.stderr)
    except (OSError, PermissionError) as exc:
        print(f"ERROR: failed to write unit files: {exc}", file=sys.stderr)
        return 5

    try:
        subprocess.run(["systemctl", "daemon-reload"], check=True)
        subprocess.run(
            ["systemctl", "enable", "--now", timer_name],
            check=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        print(f"ERROR: systemctl failed: {exc}", file=sys.stderr)
        return 5

    if legacy_note:
        print(legacy_note, file=sys.stderr)
    print(
        f"\n{timer_name} installed + enabled for cell={cell}.\n"
        f"  status:  systemctl status {timer_name}\n"
        f"  logs:    journalctl -u {service_name} -f\n"
        f"           OR /var/log/swarph-watchdog.log\n"
        f"  next:    systemctl list-timers {timer_name}",
        file=sys.stderr,
    )
    return 0


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="swarph watchdog", add_help=True)
    p.add_argument(
        "--check", action="store_true",
        help="One-shot check (cron-callable; exits with status code).",
    )
    p.add_argument(
        "--orphan-daemons", action="store_true",
        help="#666 T1: read-only scan for orphaned `claude daemon run` "
             "processes (spawner dead + tmux-spawn scope gone). Prints a "
             "report; never signals unless --reap. UNKNOWN ≠ ORPHANED.",
    )
    p.add_argument(
        "--reap", action="store_true",
        help="#666 T3: with --orphan-daemons, SIGTERM (then SIGKILL) each "
             "daemon tree that matches ALL FOUR 09-03 clauses "
             "(origin transient|fork, ppid=1, not a live pane, "
             "childless or stale version). Default OFF. --origin-transient "
             "alone is never enough. Re-verifies starttime+cmdline+scope "
             "before each signal. Never pkill -f.",
    )
    p.add_argument(
        "--can-fail", action="store_true",
        help="#666/#123: with --orphan-daemons, run the healthy-pane "
             "fixture (a transient daemon that IS a live tmux pane_pid) "
             "and require it to be spared, printing which clause spared it. "
             "Does not signal live processes.",
    )
    p.add_argument(
        "--install-service", action="store_true",
        help="Install systemd timer + service for periodic --check invocation. "
             "Requires sudo. Closes ev_6954f748 substrate-component-install gap.",
    )
    p.add_argument(
        "--dry-run", action="store_true",
        help="With --install-service: show what would be written without "
             "writing. Useful for review or non-root preview.",
    )
    p.add_argument(
        "--cell",
        default=(
            os.environ.get("SWARPH_SELF")
            or os.environ.get("SWARPH_CELL")
            or "unidentified-cell"
        ),
    )
    p.add_argument("--cursor", default=None)
    p.add_argument(
        "--activity-marker", default=None,
        help="Turn-activity marker path (the Stop-hook touches it every "
             "turn-end). The freshest mtime of {cursor, marker} is the "
             "effective liveness, so an actively-working-but-not-draining cell "
             "isn't false-judged dark. Default $TMPDIR/<role>-claude-active.txt; "
             "cell.yaml extra.activity_marker_path also honored.",
    )
    p.add_argument("--threshold", type=int, default=_DEFAULT_THRESHOLD_SEC)
    p.add_argument(
        "--pane-activity-threshold",
        type=int,
        default=_DEFAULT_PANE_ACTIVITY_THRESHOLD_SEC,
        help="F3 gate: suppress A1 if tmux pane had activity within this "
             "many seconds (covers mid-long-turn working sessions where "
             "cursor-mtime is stale but session is alive).",
    )
    p.add_argument(
        "--gateway",
        default=env_gateway(),
    )
    p.add_argument("--tmux-session", default=None)
    p.add_argument("--peer", default=None)
    p.add_argument(
        "--emit-health", action="store_true",
        help="PRODUCER (#26): POST this cell's per-check verdict to the gateway's "
             "POST /peers/<self>/health so a hung-but-alive cell becomes visible. "
             "Best-effort, never affects the exit code. Default OFF (opt-in).",
    )
    liveness_group = p.add_mutually_exclusive_group()
    liveness_group.add_argument(
        "--process-name", default="claude",
        help="Process the cell's agent runs, used by the liveness gate's "
             "`pgrep -f` (scoped to the session's panes). Default 'claude'; "
             "pass 'node' for a codex cell, 'grok' for a grok cell so a "
             "non-Claude cell isn't mis-read as dead. Mutually exclusive with "
             "--liveness-cmd.",
    )
    liveness_group.add_argument(
        "--liveness-cmd", default=None,
        help="Escape hatch: shell command whose exit status is the liveness "
             "verdict (0 = alive, non-zero = dead) instead of the pgrep gate. "
             "On timeout/error the cell is assumed ALIVE (never false-fire the "
             "destructive A2 respawn). Mutually exclusive with --process-name.",
    )
    p.add_argument("--no-respawn", action="store_true")
    p.add_argument(
        "--arm-respawn", action="store_true",
        help="With --install-service ONLY: opt IN to arming the destructive A2 "
             "respawn in the generated unit. Without it, --install-service bakes "
             "--no-respawn into ExecStart (safe-by-default — a recovery tool must "
             "be the most conservative thing in the mesh; #28). If both --arm-respawn "
             "and --no-respawn are given, safety wins.",
    )
    p.add_argument(
        "--a15-max-swaps", type=int, default=_DEFAULT_A15_MAX_SWAPS,
        help="C1 thrash circuit: max A1.5 /model swaps within the swap window "
             "before the ladder escalates to A2 instead of swapping again.",
    )
    p.add_argument(
        "--a15-swap-window-sec", type=int, default=_DEFAULT_A15_SWAP_WINDOW_SEC,
        help="C1 thrash circuit window (seconds).",
    )
    p.add_argument(
        "--a2-max-respawns", type=int, default=_DEFAULT_A2_MAX_RESPAWNS,
        help="C3 respawn circuit: max A2 respawns within the respawn window "
             "before the watchdog HOLDS (circuit open, exit 6) instead of "
             "respawn-churning the cell.",
    )
    p.add_argument(
        "--a2-respawn-window-sec", type=int, default=_DEFAULT_A2_RESPAWN_WINDOW_SEC,
        help="C3 respawn circuit window (seconds).",
    )
    p.add_argument(
        "--notify-peer", default=None,
        help="N1 observability: mesh peer to DM (fixed-template, via the "
             "--dm-wake gateway machinery) on a15_model_swap / a2_respawn / "
             "a2_circuit_open. Requires MESH_GATEWAY_TOKEN. Default OFF.",
    )
    p.add_argument(
        "--stable-model",
        default=_DEFAULT_STABLE_MODEL,
        help="A1.5 rung: the known-stable model id injected via `/model "
             "<id>` when A1 exhausts but cursor is still stale, BEFORE A2 "
             "respawn. A config value only — NEVER interpolated with peer / "
             "inbox / network data. Default: " + _DEFAULT_STABLE_MODEL + ".",
    )
    p.add_argument(
        "--model-rung", action="store_true",
        help="OPT-IN: enable the A1.5 `/model`-swap rung. OFF by default since "
             "the 2026-06-11 false-fire incident — a stale cursor on a LIVE "
             "process is ambiguous (idle vs stalled), and injecting /model on "
             "that ambiguity restarted live sessions across 5 cells. Only "
             "enable on a cell you've confirmed needs engine-swap recovery, "
             "accepting that risk; otherwise the ladder is A1 → A2(dead-only).",
    )
    p.add_argument(
        "--no-model-rung", action="store_true",
        help="Force-disable the A1.5 rung even if --model-rung is set "
             "(belt-and-suspenders; the rung is already OFF by default).",
    )
    p.add_argument(
        "--peer-health-poll", action="store_true",
        help="Phase 4 (v0.7.6): also query mesh-gateway /peer-health-events. "
             "On recent usage_limit_reset event, treat sessions as wake-"
             "candidates even before the 30min cursor-staleness threshold. "
             "Requires MESH_GATEWAY_TOKEN in env. Default OFF (opt-in).",
    )
    p.add_argument(
        "--dm-wake", action="store_true",
        help="send a cross-host wake DM to a stranded peer (A1-DM) instead "
             "of only local tmux send-keys.",
    )
    p.add_argument(
        "--dm-wake-cooldown-sec",
        type=int,
        default=_DEFAULT_DM_WAKE_COOLDOWN_SEC,
        help="T4 no-spam gate: DM-wake each stale peer at most once per this "
             "many seconds, so a peer that stays stale across many ticks is "
             "woken once, not every tick. Default 1800 (30 min).",
    )
    p.add_argument(
        "--peer-health-window-sec",
        type=int,
        default=_DEFAULT_PEER_HEALTH_WINDOW_SEC,
        help="Phase 4: window for recovery-event lookup; default 600 (10 min).",
    )
    p.add_argument(
        "--peer-health-recovery-threshold",
        type=int,
        default=_DEFAULT_PEER_HEALTH_RECOVERY_THRESHOLD_SEC,
        help="Phase 4: min cursor staleness for recovery event to promote "
             "session to wake-candidate; default 120 (2 min).",
    )
    p.add_argument("--log", default=None)
    p.add_argument("--verbose", action="store_true")

    return p


def run_watchdog(argv: Optional[list[str]] = None) -> int:
    if argv is None:
        argv = sys.argv[2:]  # skip "swarph watchdog"

    if not argv:
        print(_USAGE, file=sys.stderr)
        return 0

    p = _build_parser()

    try:
        args = p.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code or 0)

    if args.install_service:
        return run_install_service(args)

    if args.orphan_daemons:
        if getattr(args, "can_fail", False):
            from swarph_cli.orphan_daemons import run_can_fail_healthy_pane
            return run_can_fail_healthy_pane()
        from swarph_cli.orphan_daemons import run_orphan_daemons_report
        return run_orphan_daemons_report(reap=bool(args.reap))

    if getattr(args, "reap", False):
        print("swarph watchdog: --reap requires --orphan-daemons", file=sys.stderr)
        return 4

    if not args.check:
        print(_USAGE, file=sys.stderr)
        return 4

    return run_check(args)
