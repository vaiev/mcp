"""Core of the control MCP template: allow-listed actions from a TOML file, no shell, approvals, audit, redaction.

Each action in control.toml names an argv list (no shell), its parameters with a regular expression each, and a
kind: "read" (runs freely) or "change" (needs an approval "<who> <YYYY-MM-DD>: <what>" and is written to the audit
log before and after it runs). A built-in deny list (destroy, delete, recursive rm, DROP …) refuses an action even
with an approval: deletions stay with a human. Output is redacted and truncated; the child process gets a minimal
environment, so secrets in the server's environment do not leak into commands or their output.

This module has no dependency on the MCP SDK; server.py wires it to MCP.
"""
from __future__ import annotations

import datetime
import json
import os
import re
import subprocess
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

KINDS = ("read", "change")
DEFAULT_APPROVAL = r"^(?P<who>\S[^:\n]{0,60}?) (?P<date>\d{4}-\d{2}-\d{2}): (?P<what>.{4,300})$"
DEFAULT_DENY = (
    r"\bdestroy\b",
    r"\bdelete\b",
    r"\brm\s+-[a-z]*r",
    r"\bdrop\s+(database|schema|table)\b",
    r"\bpush\s+.*--force\b",
)
BASE_ENV = ("PATH", "HOME", "LANG", "LC_ALL", "TZ")
REDACTED = "[REDACTED]"
REDACTIONS = (
    (re.compile(r"-----BEGIN [A-Z0-9 ]+-----.*?(-----END [A-Z0-9 ]+-----|$)", re.S), "[REDACTED PEM]"),
    (re.compile(r"AGE-SECRET-KEY-1[0-9A-Z]+"), "[REDACTED AGE KEY]"),
    (re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})"), REDACTED),
    (re.compile(r"(?i)\b(bearer|basic|token)\s+[A-Za-z0-9._~+/=-]{8,}"), r"\1 " + REDACTED),
    (re.compile(r"(://)[^/\s:@]+:[^/\s@]+@"), r"\1" + REDACTED + "@"),
    (re.compile(r"(?i)\b([\w.-]*(?:password|passwd|passphrase|secret|token|api[_-]?key|credential)[\w.-]*)"
                r"(\"?\s*[:=]\s*\"?)([^\s\"',;}]+)"), r"\1\2" + REDACTED),
)
PLACEHOLDER = re.compile(r"\{([a-z_][a-z0-9_]*)\}")


class ConfigError(ValueError):
    """control.toml is invalid; the server refuses to start."""


@dataclass
class Action:
    name: str
    kind: str
    description: str
    argv: list[str]
    params: dict[str, re.Pattern] = field(default_factory=dict)
    timeout: int | None = None


@dataclass
class Config:
    root: Path
    actions: dict[str, Action]
    audit_log: Path
    approval: re.Pattern
    deny: list[re.Pattern]
    timeout: int
    max_output: int
    env_passthrough: list[str]


def load(path: str | os.PathLike) -> Config:
    path = Path(path).resolve()
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    settings = data.get("settings", {})
    root = (path.parent / settings.get("workdir", ".")).resolve()
    actions = {}
    for name, spec in data.get("actions", {}).items():
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,40}", name):
            raise ConfigError(f"action name {name!r}: lower-case letters, digits, _")
        if spec.get("kind") not in KINDS:
            raise ConfigError(f"{name}: kind must be one of {KINDS}")
        argv = spec.get("argv")
        if not isinstance(argv, list) or not argv or not all(isinstance(a, str) for a in argv):
            raise ConfigError(f"{name}: argv must be a non-empty list of strings (no shell string)")
        params = {}
        for pname, pattern in spec.get("params", {}).items():
            try:
                params[pname] = re.compile(pattern)
            except re.error as e:
                raise ConfigError(f"{name}.{pname}: bad pattern: {e}") from None
        used = {m for a in argv for m in PLACEHOLDER.findall(a)}
        if used != set(params):
            raise ConfigError(f"{name}: placeholders {sorted(used)} must equal params {sorted(params)}")
        actions[name] = Action(name, spec["kind"], spec.get("description", ""), argv, params, spec.get("timeout_seconds"))
    if not actions:
        raise ConfigError("no actions defined")
    return Config(
        root=root,
        actions=actions,
        audit_log=(root / settings.get("audit_log", "OPS-LOG.md")).resolve(),
        approval=re.compile(settings.get("approval_pattern", DEFAULT_APPROVAL)),
        deny=[re.compile(p, re.I) for p in (*DEFAULT_DENY, *settings.get("deny", []))],
        timeout=int(settings.get("timeout_seconds", 120)),
        max_output=int(settings.get("max_output", 8000)),
        env_passthrough=list(settings.get("env_passthrough", [])),
    )


def list_actions(cfg: Config) -> list[dict]:
    return [{"name": a.name, "kind": a.kind, "description": a.description, "params": sorted(a.params)}
            for a in cfg.actions.values()]


def redact(text: str) -> str:
    for pattern, repl in REDACTIONS:
        text = pattern.sub(repl, text)
    return text


def _audit(cfg: Config, action: str, params: dict, state: str, approval: str) -> None:
    cfg.audit_log.parent.mkdir(parents=True, exist_ok=True)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    args = json.dumps(params, sort_keys=True).replace("|", "\\|")
    with cfg.audit_log.open("a", encoding="utf-8") as log:
        log.write(f"| {stamp} | {action} | `{args}` | {state} | {approval.replace('|', '/')} |\n")


def _refuse(reason: str) -> dict:
    return {"status": "refused", "reason": reason}


def run(cfg: Config, name: str, params: dict | None = None, approved: str = "") -> dict:
    params = params or {}
    action = cfg.actions.get(name)
    if action is None:
        return _refuse(f"unknown action {name!r}; see list_actions")
    if set(params) != set(action.params):
        return _refuse(f"{name} takes exactly the params {sorted(action.params)}")
    for pname, pattern in action.params.items():
        value = params[pname]
        if not isinstance(value, str) or not pattern.fullmatch(value):
            return _refuse(f"param {pname!r} does not match {pattern.pattern}")
    argv = [PLACEHOLDER.sub(lambda m: params[m.group(1)], a) for a in action.argv]
    joined = " ".join(argv)
    for pattern in cfg.deny:
        if pattern.search(joined):
            return _refuse(f"matches deny pattern {pattern.pattern!r}: deletions and destroys stay with a human")
    env = {k: os.environ[k] for k in (*BASE_ENV, *cfg.env_passthrough) if k in os.environ}
    approval = approved.strip()
    if action.kind == "change":
        match = cfg.approval.fullmatch(approval)
        if not match:
            return _refuse("change actions need approved='<who> <YYYY-MM-DD>: <what>'")
        env.update(CONTROL_APPROVED=approval, CONTROL_APPROVED_BY=match.group("who"))
        _audit(cfg, name, params, "started", approval)
    try:
        proc = subprocess.run(argv, cwd=cfg.root, env=env, capture_output=True, text=True,
                              timeout=action.timeout or cfg.timeout, stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        if action.kind == "change":
            _audit(cfg, name, params, "timeout", approval)
        return {"status": "failed", "reason": f"timeout after {action.timeout or cfg.timeout} s"}
    except OSError as e:
        return {"status": "failed", "reason": f"cannot start {argv[0]}: {e.strerror}"}
    if action.kind == "change":
        _audit(cfg, name, params, f"exit {proc.returncode}", approval)
    output = redact(proc.stdout + proc.stderr)
    if len(output) > cfg.max_output:
        output = "…" + output[-cfg.max_output:]
    return {"status": "ok" if proc.returncode == 0 else "failed", "exit_code": proc.returncode, "output": output}
