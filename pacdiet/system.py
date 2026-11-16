"""Talking to the system: sizing paths, running commands, escalating once."""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Iterable, Sequence

HOME = Path.home()

#: Paths we refuse to delete no matter what a scanner says. Guards against a
#: scanner bug turning into a lost home directory.
PROTECTED = {
    Path("/"), Path("/home"), Path("/etc"), Path("/usr"), Path("/var"),
    Path("/boot"), Path("/bin"), Path("/lib"), Path("/opt"), Path("/srv"),
    Path("/root"), Path("/run"), Path("/proc"), Path("/sys"), Path("/dev"),
    HOME,
    HOME / ".config", HOME / ".local", HOME / ".local/share", HOME / ".cache",
    HOME / ".ssh", HOME / ".gnupg", HOME / ".password-store",
}

#: Directory names that must never appear as the *last* component of a deletion
#: target -- these hold data, not caches.
PROTECTED_NAMES = {".ssh", ".gnupg", ".password-store", "Documents", "Documentos"}


class Denied(Exception):
    """The user dismissed the polkit prompt, or escalation is unavailable."""


def have(binary: str) -> bool:
    return shutil.which(binary) is not None


def run(
    cmd: Sequence[str],
    timeout: int = 60,
    check: bool = False,
) -> subprocess.CompletedProcess[str]:
    """Run a command, capturing output. Never raises on non-zero unless asked."""
    try:
        return subprocess.run(
            list(cmd),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=check,
            env={**os.environ, "LC_ALL": "C"},
        )
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(list(cmd), 124, "", f"timed out after {timeout}s")
    except FileNotFoundError:
        return subprocess.CompletedProcess(list(cmd), 127, "", "command not found")


def lines(cmd: Sequence[str], timeout: int = 60) -> list[str]:
    """Run a command and return its non-empty stdout lines."""
    proc = run(cmd, timeout=timeout)
    if proc.returncode != 0 and not proc.stdout:
        return []
    return [ln for ln in proc.stdout.splitlines() if ln.strip()]


def dir_size(path: str | Path, timeout: int = 120) -> int:
    """Apparent-disk size of a path in bytes, via `du`. 0 if unreadable."""
    proc = run(["du", "-sbx", "--", str(path)], timeout=timeout)
    if proc.returncode in (0, 1) and proc.stdout:
        try:
            return int(proc.stdout.split(maxsplit=1)[0])
        except (ValueError, IndexError):
            return 0
    return 0


def dir_sizes(paths: Iterable[str | Path], timeout: int = 300) -> dict[str, int]:
    """Size several paths in one `du` call. Much faster than one call each."""
    targets = [str(p) for p in paths]
    if not targets:
        return {}
    proc = run(["du", "-sbx", "--", *targets], timeout=timeout)
    out: dict[str, int] = {}
    for ln in proc.stdout.splitlines():
        parts = ln.split("\t", 1)
        if len(parts) == 2:
            try:
                out[parts[1]] = int(parts[0])
            except ValueError:
                continue
    return out


def file_size(path: str | Path) -> int:
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


def mtime_days(path: str | Path) -> float:
    """Days since the path was last modified. inf if unreadable."""
    import time
    try:
        return (time.time() - os.path.getmtime(path)) / 86400.0
    except OSError:
        return float("inf")


def is_protected(path: str | Path) -> bool:
    """True if deleting this path should be refused outright."""
    try:
        p = Path(path).expanduser()
    except (OSError, RuntimeError):
        return True
    if not p.is_absolute():
        return True
    # Resolve symlinks only for the parent, so a symlinked cache dir is still
    # deletable but cannot point the deletion at a protected target.
    resolved = p if not p.exists() else Path(os.path.realpath(p))
    if resolved in PROTECTED or p in PROTECTED:
        return True
    if p.name in PROTECTED_NAMES:
        return True
    if len(resolved.parts) <= 2 and resolved != HOME:
        return True  # /something -- too close to the root to be a cache
    return False


# ---------------------------------------------------------------------------
# Execution


def delete_paths(paths: Iterable[str | Path], log: list[str]) -> int:
    """Delete paths as the current user. Returns bytes freed (best effort)."""
    freed = 0
    for raw in paths:
        p = Path(raw)
        if is_protected(p):
            log.append(f"REFUSED (protected): {p}")
            continue
        if not p.exists() and not p.is_symlink():
            log.append(f"gone already: {p}")
            continue
        size = file_size(p) if p.is_file() or p.is_symlink() else dir_size(p)
        try:
            if p.is_symlink() or p.is_file():
                p.unlink()
            else:
                shutil.rmtree(p)
            freed += size
            log.append(f"removed: {p}")
        except OSError as exc:
            log.append(f"FAILED: {p}: {exc}")
    return freed


def run_user_command(cmd: Sequence[str], log: list[str]) -> None:
    log.append(f"$ {shlex.join(cmd)}")
    proc = run(cmd, timeout=900)
    for stream in (proc.stdout, proc.stderr):
        for ln in stream.splitlines():
            log.append(f"  {ln}")
    if proc.returncode != 0:
        log.append(f"  (exit {proc.returncode})")


def build_root_script(paths: Sequence[str], commands: Sequence[Sequence[str]]) -> str:
    """Render one bash script for every privileged action, so the user is
    prompted for their password exactly once."""
    out = [
        "#!/usr/bin/env bash",
        "# Generated by pacdiet. Runs once, then is deleted.",
        "set -u",
        "export LC_ALL=C",
        "status=0",
        "",
    ]
    for p in paths:
        q = shlex.quote(p)
        out += [
            f"echo \"removing: {p}\"",
            f"rm -rf --one-file-system -- {q} || {{ echo \"FAILED: {p}\"; status=1; }}",
        ]
    for cmd in commands:
        joined = shlex.join(cmd)
        out += [
            f"echo \"$ {joined}\"",
            f"{joined} || {{ echo \"FAILED: {joined}\"; status=1; }}",
        ]
    out += ["", "exit $status", ""]
    return "\n".join(out)


def run_root_script(script: str, log: list[str]) -> None:
    """Execute a privileged batch via pkexec (one prompt for the whole run)."""
    if not have("pkexec"):
        raise Denied("pkexec is not installed; cannot run privileged cleanups")

    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=".sh", prefix="pacdiet-", delete=False
    )
    try:
        tmp.write(script)
        tmp.close()
        os.chmod(tmp.name, 0o700)
        log.append("--- privileged actions (authenticating) ---")
        proc = subprocess.run(
            ["pkexec", "/usr/bin/env", "bash", tmp.name],
            capture_output=True,
            text=True,
            timeout=1800,
        )
        for stream in (proc.stdout, proc.stderr):
            for ln in stream.splitlines():
                log.append(f"  {ln}")
        # pkexec exits 126 when the dialog is dismissed, 127 when it cannot run.
        if proc.returncode == 126:
            raise Denied("Authentication was cancelled")
        if proc.returncode == 127:
            raise Denied("pkexec could not start the privileged helper")
        if proc.returncode != 0:
            log.append(f"  (exit {proc.returncode})")
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass
