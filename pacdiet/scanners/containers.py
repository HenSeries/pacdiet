"""Docker, Podman and Flatpak."""

from __future__ import annotations

import json
import re
from pathlib import Path

from ..model import Action, Finding, Risk, Scanner
from ..system import have, lines, run


def _docker_reachable(binary: str) -> bool:
    if not have(binary):
        return False
    return run([binary, "info", "--format", "{{.ServerVersion}}"], timeout=15).returncode == 0


def _parse_size(text: str) -> int:
    match = re.match(r"\s*([\d.,]+)\s*([kKMGTB]i?B?)", text or "")
    if not match:
        return 0
    value = float(match.group(1).replace(",", "."))
    unit = match.group(2).lower().rstrip("b").rstrip("i")
    factor = {"": 1, "k": 1000, "m": 1000**2, "g": 1000**3, "t": 1000**4}
    return int(value * factor.get(unit, 1))


def _engine_findings(binary: str) -> list[Finding]:
    """Reclaimable space per resource type, read from `system df`."""
    proc = run([binary, "system", "df", "--format", "{{json .}}"], timeout=60)
    rows = []
    for ln in proc.stdout.splitlines():
        ln = ln.strip()
        if not ln:
            continue
        try:
            rows.append(json.loads(ln))
        except json.JSONDecodeError:
            continue

    specs = {
        "Images": (
            "Dangling and unused images",
            ["image", "prune", "-af"],
            "Images not referenced by any container. Re-pulled when needed.",
            Risk.SAFE,
        ),
        "Containers": (
            "Stopped containers",
            ["container", "prune", "-f"],
            "Containers that are not running. Their writable layers are lost.",
            Risk.REVIEW,
        ),
        "Build Cache": (
            "Build cache",
            ["builder", "prune", "-af"],
            "Cached build layers. Rebuilt on the next docker build.",
            Risk.SAFE,
        ),
        "Local Volumes": (
            "Unused volumes",
            ["volume", "prune", "-af"],
            "Volumes no container references. These can hold real data — "
            "databases from old projects live here.",
            Risk.CAREFUL,
        ),
    }

    findings = []
    for row in rows:
        kind = row.get("Type")
        if kind not in specs:
            continue
        label, args, detail, risk = specs[kind]
        size = _parse_size(row.get("Reclaimable", ""))
        if size < 1024 * 1024:
            continue
        findings.append(Finding(
            key=f"{binary}-{kind.lower().replace(' ', '-')}",
            label=f"{binary}: {label}",
            detail=f"{detail} ({row.get('Reclaimable')} reclaimable of {row.get('Size')}.)",
            size=size,
            risk=risk,
            selected=risk is Risk.SAFE,
            action=Action(command=[binary, *args], root=binary == "docker"),
        ))
    return findings


def scan_containers() -> list[Finding]:
    findings = []
    for binary in ("docker", "podman"):
        if _docker_reachable(binary):
            findings.extend(_engine_findings(binary))
    return findings


def scan_flatpak() -> list[Finding]:
    if not have("flatpak"):
        return []
    findings = []

    # Strictly read-only. A scan must never invoke `flatpak uninstall`, not
    # even with a dry-run style flag: the accepted flags differ between
    # versions, and a misparse would uninstall for real.
    runtimes = lines(["flatpak", "list", "--runtime", "--columns=ref,size"], timeout=60)
    required: set[str] = {
        ln.strip() for ln in lines(["flatpak", "list", "--app", "--columns=runtime"], timeout=60)
        if ln.strip()
    }

    unused: list[tuple[str, int]] = []
    for ln in runtimes:
        parts = ln.split("\t")
        if len(parts) < 2:
            continue
        ref, size_text = parts[0].strip(), parts[-1]
        # Treat a .Locale/.Debug extension as needed whenever its base runtime
        # is still required by an installed app.
        base = ref.split("/", 1)[0]
        stem = base.rsplit(".Locale", 1)[0].rsplit(".Debug", 1)[0]
        if any(dep.split("/", 1)[0].startswith(stem) for dep in required):
            continue
        unused.append((ref, _parse_size(size_text)))

    total = sum(size for _, size in unused)
    if unused and total > 1024 * 1024:
        listed = ", ".join(ref for ref, _ in unused[:6]) + ("…" if len(unused) > 6 else "")
        findings.append(Finding(
            key="flatpak-unused",
            label=f"Unused Flatpak runtimes ({len(unused)})",
            detail=(
                f"No installed app declares these as a dependency: {listed}. "
                "Flatpak makes the final decision when the cleanup runs."
            ),
            size=total,
            risk=Risk.SAFE,
            selected=True,
            action=Action(command=["flatpak", "uninstall", "--unused", "-y"], root=False),
        ))

    repo = Path("/var/tmp/flatpak-cache")
    for candidate in (repo, Path("/var/lib/flatpak/repo/tmp")):
        if candidate.is_dir():
            from ..system import dir_size
            size = dir_size(candidate)
            if size > 1024 * 1024:
                findings.append(Finding(
                    key=f"flatpak-tmp-{candidate.name}",
                    label=f"Flatpak download cache ({candidate})",
                    detail="Partially downloaded or already-applied update data.",
                    size=size,
                    risk=Risk.SAFE,
                    selected=True,
                    action=Action(paths=[str(candidate)], root=True),
                ))
    return findings


def scan_snap() -> list[Finding]:
    """Disabled snap revisions, for the rare Arch system that has snapd."""
    if not have("snap"):
        return []
    findings = []
    for ln in lines(["snap", "list", "--all"], timeout=30):
        parts = ln.split()
        if len(parts) >= 6 and "disabled" in parts[-1]:
            name, _, rev = parts[0], parts[1], parts[2]
            findings.append(Finding(
                key=f"snap-{name}-{rev}",
                label=f"{name} revision {rev} (disabled)",
                detail="An old snap revision kept for rollback.",
                size=0,
                risk=Risk.REVIEW,
                action=Action(command=["snap", "remove", name, "--revision", rev], root=True),
            ))
    return findings


def scanners() -> list[Scanner]:
    return [
        Scanner(
            key="containers",
            title="Containers",
            subtitle="Docker and Podman images, build cache and volumes",
            icon="network-server-symbolic",
            run=scan_containers,
            available=lambda: have("docker") or have("podman"),
            unavailable_note="No container engine found",
            note="Sizes come straight from 'system df'. Volumes are never preselected — they hold data.",
        ),
        Scanner(
            key="flatpak",
            title="Flatpak",
            subtitle="Unused runtimes and download caches",
            icon="application-x-addon-symbolic",
            run=scan_flatpak,
            available=lambda: have("flatpak"),
            unavailable_note="Flatpak is not installed",
        ),
        Scanner(
            key="snap",
            title="Snap",
            subtitle="Disabled snap revisions",
            icon="application-x-addon-symbolic",
            run=scan_snap,
            available=lambda: have("snap"),
            unavailable_note="snapd is not installed",
        ),
    ]
