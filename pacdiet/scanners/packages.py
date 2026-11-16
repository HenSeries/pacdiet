"""Pacman, AUR helpers and package-related leftovers."""

from __future__ import annotations

import os
import re
from pathlib import Path

from ..model import Action, Finding, Risk, Scanner
from ..system import HOME, dir_size, dir_sizes, file_size, have, lines, run

PKG_CACHE = Path("/var/cache/pacman/pkg")
PKG_RE = re.compile(r"^(?P<name>.+)-(?P<ver>[^-]+-[^-]+)-(?P<arch>[^-]+)\.pkg\.tar\.\w+$")


def _cache_files() -> list[Path]:
    try:
        return [p for p in PKG_CACHE.iterdir() if p.name.endswith((".zst", ".xz", ".gz"))]
    except OSError:
        return []


def _paccache_candidates(args: list[str]) -> tuple[list[str], int]:
    """Ask paccache what it would prune, and total the real file sizes.

    We sum sizes ourselves rather than parsing paccache's rounded summary line.
    """
    if not have("paccache"):
        return [], 0
    out = lines(["paccache", "-dv", *args], timeout=180)
    names = [ln.strip() for ln in out if not ln.startswith("==>") and ln.strip()]
    paths, total = [], 0
    for name in names:
        p = PKG_CACHE / name
        size = file_size(p)
        if size:
            paths.append(str(p))
            total += size
    return paths, total


def scan_pacman_cache() -> list[Finding]:
    findings: list[Finding] = []
    files = _cache_files()
    if not files:
        return findings

    # 1. Versions of packages that are no longer installed at all.
    paths, size = _paccache_candidates(["-uk0"])
    if size:
        findings.append(Finding(
            key="cache-uninstalled",
            label="Cached packages you no longer have installed",
            detail=f"{len(paths)} files. Nothing can roll back to these — they are dead weight.",
            size=size,
            risk=Risk.SAFE,
            selected=True,
            action=Action(command=["paccache", "-ruk0"], root=True),
        ))

    # 2. Superseded versions of packages that *are* installed, keeping the
    #    three newest so downgrades stay possible.
    paths, size = _paccache_candidates(["-k3"])
    if size:
        findings.append(Finding(
            key="cache-old-versions",
            label="Old versions of installed packages (keeping the 3 newest)",
            detail=f"{len(paths)} files. You can still downgrade to any of the 3 kept versions.",
            size=size,
            risk=Risk.SAFE,
            selected=True,
            action=Action(command=["paccache", "-rk3"], root=True),
        ))

    # 3. The whole cache. On a system that only ever holds one version per
    #    package, this is the only thing that actually frees meaningful space --
    #    at the cost of being able to reinstall or downgrade offline.
    total = sum(file_size(p) for p in files)
    sigs = sum(file_size(p) for p in PKG_CACHE.glob("*.sig")) if PKG_CACHE.exists() else 0
    already = sum(f.size for f in findings)
    remainder = total + sigs - already
    if remainder > 0:
        findings.append(Finding(
            key="cache-everything",
            label="Every remaining cached package (full cache clear)",
            detail=(
                "Frees the most space by far, but afterwards you cannot reinstall "
                "or downgrade a package without re-downloading it. Pick this only "
                "if you have a good connection."
            ),
            size=remainder,
            risk=Risk.CAREFUL,
            action=Action(command=["pacman", "-Scc", "--noconfirm"], root=True),
        ))
    return findings


def scan_orphans() -> list[Finding]:
    """Packages pulled in as dependencies that nothing needs any more."""
    if not have("pacman"):
        return []
    names = lines(["pacman", "-Qqtd"], timeout=60)
    if not names:
        return []

    sizes: dict[str, int] = {}
    info = run(["pacman", "-Qi", *names], timeout=120)
    current = None
    for ln in info.stdout.splitlines():
        if ln.startswith("Name"):
            current = ln.split(":", 1)[1].strip()
        elif ln.startswith("Installed Size") and current:
            sizes[current] = _parse_size(ln.split(":", 1)[1].strip())
            current = None

    # Deliberately NOT preselected, and rated Careful.
    #
    # "Orphan" only means that no *other installed package* depends on it. A
    # tool you installed yourself and use every day shows up here the moment
    # it was pulled in as a dependency -- or installed with --asdeps, or left
    # behind when a meta-package went away. Removing the whole list
    # unreviewed takes out things like your lock screen, your Qt theme engine
    # or your password manager, and -Rns cascades into their dependencies
    # too. This list is a prompt to read, never a batch to approve.
    findings = [
        Finding(
            key=f"orphan-{name}",
            label=name,
            detail=(
                "No installed package depends on this. That does not mean you do "
                "not use it — check before ticking it."
            ),
            size=sizes.get(name, 0),
            risk=Risk.CAREFUL,
            selected=False,
            action=Action(command=["pacman", "-Rns", "--noconfirm", name], root=True),
        )
        for name in names
    ]
    return sorted(findings, key=lambda f: f.size, reverse=True)


def _parse_size(text: str) -> int:
    match = re.match(r"([\d.,]+)\s*([KMGT]?i?B)", text)
    if not match:
        return 0
    value = float(match.group(1).replace(",", "."))
    factor = {"B": 1, "KiB": 1024, "MiB": 1024**2, "GiB": 1024**3, "TiB": 1024**4}
    return int(value * factor.get(match.group(2), 1))


AUR_DIRS = [
    (HOME / ".cache/paru/clone", "paru build directory", "Cloned PKGBUILDs and compiled packages. Rebuilt on demand."),
    (HOME / ".cache/paru/pkg", "paru package cache", "Built AUR packages kept for reinstalling."),
    (HOME / ".cache/yay", "yay build directory", "Cloned PKGBUILDs and compiled packages. Rebuilt on demand."),
    (HOME / ".cache/pikaur", "pikaur build directory", "Cloned PKGBUILDs and build output."),
    (HOME / ".cache/trizen", "trizen build directory", "Cloned PKGBUILDs and build output."),
    (Path("/var/cache/private/paru"), "paru system cache", "Build output cached under /var/cache."),
]


def scan_aur_cache() -> list[Finding]:
    present = [(p, title, detail) for p, title, detail in AUR_DIRS if p.is_dir()]
    sizes = dir_sizes([p for p, _, _ in present])
    findings = []
    for path, title, detail in present:
        size = sizes.get(str(path), 0)
        if size < 1024:
            continue
        findings.append(Finding(
            key=f"aur-{path.name}-{path.parent.name}",
            label=f"{title} ({path})",
            detail=detail,
            size=size,
            risk=Risk.SAFE,
            selected=True,
            action=Action(paths=[str(path)], root=not str(path).startswith(str(HOME))),
        ))
    return findings


def scan_stale_modules() -> list[Finding]:
    """Module trees under /usr/lib/modules with no matching installed kernel.

    These are left behind when a kernel package is removed without its modules
    being cleaned up, and they are pure waste.
    """
    root = Path("/usr/lib/modules")
    if not root.is_dir():
        return []
    owned: set[str] = set()
    for ln in lines(["pacman", "-Qqo", str(root)], timeout=30):
        owned.add(ln)

    candidates = []
    for entry in sorted(root.iterdir()):
        if not entry.is_dir():
            continue
        proc = run(["pacman", "-Qqo", str(entry)], timeout=20)
        if proc.returncode != 0:
            candidates.append(entry)  # no package owns it
    if not candidates:
        return []
    sizes = dir_sizes(candidates)
    return [
        Finding(
            key=f"module-{p.name}",
            label=f"Orphaned kernel modules: {p.name}",
            detail="No installed package owns this directory — a leftover from a removed kernel.",
            size=sizes.get(str(p), 0),
            risk=Risk.CAREFUL,
            selected=False,
            action=Action(paths=[str(p)], root=True),
        )
        for p in candidates
    ]


def scan_pacfiles() -> list[Finding]:
    """.pacnew/.pacsave config files. Reported, never auto-deleted: these need
    merging by hand, and the size is trivial. Shown so they stop being forgotten."""
    out = run(
        ["find", "/etc", "-name", "*.pacnew", "-o", "-name", "*.pacsave"],
        timeout=60,
    )
    paths = [ln for ln in out.stdout.splitlines() if ln.strip()]
    return [
        Finding(
            key=f"pacfile-{p}",
            label=p,
            detail="Merge this into your config before deleting it. Use pacdiff.",
            size=file_size(p),
            risk=Risk.CAREFUL,
            action=Action(paths=[p], root=True),
        )
        for p in paths
    ]


def scanners() -> list[Scanner]:
    return [
        Scanner(
            key="pacman-cache",
            title="Pacman package cache",
            subtitle="Downloaded packages kept under /var/cache/pacman/pkg",
            icon="folder-download-symbolic",
            run=scan_pacman_cache,
            available=lambda: PKG_CACHE.is_dir(),
        ),
        Scanner(
            key="orphans",
            title="Orphaned packages",
            subtitle="Dependencies nothing needs any more",
            icon="package-x-generic-symbolic",
            run=scan_orphans,
            note=(
                "Read this list item by item. An orphan is simply a package nothing "
                "else depends on — tools you installed and use appear here too, and "
                "-Rns pulls their dependencies out with them. Nothing is preselected."
            ),
            available=lambda: have("pacman"),
        ),
        Scanner(
            key="aur-cache",
            title="AUR helper caches",
            subtitle="Cloned PKGBUILDs and built packages from paru / yay",
            icon="utilities-terminal-symbolic",
            run=scan_aur_cache,
        ),
        Scanner(
            key="stale-modules",
            title="Orphaned kernel modules",
            subtitle="Module trees left behind by removed kernels",
            icon="application-x-firmware-symbolic",
            run=scan_stale_modules,
            available=lambda: have("pacman") and Path("/usr/lib/modules").is_dir(),
        ),
        Scanner(
            key="pacfiles",
            title="Unmerged config files",
            subtitle=".pacnew and .pacsave files waiting for review",
            icon="text-x-generic-symbolic",
            run=scan_pacfiles,
            note="These are listed so you remember to merge them — run pacdiff. Deleting without merging loses either your settings or the new defaults.",
        ),
    ]
