"""Everything under the user's own cache and data directories."""

from __future__ import annotations

import os
from pathlib import Path

from ..model import Action, Finding, Risk, Scanner
from ..system import HOME, dir_size, dir_sizes, mtime_days

CACHE = Path(os.environ.get("XDG_CACHE_HOME") or HOME / ".cache")

#: Cache subdirectories we can describe, and how cautious to be about them.
#: Anything not listed is still offered, just with a generic description.
KNOWN: dict[str, tuple[str, Risk]] = {
    "thumbnails": ("Image thumbnails for file managers. Regenerated on demand.", Risk.SAFE),
    "mesa_shader_cache": ("Compiled GPU shaders. Rebuilt on first run, costing a brief stutter.", Risk.SAFE),
    "mesa_shader_cache_db": ("Compiled GPU shaders. Rebuilt on first run.", Risk.SAFE),
    "nvidia": ("NVIDIA shader cache. Rebuilt automatically.", Risk.SAFE),
    "fontconfig": ("Font metadata index. Rebuilt on demand.", Risk.SAFE),
    "chromium": ("Chromium browser cache. Does not include history or passwords.", Risk.SAFE),
    "google-chrome": ("Chrome browser cache. Does not include history or passwords.", Risk.SAFE),
    "mozilla": ("Firefox browser cache. Does not include history or passwords.", Risk.SAFE),
    "zen": ("Zen browser cache. Does not include history or passwords.", Risk.SAFE),
    "BraveSoftware": ("Brave browser cache.", Risk.SAFE),
    "vivaldi": ("Vivaldi browser cache.", Risk.SAFE),
    "wine": ("Wine's own cache of downloaded components.", Risk.SAFE),
    "winetricks": ("Installers downloaded by winetricks. Re-downloaded if needed.", Risk.REVIEW),
    "pip": ("Python wheel cache. Re-downloaded on next install.", Risk.SAFE),
    "uv": ("uv's package cache. Re-downloaded on next sync.", Risk.SAFE),
    "yarn": ("Yarn package cache.", Risk.SAFE),
    "go-build": ("Go build cache. Rebuilt on next compile.", Risk.SAFE),
    "torch": ("Downloaded PyTorch model weights. Large and slow to re-download.", Risk.REVIEW),
    "huggingface": ("Downloaded ML models and datasets. Often many GiB and slow to refetch.", Risk.CAREFUL),
    "whisper": ("Downloaded speech model weights.", Risk.REVIEW),
    "ollama": ("Ollama model blobs. Re-downloading these takes a long time.", Risk.CAREFUL),
    "JetBrains": ("JetBrains IDE caches and indexes. Rebuilt when you reopen a project.", Risk.SAFE),
    "zed": ("Zed editor cache.", Risk.SAFE),
    "tldr": ("Cached tldr pages.", Risk.SAFE),
    "fish": ("Fish shell's generated completions.", Risk.SAFE),
    "paru": ("Handled under AUR helper caches.", Risk.SAFE),
    "yay": ("Handled under AUR helper caches.", Risk.SAFE),
    "flutter_local": ("Flutter tool cache. Rebuilt by the SDK.", Risk.SAFE),
    "electron": ("Downloaded Electron runtimes.", Risk.REVIEW),
    "typescript": ("TypeScript language server cache.", Risk.SAFE),
    "puppeteer": ("Chromium builds downloaded by Puppeteer.", Risk.REVIEW),
    "ms-playwright": ("Browser builds downloaded by Playwright.", Risk.REVIEW),
}

#: Skipped entirely -- either not a cache or handled by a dedicated scanner.
SKIP = {"paru", "yay", "pikaur", "trizen"}

MIN_SIZE = 5 * 1024 * 1024


def scan_user_cache() -> list[Finding]:
    if not CACHE.is_dir():
        return []
    try:
        entries = [p for p in CACHE.iterdir() if p.name not in SKIP]
    except OSError:
        return []

    sizes = dir_sizes(entries, timeout=600)
    findings = []
    for path in entries:
        size = sizes.get(str(path), 0)
        if size < MIN_SIZE:
            continue
        detail, risk = KNOWN.get(
            path.name,
            ("Cache directory for this application. Most applications rebuild "
             "their cache automatically, but this one is not on our known list.",
             Risk.REVIEW),
        )
        idle = mtime_days(path)
        if idle != float("inf") and idle > 30:
            detail += f" Untouched for {int(idle)} days."
        findings.append(Finding(
            key=f"cache-{path.name}",
            label=path.name,
            detail=detail,
            size=size,
            risk=risk,
            selected=risk is Risk.SAFE,
            action=Action(paths=[str(path)]),
        ))
    return sorted(findings, key=lambda f: f.size, reverse=True)


def scan_trash() -> list[Finding]:
    bases = [
        Path(os.environ.get("XDG_DATA_HOME") or HOME / ".local/share") / "Trash",
        HOME / ".Trash",
    ]
    findings = []
    for base in bases:
        if not base.is_dir():
            continue
        size = dir_size(base)
        if size < 1024:
            continue
        files = base / "files"
        count = 0
        if files.is_dir():
            try:
                count = len(list(files.iterdir()))
            except OSError:
                count = 0
        findings.append(Finding(
            key=f"trash-{base.parent.name}",
            label=f"Trash ({count} items)" if count else "Trash",
            detail="Deleting these is permanent — check the contents first if you are unsure.",
            size=size,
            risk=Risk.REVIEW,
            action=Action(paths=[
                str(base / "files"), str(base / "info"), str(base / "expunged"),
            ]),
        ))
    return findings


def scan_app_leftovers() -> list[Finding]:
    """Config and data directories for applications that are no longer installed.

    Matched conservatively: only reported when the directory name maps to a
    binary that is clearly absent, so we do not propose deleting the data of a
    program that is merely named differently from its folder.
    """
    import shutil

    data = Path(os.environ.get("XDG_DATA_HOME") or HOME / ".local/share")
    candidates: list[Path] = []
    for base in (data,):
        if not base.is_dir():
            continue
        try:
            for path in base.iterdir():
                if not path.is_dir() or path.name.startswith("."):
                    continue
                name = path.name
                if shutil.which(name) or shutil.which(name.lower()):
                    continue
                # Require a long idle time before suggesting anything.
                if mtime_days(path) < 180:
                    continue
                candidates.append(path)
        except OSError:
            continue
    if not candidates:
        return []
    sizes = dir_sizes(candidates, timeout=600)
    findings = []
    for path in candidates:
        size = sizes.get(str(path), 0)
        if size < 20 * 1024 * 1024:
            continue
        findings.append(Finding(
            key=f"leftover-{path.name}",
            label=path.name,
            detail=(
                f"No command named '{path.name}' is on your PATH and this folder has "
                f"not changed in {int(mtime_days(path))} days. It may still belong to "
                "an installed application under a different name — check before deleting."
            ),
            size=size,
            risk=Risk.CAREFUL,
            action=Action(paths=[str(path)]),
        ))
    return sorted(findings, key=lambda f: f.size, reverse=True)


def scanners() -> list[Scanner]:
    return [
        Scanner(
            key="user-cache",
            title="Application caches",
            subtitle=f"Per-application caches under {CACHE}",
            icon="user-home-symbolic",
            run=scan_user_cache,
            note="Clearing a browser cache signs you out of nothing and keeps your history.",
        ),
        Scanner(
            key="trash",
            title="Trash",
            subtitle="Files you deleted but never purged",
            icon="user-trash-symbolic",
            run=scan_trash,
        ),
        Scanner(
            key="app-leftovers",
            title="Data from uninstalled apps",
            subtitle="Long-idle folders whose application is no longer on your PATH",
            icon="edit-find-symbolic",
            run=scan_app_leftovers,
            deep=True,
            note="Guesswork by nature — these are never preselected. Read each one.",
        ),
    ]
