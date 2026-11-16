"""Finding space that no rule can classify: big files, duplicates, old downloads.

These scanners cannot know what matters to you, so nothing here is ever
preselected. They exist because after the mechanical cleanups are done, what is
left is usually one forgotten folder of ISOs.
"""

from __future__ import annotations

import hashlib
import os
from collections import defaultdict
from pathlib import Path

from ..model import Action, Finding, Risk, Scanner
from ..system import HOME, dir_sizes, file_size, mtime_days, run

BIG_FILE_MIN = 200 * 1024 * 1024
DOWNLOAD_AGE = 60

#: Installer and image types that are usually safe to re-download.
DISPOSABLE_SUFFIXES = {
    ".iso", ".img", ".exe", ".msi", ".appimage", ".deb", ".rpm",
    ".pkg.tar.zst", ".pkg.tar.xz", ".dmg", ".apk", ".zip", ".tar.gz",
    ".tar.xz", ".tar.zst", ".7z", ".rar",
}

#: Download directories across the common locales -- Arch users are everywhere.
DOWNLOAD_NAMES = (
    "Downloads", "Descargas", "Téléchargements", "Downloads", "Baixados",
    "Descàrregues", "Downloaded", "Загрузки", "下载", "ダウンロード",
)


def _xdg_download() -> list[Path]:
    found = []
    proc = run(["xdg-user-dir", "DOWNLOAD"], timeout=10)
    if proc.returncode == 0 and proc.stdout.strip():
        p = Path(proc.stdout.strip())
        if p.is_dir() and p != HOME:
            found.append(p)
    for name in DOWNLOAD_NAMES:
        p = HOME / name
        if p.is_dir() and p not in found:
            found.append(p)
    return found


def _visible_roots() -> list[str]:
    roots = []
    try:
        for entry in HOME.iterdir():
            if entry.is_dir() and not entry.name.startswith(".") and not entry.is_symlink():
                roots.append(str(entry))
    except OSError:
        pass
    return roots


def scan_big_files(timeout: int = 600) -> list[Finding]:
    roots = _visible_roots()
    if not roots:
        return []
    proc = run(
        ["find", *roots, "-xdev", "-type", "f", "-size", f"+{BIG_FILE_MIN // 1024}k", "-print"],
        timeout=timeout,
    )
    paths = [p for p in proc.stdout.splitlines() if p.strip()]
    sized = sorted(((file_size(p), p) for p in paths), reverse=True)[:60]

    findings = []
    for size, path in sized:
        if size < BIG_FILE_MIN:
            continue
        p = Path(path)
        suffix = "".join(p.suffixes[-2:]).lower()
        disposable = any(suffix.endswith(s) for s in DISPOSABLE_SUFFIXES)
        idle = mtime_days(p)
        detail = f"Last modified {int(idle)} days ago." if idle != float("inf") else ""
        if disposable:
            detail += " Looks like an installer or disk image — usually re-downloadable."
        findings.append(Finding(
            key=f"big-{path}",
            label=f"{p.name}  —  {p.parent}",
            detail=detail.strip() or str(p),
            size=size,
            risk=Risk.CAREFUL,
            action=Action(paths=[path]),
        ))
    if proc.returncode == 124:
        findings.insert(0, Finding(
            key="big-partial",
            label="(scan hit its time limit — results are incomplete)",
            detail="Your home directory is large; not every file was examined.",
            size=0,
            risk=Risk.CAREFUL,
            info_only=True,
            action=Action(noop=True),
        ))
    return findings


def scan_old_downloads() -> list[Finding]:
    findings = []
    for folder in _xdg_download():
        try:
            entries = list(folder.iterdir())
        except OSError:
            continue
        stale = [p for p in entries if mtime_days(p) > DOWNLOAD_AGE]
        if not stale:
            continue
        sizes = dir_sizes(stale, timeout=300)
        ranked = sorted(stale, key=lambda p: sizes.get(str(p), 0), reverse=True)
        for p in ranked[:40]:
            size = sizes.get(str(p), 0)
            if size < 10 * 1024 * 1024:
                continue
            findings.append(Finding(
                key=f"dl-{p}",
                label=p.name,
                detail=(
                    f"In {folder}, untouched for {int(mtime_days(p))} days. "
                    "Downloads are the one folder almost everyone forgets to empty."
                ),
                size=size,
                risk=Risk.CAREFUL,
                action=Action(paths=[str(p)]),
            ))
    return findings


def _partial_hash(path: str, chunk: int = 65536) -> str | None:
    """Hash the first and last chunk. Cheap way to rule out most non-duplicates."""
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as fh:
            head = fh.read(chunk)
            if size > chunk * 2:
                fh.seek(-chunk, os.SEEK_END)
                tail = fh.read(chunk)
            else:
                tail = b""
        return hashlib.blake2b(head + tail, digest_size=16).hexdigest()
    except OSError:
        return None


def _full_hash(path: str) -> str | None:
    try:
        digest = hashlib.blake2b(digest_size=16)
        with open(path, "rb") as fh:
            for block in iter(lambda: fh.read(1024 * 1024), b""):
                digest.update(block)
        return digest.hexdigest()
    except OSError:
        return None


def scan_duplicates(min_size: int = 20 * 1024 * 1024, timeout: int = 600) -> list[Finding]:
    """Identical files, found by size, then partial hash, then full hash.

    Only the *extra* copies count toward the reclaimable total; the first copy
    of each set is listed as context and cannot be selected.
    """
    roots = _visible_roots()
    if not roots:
        return []
    proc = run(
        ["find", *roots, "-xdev", "-type", "f", "-size", f"+{min_size // 1024}k", "-print"],
        timeout=timeout,
    )
    by_size: dict[int, list[str]] = defaultdict(list)
    for path in proc.stdout.splitlines():
        if not path.strip():
            continue
        size = file_size(path)
        if size >= min_size:
            by_size[size].append(path)

    groups: list[tuple[int, list[str]]] = []
    for size, paths in by_size.items():
        if len(paths) < 2:
            continue
        by_partial: dict[str, list[str]] = defaultdict(list)
        for p in paths:
            h = _partial_hash(p)
            if h:
                by_partial[h].append(p)
        for candidates in by_partial.values():
            if len(candidates) < 2:
                continue
            by_full: dict[str, list[str]] = defaultdict(list)
            for p in candidates:
                h = _full_hash(p)
                if h:
                    by_full[h].append(p)
            for identical in by_full.values():
                if len(identical) > 1:
                    groups.append((size, sorted(identical)))

    groups.sort(key=lambda g: g[0] * (len(g[1]) - 1), reverse=True)
    findings: list[Finding] = []
    for size, paths in groups[:40]:
        keep, extras = paths[0], paths[1:]
        findings.append(Finding(
            key=f"dup-keep-{keep}",
            label=f"Keeping: {keep}",
            detail=f"{len(paths)} identical copies of this file, {size // 1024**2} MiB each.",
            size=size,
            risk=Risk.CAREFUL,
            info_only=True,
            advice="This copy is left alone. The duplicates below it can be removed.",
            action=Action(noop=True),
        ))
        for extra in extras:
            findings.append(Finding(
                key=f"dup-{extra}",
                label=f"Duplicate: {extra}",
                detail="Byte-for-byte identical to the file above.",
                size=size,
                risk=Risk.CAREFUL,
                action=Action(paths=[extra]),
            ))
    return findings


def scanners() -> list[Scanner]:
    return [
        Scanner(
            key="old-downloads",
            title="Forgotten downloads",
            subtitle=f"Items in your download folders older than {DOWNLOAD_AGE} days",
            icon="folder-download-symbolic",
            run=scan_old_downloads,
            deep=True,
        ),
        Scanner(
            key="big-files",
            title="Largest files",
            subtitle=f"Individual files over {BIG_FILE_MIN // 1024**2} MiB in your home directory",
            icon="drive-harddisk-symbolic",
            run=scan_big_files,
            deep=True,
            note="Listed so you can see where the space actually went. Nothing here is preselected.",
        ),
        Scanner(
            key="duplicates",
            title="Duplicate files",
            subtitle="Byte-for-byte identical copies over 20 MiB",
            icon="edit-copy-symbolic",
            run=scan_duplicates,
            deep=True,
            note="Verified by full content hash, not by name. One copy of each set is always kept.",
        ),
    ]
