"""Steam, Proton, Wine and other launchers.

Game installs are the biggest thing on many desktops, but they are not junk --
so installed games are reported for context only, with a pointer at the right
way to remove them. What this scanner actually offers to delete is the debris
around them: shader caches, leftover Proton prefixes, abandoned downloads.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from ..model import Action, Finding, Risk, Scanner
from ..system import HOME, dir_size, dir_sizes, mtime_days

STEAM_ROOTS = [
    HOME / ".local/share/Steam",
    HOME / ".steam/steam",
    HOME / ".steam/root",
]


def _steam_root() -> Path | None:
    for root in STEAM_ROOTS:
        if (root / "steamapps").is_dir() and not root.is_symlink():
            return root
    return None


def _library_paths(root: Path) -> list[Path]:
    """Every Steam library on this machine, from libraryfolders.vdf."""
    vdf = root / "steamapps/libraryfolders.vdf"
    paths = [root]
    try:
        text = vdf.read_text(errors="replace")
    except OSError:
        return paths
    for match in re.finditer(r'"path"\s+"([^"]+)"', text):
        p = Path(match.group(1))
        if p.is_dir() and p not in paths:
            paths.append(p)
    return paths


def _installed_appids(library: Path) -> set[str]:
    out = set()
    steamapps = library / "steamapps"
    try:
        for manifest in steamapps.glob("appmanifest_*.acf"):
            match = re.search(r"appmanifest_(\d+)\.acf", manifest.name)
            if match:
                out.add(match.group(1))
    except OSError:
        pass
    return out


def _app_names(library: Path) -> dict[str, str]:
    names = {}
    try:
        for manifest in (library / "steamapps").glob("appmanifest_*.acf"):
            appid = re.search(r"appmanifest_(\d+)\.acf", manifest.name)
            if not appid:
                continue
            text = manifest.read_text(errors="replace")
            name = re.search(r'"name"\s+"([^"]+)"', text)
            names[appid.group(1)] = name.group(1) if name else appid.group(1)
    except OSError:
        pass
    return names


def scan_steam() -> list[Finding]:
    root = _steam_root()
    if root is None:
        return []

    findings: list[Finding] = []
    libraries = _library_paths(root)
    installed: set[str] = set()
    names: dict[str, str] = {}
    for lib in libraries:
        installed |= _installed_appids(lib)
        names |= _app_names(lib)

    for lib in libraries:
        steamapps = lib / "steamapps"

        # Proton prefixes whose game is no longer installed. These hold save
        # games for some titles, so they are never preselected.
        compatdata = steamapps / "compatdata"
        if compatdata.is_dir():
            orphans = [
                d for d in compatdata.iterdir()
                if d.is_dir() and d.name.isdigit() and d.name not in installed
            ]
            sizes = dir_sizes(orphans, timeout=300)
            for d in orphans:
                size = sizes.get(str(d), 0)
                if size < 5 * 1024 * 1024:
                    continue
                findings.append(Finding(
                    key=f"steam-compat-{d.name}",
                    label=f"Proton prefix for uninstalled app {d.name}",
                    detail=(
                        "A Windows prefix left behind after the game was uninstalled. "
                        "For titles that do not use Steam Cloud this is where your "
                        "save games live — check before deleting."
                    ),
                    size=size,
                    risk=Risk.CAREFUL,
                    action=Action(paths=[str(d)]),
                ))

        # Shader caches rebuild themselves on next launch.
        shader = steamapps / "shadercache"
        if shader.is_dir():
            size = dir_size(shader)
            if size > 10 * 1024 * 1024:
                findings.append(Finding(
                    key=f"steam-shader-{lib.name}",
                    label=f"Steam shader cache ({shader})",
                    detail="Precompiled GPU shaders. Rebuilt on next launch, at the cost of some early stutter.",
                    size=size,
                    risk=Risk.SAFE,
                    selected=True,
                    action=Action(paths=[str(shader)]),
                ))

        # Abandoned or interrupted downloads.
        for name, detail in (
            ("downloading", "Partially downloaded game data from an interrupted or paused download."),
            ("temp", "Temporary files from Steam's installer."),
        ):
            d = steamapps / name
            if not d.is_dir():
                continue
            size = dir_size(d)
            if size > 50 * 1024 * 1024:
                findings.append(Finding(
                    key=f"steam-{name}-{lib.name}",
                    label=f"Steam {name} folder ({d})",
                    detail=detail + " Steam re-downloads anything it still needs.",
                    size=size,
                    risk=Risk.REVIEW,
                    action=Action(paths=[str(d)]),
                ))

        # Workshop content for games that are gone.
        workshop = steamapps / "workshop/content"
        if workshop.is_dir():
            orphans = [
                d for d in workshop.iterdir()
                if d.is_dir() and d.name.isdigit() and d.name not in installed
            ]
            sizes = dir_sizes(orphans, timeout=300)
            for d in orphans:
                size = sizes.get(str(d), 0)
                if size < 10 * 1024 * 1024:
                    continue
                findings.append(Finding(
                    key=f"steam-workshop-{d.name}",
                    label=f"Workshop content for uninstalled app {d.name}",
                    detail="Mods and maps for a game you no longer have installed.",
                    size=size,
                    risk=Risk.REVIEW,
                    action=Action(paths=[str(d)]),
                ))

        # Installed games: context only.
        common = steamapps / "common"
        if common.is_dir():
            try:
                games = [d for d in common.iterdir() if d.is_dir()]
            except OSError:
                games = []
            sizes = dir_sizes(games, timeout=600)
            ranked = sorted(games, key=lambda d: sizes.get(str(d), 0), reverse=True)
            for d in ranked[:10]:
                size = sizes.get(str(d), 0)
                if size < 1024**3:
                    continue
                idle = mtime_days(d)
                played = f" Not touched in {int(idle)} days." if idle > 90 else ""
                findings.append(Finding(
                    key=f"steam-game-{d.name}",
                    label=d.name,
                    detail=f"Installed game, {size // 1024**3} GiB.{played}",
                    size=size,
                    risk=Risk.CAREFUL,
                    info_only=True,
                    advice="Uninstall from Steam's library rather than deleting the folder, so Steam's records stay consistent.",
                    action=Action(noop=True),
                ))
    return findings


def scan_proton_runtimes() -> list[Finding]:
    """Proton and Steam Linux Runtime builds, plus umu/Wine runtimes."""
    root = _steam_root()
    findings: list[Finding] = []

    candidates: list[tuple[Path, str, str, Risk]] = []
    if root:
        compat = root / "compatibilitytools.d"
        if compat.is_dir():
            try:
                for d in compat.iterdir():
                    if d.is_dir():
                        candidates.append((
                            d, f"Custom Proton build: {d.name}",
                            "A Proton-GE or similar build you installed by hand. "
                            "Games configured to use it will fall back to stock Proton.",
                            Risk.REVIEW,
                        ))
            except OSError:
                pass

    umu = HOME / ".local/share/umu"
    if umu.is_dir():
        try:
            for d in umu.iterdir():
                if d.is_dir() and d.name.startswith("steamrt"):
                    candidates.append((
                        d, f"umu runtime: {d.name}",
                        "Steam Linux Runtime used by umu/Proton outside Steam. "
                        "Re-downloaded on the next launch.",
                        Risk.REVIEW,
                    ))
        except OSError:
            pass

    for rel, label, detail, risk in (
        (".cache/wine", "Wine component cache",
         "Installers Wine downloaded (mono, gecko). Re-fetched when a prefix needs them.", Risk.SAFE),
        (".cache/winetricks", "winetricks downloads",
         "Redistributables downloaded by winetricks. Re-downloaded on demand.", Risk.REVIEW),
        (".cache/lutris", "Lutris cache",
         "Installer downloads and banners. Regenerated by Lutris.", Risk.SAFE),
        (".cache/heroic", "Heroic cache",
         "Metadata and images cached by Heroic Games Launcher.", Risk.SAFE),
        (".local/share/bottles/temp", "Bottles temporary files",
         "Installer downloads kept by Bottles.", Risk.SAFE),
    ):
        p = HOME / rel
        if p.is_dir():
            candidates.append((p, f"{label} (~/{rel})", detail, risk))

    sizes = dir_sizes([p for p, *_ in candidates], timeout=600)
    for path, label, detail, risk in candidates:
        size = sizes.get(str(path), 0)
        if size < 10 * 1024 * 1024:
            continue
        findings.append(Finding(
            key=f"runtime-{path.as_posix().replace('/', '-')}",
            label=label,
            detail=detail,
            size=size,
            risk=risk,
            selected=risk is Risk.SAFE,
            action=Action(paths=[str(path)]),
        ))
    return sorted(findings, key=lambda f: f.size, reverse=True)


def scanners() -> list[Scanner]:
    return [
        Scanner(
            key="steam",
            title="Steam",
            subtitle="Shader caches, orphaned Proton prefixes, stalled downloads",
            icon="input-gaming-symbolic",
            run=scan_steam,
            available=lambda: _steam_root() is not None,
            unavailable_note="No Steam installation found",
            note="Installed games are listed for context only — uninstall those through Steam.",
        ),
        Scanner(
            key="proton",
            title="Proton and Wine runtimes",
            subtitle="Compatibility tools and launcher caches",
            icon="application-x-executable-symbolic",
            run=scan_proton_runtimes,
        ),
    ]
