"""Logs, crash dumps and other system-level accumulation."""

from __future__ import annotations

import re
from pathlib import Path

from ..model import Action, Finding, Risk, Scanner
from ..system import dir_size, dir_sizes, file_size, have, mtime_days, run

JOURNAL_KEEP = "500M"
JOURNAL_KEEP_TIME = "2weeks"


def _journal_bytes() -> int:
    proc = run(["journalctl", "--disk-usage"], timeout=30)
    match = re.search(r"take up ([\d.,]+)([KMGT])", proc.stdout)
    if not match:
        return 0
    value = float(match.group(1).replace(",", "."))
    factor = {"K": 1024, "M": 1024**2, "G": 1024**3, "T": 1024**4}
    return int(value * factor[match.group(2)])


def scan_journal() -> list[Finding]:
    total = _journal_bytes()
    if total <= 0:
        return []
    findings = []
    keep_bytes = 500 * 1024**2
    if total > keep_bytes:
        findings.append(Finding(
            key="journal-size",
            label=f"Trim the systemd journal to {JOURNAL_KEEP}",
            detail=(
                f"The journal currently holds {total // 1024**2} MiB. Older entries are "
                "dropped; recent logs — the ones you would actually read when "
                "something breaks — are kept."
            ),
            size=total - keep_bytes,
            risk=Risk.SAFE,
            selected=True,
            action=Action(command=["journalctl", f"--vacuum-size={JOURNAL_KEEP}"], root=True),
        ))
    findings.append(Finding(
        key="journal-time",
        label=f"Drop journal entries older than {JOURNAL_KEEP_TIME}",
        detail="An alternative to the size cap above. Pick one, not both.",
        size=0,
        risk=Risk.REVIEW,
        action=Action(command=["journalctl", f"--vacuum-time={JOURNAL_KEEP_TIME}"], root=True),
    ))
    return findings


def scan_coredumps() -> list[Finding]:
    path = Path("/var/lib/systemd/coredump")
    if not path.is_dir():
        return []
    size = dir_size(path)
    if size < 1024 * 1024:
        return []
    try:
        count = len(list(path.iterdir()))
    except OSError:
        count = 0
    return [Finding(
        key="coredumps",
        label=f"Crash dumps ({count} files)",
        detail=(
            "Memory images written when a program crashed. Only useful if you are "
            "debugging that specific crash right now."
        ),
        size=size,
        risk=Risk.SAFE,
        selected=True,
        action=Action(command=["find", str(path), "-mindepth", "1", "-delete"], root=True),
    )]


def scan_old_logs() -> list[Finding]:
    """Rotated and compressed logs under /var/log, plus a few known hogs."""
    log_dir = Path("/var/log")
    if not log_dir.is_dir():
        return []

    rotated = run(
        [
            "find", str(log_dir), "-type", "f",
            "(", "-name", "*.gz", "-o", "-name", "*.xz", "-o", "-name", "*.zst",
            "-o", "-name", "*.old", "-o", "-name", "*.[0-9]",
            "-o", "-name", "*-[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]", ")",
        ],
        timeout=90,
    )
    paths = [p for p in rotated.stdout.splitlines() if p.strip()]
    findings = []
    if paths:
        total = sum(file_size(p) for p in paths)
        if total > 1024 * 1024:
            findings.append(Finding(
                key="logs-rotated",
                label=f"Rotated log archives ({len(paths)} files)",
                detail="Compressed copies of logs that have already been superseded.",
                size=total,
                risk=Risk.SAFE,
                selected=True,
                action=Action(paths=paths, root=True),
            ))

    # Stale per-user and per-service log trees, e.g. an old journal namespace
    for sub in ("old", "journal.old"):
        p = log_dir / sub
        if p.is_dir():
            size = dir_size(p)
            if size > 1024 * 1024:
                findings.append(Finding(
                    key=f"logs-{sub}",
                    label=f"/var/log/{sub}",
                    detail="A leftover log directory from an earlier rotation or migration.",
                    size=size,
                    risk=Risk.SAFE,
                    selected=True,
                    action=Action(paths=[str(p)], root=True),
                ))
    return findings


MISC_SYSTEM = [
    ("/var/cache/fwupd", "Firmware update cache", "Downloaded firmware images and metadata. Re-fetched when needed.", Risk.SAFE),
    ("/var/cache/man", "Pre-formatted man pages", "Regenerated the next time you open the page.", Risk.SAFE),
    ("/var/cache/PackageKit", "PackageKit cache", "Metadata for the PackageKit abstraction layer.", Risk.SAFE),
    ("/var/cache/swcatalog", "Software catalog cache", "AppStream metadata, refreshed automatically.", Risk.SAFE),
    ("/var/cache/cups", "CUPS cache", "Printer driver and job caches.", Risk.SAFE),
    ("/var/tmp/pamac", "Pamac temporary files", "Build leftovers from the Pamac helper.", Risk.SAFE),
    ("/var/lib/libvirt/qemu/snapshot", "libvirt VM snapshots", "Saved virtual machine states. Deleting loses those snapshots.", Risk.CAREFUL),
]


def scan_misc_system() -> list[Finding]:
    present = [(Path(p), *rest) for p, *rest in MISC_SYSTEM if Path(p).is_dir()]
    sizes = dir_sizes([p for p, *_ in present])
    findings = []
    for path, title, detail, risk in present:
        size = sizes.get(str(path), 0)
        if size < 1024 * 1024:
            continue
        findings.append(Finding(
            key=f"sys-{path.as_posix().strip('/').replace('/', '-')}",
            label=f"{title} ({path})",
            detail=detail,
            size=size,
            risk=risk,
            selected=risk is Risk.SAFE,
            action=Action(
                command=["find", str(path), "-mindepth", "1", "-delete"],
                root=True,
            ),
        ))
    return findings


def scan_tmp() -> list[Finding]:
    """Files in /tmp and /var/tmp older than a week.

    /tmp is usually a tmpfs and so costs RAM rather than disk, but /var/tmp
    survives reboots and does accumulate.
    """
    findings = []
    for base, days in (("/var/tmp", 7), ("/tmp", 7)):
        root = Path(base)
        if not root.is_dir():
            continue
        stale = [
            p for p in root.iterdir()
            if mtime_days(p) > days and not p.name.startswith(("systemd-", ".X11-unix", ".ICE-"))
        ]
        if not stale:
            continue
        sizes = dir_sizes(stale)
        total = sum(sizes.values())
        if total < 1024 * 1024:
            continue
        findings.append(Finding(
            key=f"tmp-{root.name}",
            label=f"{base}: {len(stale)} items untouched for over a week",
            detail="Temporary files that no running program has needed in days.",
            size=total,
            risk=Risk.REVIEW,
            action=Action(paths=[str(p) for p in stale], root=True),
        ))
    return findings


def scanners() -> list[Scanner]:
    return [
        Scanner(
            key="journal",
            title="System journal",
            subtitle="systemd logs under /var/log/journal",
            icon="document-properties-symbolic",
            run=scan_journal,
            note="To stop it growing again, set SystemMaxUse=500M in /etc/systemd/journald.conf.",
            available=lambda: have("journalctl"),
        ),
        Scanner(
            key="coredumps",
            title="Crash dumps",
            subtitle="Core files saved by systemd-coredump",
            icon="dialog-warning-symbolic",
            run=scan_coredumps,
        ),
        Scanner(
            key="logs",
            title="Rotated logs",
            subtitle="Archived log files under /var/log",
            icon="text-x-generic-symbolic",
            run=scan_old_logs,
        ),
        Scanner(
            key="misc-system",
            title="System caches",
            subtitle="Firmware, man pages, printer and metadata caches",
            icon="drive-harddisk-symbolic",
            run=scan_misc_system,
        ),
        Scanner(
            key="tmp",
            title="Stale temporary files",
            subtitle="Items in /tmp and /var/tmp older than a week",
            icon="folder-temporary-symbolic",
            run=scan_tmp,
        ),
    ]
