"""Core data model: what a scanner finds and how it gets cleaned."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Callable, Iterable, Sequence


class Risk(enum.IntEnum):
    """How much thought a finding deserves before you delete it."""

    SAFE = 0      # regenerated automatically, no history lost
    REVIEW = 1    # fine for most people, but worth a glance
    CAREFUL = 2   # you may actually want this; never preselected

    @property
    def label(self) -> str:
        return {Risk.SAFE: "Safe", Risk.REVIEW: "Review", Risk.CAREFUL: "Careful"}[self]

    @property
    def css_class(self) -> str:
        return {Risk.SAFE: "risk-safe", Risk.REVIEW: "risk-review", Risk.CAREFUL: "risk-careful"}[self]


@dataclass
class Action:
    """One concrete thing to do to reclaim space.

    Either a list of paths to delete, or a shell command to run (for things
    like `paccache` and `journalctl --vacuum-size` that know better than we do).
    """

    paths: Sequence[str] = ()
    command: Sequence[str] = ()
    root: bool = False

    #: An Action with neither paths nor a command is a no-op, used by
    #: informational findings that only tell the user where to look.
    noop: bool = False

    def __post_init__(self) -> None:
        if not self.paths and not self.command and not self.noop:
            raise ValueError("an Action needs either paths, a command, or noop=True")


@dataclass
class Finding:
    """A single reclaimable item shown as one row in the UI."""

    key: str
    label: str
    size: int
    action: Action
    detail: str = ""
    risk: Risk = Risk.SAFE
    selected: bool = False
    #: Shown for context but not deletable here -- e.g. an installed game that
    #: should be removed through its own launcher. Excluded from every total.
    info_only: bool = False
    #: What to do instead, when info_only is set.
    advice: str = ""

    @property
    def needs_root(self) -> bool:
        return self.action.root


@dataclass
class Category:
    """A group of findings produced by one scanner."""

    key: str
    title: str
    subtitle: str
    icon: str
    findings: list[Finding] = field(default_factory=list)
    note: str = ""
    error: str = ""
    skipped: str = ""

    @property
    def reclaimable(self) -> list[Finding]:
        return [f for f in self.findings if not f.info_only]

    @property
    def total(self) -> int:
        return sum(f.size for f in self.reclaimable)

    @property
    def selected_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.selected and not f.info_only]

    @property
    def selected_size(self) -> int:
        return sum(f.size for f in self.selected_findings)


@dataclass
class Scanner:
    """Metadata plus the callable that does the work."""

    key: str
    title: str
    subtitle: str
    icon: str
    run: Callable[[], Iterable[Finding]]
    note: str = ""
    deep: bool = False          # only runs when deep scan is enabled
    available: Callable[[], bool] | None = None
    unavailable_note: str = "Not applicable on this system"

    def is_available(self) -> bool:
        return self.available() if self.available else True

    def make_category(self) -> Category:
        return Category(self.key, self.title, self.subtitle, self.icon, note=self.note)


def human(size: int) -> str:
    """Format bytes the way disk tools do (base 1024, one decimal)."""
    if size < 0:
        return "?"
    units = ("B", "KiB", "MiB", "GiB", "TiB")
    value = float(size)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            if unit == "B":
                return f"{int(value)} {unit}"
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TiB"
