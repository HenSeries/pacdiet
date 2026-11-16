"""Scanner modules. Each exposes `scanners()` returning a list of Scanner."""

from __future__ import annotations

from ..model import Scanner
from . import bigstuff, containers, dev, games, packages, system_junk, user_caches

MODULES = (packages, system_junk, user_caches, dev, containers, games, bigstuff)


def all_scanners() -> list[Scanner]:
    found: list[Scanner] = []
    for module in MODULES:
        found.extend(module.scanners())
    return found
