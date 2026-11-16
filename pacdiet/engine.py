"""Orchestration: run scanners concurrently, then execute what the user picked."""

from __future__ import annotations

import shutil
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Sequence

from .model import Action, Category, Finding, Risk, Scanner
from .scanners import all_scanners
from .system import Denied, build_root_script, delete_paths, run_root_script, run_user_command

ProgressFn = Callable[[str, int, int], None]
CategoryFn = Callable[[Category], None]


@dataclass
class DiskUsage:
    total: int
    used: int
    free: int

    @property
    def percent(self) -> float:
        return (self.used / self.total * 100) if self.total else 0.0


def disk_usage(path: str | Path = Path.home()) -> DiskUsage:
    usage = shutil.disk_usage(str(path))
    return DiskUsage(usage.total, usage.used, usage.free)


@dataclass
class ScanResult:
    categories: list[Category] = field(default_factory=list)

    @property
    def total(self) -> int:
        return sum(c.total for c in self.categories)

    @property
    def selected_size(self) -> int:
        return sum(c.selected_size for c in self.categories)

    def selected(self) -> list[Finding]:
        out: list[Finding] = []
        for cat in self.categories:
            out.extend(cat.selected_findings)
        return out


def _sanitise(findings: list[Finding]) -> list[Finding]:
    """Enforce the invariants no scanner is trusted to get right on its own.

    The rule that matters: anything rated above SAFE arrives deselected. A
    scanner that preselects a Careful finding would let one click destroy
    something the user wanted -- removing every "orphan" package, for
    instance, which on Arch includes tools the user installed themselves.
    Rather than relying on every scanner author to remember this, it is
    imposed here, once, for all of them.
    """
    for finding in findings:
        if finding.info_only:
            finding.selected = False
        elif finding.risk > Risk.SAFE and finding.selected:
            finding.selected = False
    return findings


def scan(
    deep: bool = False,
    only: Sequence[str] | None = None,
    on_progress: ProgressFn | None = None,
    on_category: CategoryFn | None = None,
    cancelled: Callable[[], bool] | None = None,
    workers: int = 6,
) -> ScanResult:
    """Run every applicable scanner. Scanners are independent, so they run in
    parallel -- most of their time is spent waiting on `du` and `find`."""

    scanners = [s for s in all_scanners() if deep or not s.deep]
    if only:
        wanted = set(only)
        scanners = [s for s in scanners if s.key in wanted]

    total = len(scanners)
    done = 0
    result = ScanResult()

    def report(title: str) -> None:
        nonlocal done
        done += 1
        if on_progress:
            on_progress(title, done, total)

    def work(scanner: Scanner) -> Category:
        category = scanner.make_category()
        if not scanner.is_available():
            category.skipped = scanner.unavailable_note
            return category
        if cancelled and cancelled():
            category.skipped = "Cancelled"
            return category
        try:
            category.findings = _sanitise(list(scanner.run()))
        except Exception as exc:  # a broken scanner must not sink the scan
            category.error = f"{type(exc).__name__}: {exc}"
            traceback.print_exc()
        return category

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(work, s): s for s in scanners}
        for future in as_completed(futures):
            scanner = futures[future]
            category = future.result()
            result.categories.append(category)
            if on_category:
                on_category(category)
            report(scanner.title)

    order = {s.key: i for i, s in enumerate(all_scanners())}
    result.categories.sort(key=lambda c: order.get(c.key, 999))
    return result


# ---------------------------------------------------------------------------
# Execution


@dataclass
class Plan:
    """Everything the user ticked, split by what privilege it needs."""

    user_paths: list[str] = field(default_factory=list)
    user_commands: list[Sequence[str]] = field(default_factory=list)
    root_paths: list[str] = field(default_factory=list)
    root_commands: list[Sequence[str]] = field(default_factory=list)
    size: int = 0
    count: int = 0

    @property
    def needs_root(self) -> bool:
        return bool(self.root_paths or self.root_commands)

    @property
    def empty(self) -> bool:
        return not (self.user_paths or self.user_commands or self.needs_root)


def build_plan(findings: Iterable[Finding]) -> Plan:
    """Turn ticked findings into a plan.

    Defence in depth: this re-checks `selected` rather than trusting the
    caller to have filtered already, so a plan can never contain an item the
    user did not tick -- even if a future caller forgets to filter.
    """
    plan = Plan()
    for finding in findings:
        action = finding.action
        if action.noop or finding.info_only or not finding.selected:
            continue
        plan.size += finding.size
        plan.count += 1
        if action.root:
            plan.root_paths.extend(action.paths)
            if action.command:
                plan.root_commands.append(list(action.command))
        else:
            plan.user_paths.extend(action.paths)
            if action.command:
                plan.user_commands.append(list(action.command))
    return plan


def preview(plan: Plan) -> str:
    """A human-readable dry run: exactly what will happen, before it happens."""
    out: list[str] = []
    if plan.user_paths:
        out.append("Delete as you:")
        out += [f"  rm -rf {p}" for p in plan.user_paths]
    if plan.user_commands:
        out.append("Run as you:")
        out += [f"  {' '.join(c)}" for c in plan.user_commands]
    if plan.root_paths:
        out.append("Delete as root:")
        out += [f"  rm -rf {p}" for p in plan.root_paths]
    if plan.root_commands:
        out.append("Run as root:")
        out += [f"  {' '.join(c)}" for c in plan.root_commands]
    return "\n".join(out) or "Nothing selected."


@dataclass
class Outcome:
    freed: int = 0
    log: list[str] = field(default_factory=list)
    denied: bool = False
    message: str = ""


def execute(plan: Plan, dry_run: bool = False) -> Outcome:
    """Carry out the plan. User-level work happens in-process; everything
    privileged is batched into a single pkexec call so the user authenticates
    once rather than per item."""

    outcome = Outcome()
    if dry_run:
        outcome.log.append("DRY RUN — nothing was deleted.")
        outcome.log.extend(preview(plan).splitlines())
        return outcome

    if plan.user_paths:
        outcome.freed += delete_paths(plan.user_paths, outcome.log)
    for cmd in plan.user_commands:
        run_user_command(cmd, outcome.log)

    if plan.needs_root:
        script = build_root_script(plan.root_paths, plan.root_commands)
        try:
            run_root_script(script, outcome.log)
        except Denied as exc:
            outcome.denied = True
            outcome.message = str(exc)
            outcome.log.append(f"skipped privileged actions: {exc}")

    return outcome
