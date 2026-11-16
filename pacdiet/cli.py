"""Terminal front end. Same engine as the GUI, for servers and scripts."""

from __future__ import annotations

import argparse
import sys

from .engine import build_plan, disk_usage, execute, preview, scan
from .model import Risk, human

RISK_BY_NAME = {"safe": Risk.SAFE, "review": Risk.REVIEW, "all": Risk.CAREFUL}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pacdiet",
        description="Find and reclaim wasted disk space on Arch Linux.",
    )
    parser.add_argument("--deep", action="store_true",
                        help="also scan for build output, duplicates and large files")
    parser.add_argument("--only", metavar="KEY", action="append",
                        help="limit the scan to this scanner (repeatable)")
    parser.add_argument("--clean", action="store_true",
                        help="delete the matching items instead of only listing them")
    parser.add_argument("--risk", choices=sorted(RISK_BY_NAME), default="safe",
                        help="highest risk tier to select when cleaning (default: safe)")
    parser.add_argument("--dry-run", action="store_true",
                        help="with --clean, print the exact commands without running them")
    parser.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    args = parser.parse_args(argv)

    before = disk_usage("/")
    print(f"Disk: {human(before.used)} of {human(before.total)} used "
          f"({before.percent:.0f}%), {human(before.free)} free\n")

    result = scan(
        deep=args.deep,
        only=args.only,
        on_progress=lambda title, done, total: print(
            f"  [{done:>2}/{total}] {title}", file=sys.stderr
        ),
    )
    print(file=sys.stderr)

    threshold = RISK_BY_NAME[args.risk]
    for category in result.categories:
        if not category.findings:
            continue
        print(f"{category.title}  —  {human(category.total)}")
        for finding in category.findings:
            if finding.info_only:
                mark = "i"
            else:
                finding.selected = finding.risk <= threshold
                mark = "x" if finding.selected else " "
            print(f"  [{mark}] {finding.risk.label:<7} {human(finding.size):>10}  {finding.label}")
        print()

    plan = build_plan(result.selected())
    print(f"Total reclaimable: {human(result.total)}")
    print(f"Selected at risk tier '{args.risk}': {plan.count} items, {human(plan.size)}")

    if not args.clean:
        print("\nRun again with --clean to act on the selection.")
        return 0
    if plan.empty:
        print("\nNothing selected.")
        return 0

    print("\n" + preview(plan))
    if not args.yes and not args.dry_run:
        answer = input(f"\nDelete {plan.count} items ({human(plan.size)})? [y/N] ")
        if answer.strip().lower() not in ("y", "yes"):
            print("Cancelled.")
            return 1

    outcome = execute(plan, dry_run=args.dry_run)
    print()
    for line in outcome.log:
        print(line)
    if outcome.denied:
        print(f"\n{outcome.message}", file=sys.stderr)
        return 1
    if not args.dry_run:
        after = disk_usage("/")
        print(f"\nFree space: {human(before.free)} -> {human(after.free)} "
              f"({human(after.free - before.free)} reclaimed)")
    return 0
