"""Fast invariant checks. Run: python3 tests_quick.py"""
import sys
from pacdiet.engine import _sanitise, build_plan, preview
from pacdiet.model import Action, Finding, Risk
from pacdiet.system import is_protected
from pacdiet.scanners import all_scanners

fails = []

def check(name, cond):
    print(("  ok   " if cond else "  FAIL ") + name)
    if not cond:
        fails.append(name)

print("invariant: nothing above SAFE is preselected")
f = [
    Finding("a", "safe", 1, Action(paths=["/tmp/x"]), risk=Risk.SAFE, selected=True),
    Finding("b", "review", 1, Action(paths=["/tmp/y"]), risk=Risk.REVIEW, selected=True),
    Finding("c", "careful", 1, Action(paths=["/tmp/z"]), risk=Risk.CAREFUL, selected=True),
    Finding("d", "info", 1, Action(noop=True), risk=Risk.SAFE, selected=True, info_only=True),
]
_sanitise(f)
check("SAFE stays selected", f[0].selected)
check("REVIEW deselected", not f[1].selected)
check("CAREFUL deselected", not f[2].selected)
check("info_only deselected", not f[3].selected)

print("\ninvariant: protected paths are refused")
for p in ("/", "/home", "/usr", "/home/hen", "/home/hen/.cache",
          "/home/hen/.ssh", "/home/hen/.gnupg", "/etc", "/boot", "relative/path"):
    check(f"refuses {p}", is_protected(p))
for p in ("/home/hen/.cache/epsi", "/var/cache/pacman/pkg/foo.pkg.tar.zst"):
    check(f"allows {p}", not is_protected(p))

print("\ninvariant: a plan contains only ticked, actionable items")
plan = build_plan(f)   # deliberately passing ALL findings, not just selected
check("unticked items excluded", plan.user_paths == ["/tmp/x"])
check("info_only excluded", plan.count == 1)
f[1].selected = True   # user ticks the REVIEW item explicitly
check("explicitly ticked item included", build_plan(f).user_paths == ["/tmp/x", "/tmp/y"])

print("\ninvariant: no scanner preselects above SAFE (static check)")
import inspect, re
for mod in {s.run.__module__ for s in all_scanners()}:
    src = inspect.getsource(sys.modules[mod])
    for block in re.findall(r"Finding\((?:[^()]|\([^()]*\))*\)", src):
        if "selected=True" in block and "Risk.SAFE" not in block:
            check(f"{mod}: preselect without SAFE", False)
check("all scanner sources clean", True)

print("\ninvariant: every scanner is importable and declares metadata")
for sc in all_scanners():
    check(f"{sc.key} well-formed", bool(sc.key and sc.title and sc.icon and callable(sc.run)))

print()
if fails:
    print(f"{len(fails)} FAILURES"); sys.exit(1)
print("all checks passed")
