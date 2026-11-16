"""Entry point.

With no arguments and a display present, pacdiet opens its window. Pass --cli
to force the terminal front end; any other argument implies it.
"""

from __future__ import annotations

import os
import sys


def _has_display() -> bool:
    return bool(os.environ.get("WAYLAND_DISPLAY") or os.environ.get("DISPLAY"))


def main() -> int:
    args = sys.argv[1:]
    force_gui = "--gui" in args
    force_cli = "--cli" in args
    args = [a for a in args if a not in ("--gui", "--cli")]

    if force_gui or (not force_cli and not args and _has_display()):
        from .ui.window import PacdietApp
        return PacdietApp().run([sys.argv[0]])

    from .cli import main as cli_main
    return cli_main(args)


if __name__ == "__main__":
    sys.exit(main())
