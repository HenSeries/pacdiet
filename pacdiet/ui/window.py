"""The main window.

Layout is three stack pages -- welcome, scanning, results -- plus a log page,
with a persistent bottom bar showing what is selected and the button that acts
on it. Scanning happens on a worker thread; every UI touch goes through
GLib.idle_add.
"""

from __future__ import annotations

import threading
from pathlib import Path

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gdk, GLib, Gtk  # noqa: E402

#: libadwaita renamed its dialogs in 1.5. Prefer the new names, fall back to
#: the old ones so the app still runs on an older libadwaita.
AlertDialog = getattr(Adw, "AlertDialog", None) or Adw.MessageDialog
AboutDialog = getattr(Adw, "AboutDialog", None) or Adw.AboutWindow
HAS_NEW_DIALOGS = hasattr(Adw, "AlertDialog")

from ..engine import build_plan, disk_usage, execute, preview, scan
from ..model import Category, Finding, Risk, human  # noqa: E402

APP_ID = "io.github.henseries.pacdiet"


def _pill(risk: Risk) -> Gtk.Label:
    label = Gtk.Label(label=risk.label.upper())
    label.add_css_class("risk-pill")
    label.add_css_class(risk.css_class)
    label.set_valign(Gtk.Align.CENTER)
    return label


class FindingRow(Adw.ActionRow):
    """One reclaimable item, with its checkbox, size and risk tier."""

    def __init__(self, finding: Finding, on_toggle) -> None:
        super().__init__()
        self.finding = finding
        self._on_toggle = on_toggle

        self.set_title(GLib.markup_escape_text(finding.label))
        subtitle = finding.detail
        if finding.info_only and finding.advice:
            subtitle = f"{subtitle} — {finding.advice}" if subtitle else finding.advice
        if subtitle:
            self.set_subtitle(GLib.markup_escape_text(subtitle))
        self.set_subtitle_lines(3)
        self.set_title_lines(2)

        self.check: Gtk.CheckButton | None = None
        if finding.info_only:
            icon = Gtk.Image.new_from_icon_name("dialog-information-symbolic")
            icon.set_valign(Gtk.Align.CENTER)
            self.add_prefix(icon)
            self.add_css_class("info-row")
        else:
            self.check = Gtk.CheckButton(active=finding.selected)
            self.check.set_valign(Gtk.Align.CENTER)
            self.check.connect("toggled", self._toggled)
            self.add_prefix(self.check)
            self.set_activatable_widget(self.check)

        size = Gtk.Label(label=human(finding.size) if finding.size else "—")
        size.add_css_class("size-dim" if finding.info_only else "size-label")
        size.set_valign(Gtk.Align.CENTER)
        size.set_width_chars(10)
        size.set_xalign(1.0)

        box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        box.append(_pill(finding.risk))
        box.append(size)
        self.add_suffix(box)

    def _toggled(self, button: Gtk.CheckButton) -> None:
        self.finding.selected = button.get_active()
        self._on_toggle()

    def set_selected(self, value: bool) -> None:
        if self.check is not None:
            self.check.set_active(value)


class CategoryGroup(Adw.PreferencesGroup):
    """One scanner's findings, collapsed behind an expander."""

    def __init__(self, category: Category, on_toggle) -> None:
        super().__init__()
        self.category = category
        self.rows: list[FindingRow] = []

        self.expander = Adw.ExpanderRow()
        self.expander.set_title(GLib.markup_escape_text(category.title))

        if category.skipped:
            self.expander.set_subtitle(GLib.markup_escape_text(category.skipped))
            self.expander.set_sensitive(False)
        elif category.error:
            self.expander.set_subtitle(
                GLib.markup_escape_text(f"Scan failed — {category.error}")
            )
            self.expander.set_sensitive(False)
        elif not category.findings:
            self.expander.set_subtitle("Nothing to clean up here")
            self.expander.set_sensitive(False)
        else:
            self.expander.set_subtitle(GLib.markup_escape_text(category.subtitle))

        icon = Gtk.Image.new_from_icon_name(category.icon)
        icon.set_valign(Gtk.Align.CENTER)
        self.expander.add_prefix(icon)

        self.total_label = Gtk.Label(label=human(category.total) if category.total else "—")
        self.total_label.add_css_class("size-label")
        self.total_label.set_valign(Gtk.Align.CENTER)
        self.total_label.set_width_chars(10)
        self.total_label.set_xalign(1.0)
        self.expander.add_suffix(self.total_label)

        self.add(self.expander)

        if category.note and category.findings:
            note = Adw.ActionRow()
            note.set_title(GLib.markup_escape_text(category.note))
            note.set_title_lines(3)
            note.add_css_class("info-row")
            hint = Gtk.Image.new_from_icon_name("dialog-information-symbolic")
            hint.set_valign(Gtk.Align.CENTER)
            note.add_prefix(hint)
            self.expander.add_row(note)

        for finding in category.findings:
            row = FindingRow(finding, on_toggle)
            self.rows.append(row)
            self.expander.add_row(row)

    def apply_selection(self, mode: str) -> None:
        """mode: 'none' | 'safe' | 'review' | 'all'"""
        threshold = {"none": -1, "safe": Risk.SAFE, "review": Risk.REVIEW, "all": Risk.CAREFUL}[mode]
        for row in self.rows:
            if row.finding.info_only:
                continue
            row.set_selected(threshold >= 0 and row.finding.risk <= threshold)


class PacdietWindow(Adw.ApplicationWindow):
    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.set_title("pacdiet")
        self.set_default_size(960, 760)

        self.result = None
        self.groups: list[CategoryGroup] = []
        self._scan_thread: threading.Thread | None = None
        self._cancel = threading.Event()
        self.deep_scan = False
        self.dry_run = False

        self.toasts = Adw.ToastOverlay()
        toolbar = Adw.ToolbarView()
        toolbar.add_top_bar(self._build_header())
        toolbar.set_content(self._build_body())
        toolbar.add_bottom_bar(self._build_bottom_bar())
        self.toasts.set_child(toolbar)
        self.set_content(self.toasts)

        self._show_welcome()

    # -- chrome ------------------------------------------------------------

    def _build_header(self) -> Adw.HeaderBar:
        header = Adw.HeaderBar()

        self.scan_button = Gtk.Button(label="Scan")
        self.scan_button.add_css_class("suggested-action")
        self.scan_button.connect("clicked", lambda *_: self.start_scan())
        header.pack_start(self.scan_button)

        menu = Gtk.MenuButton(icon_name="open-menu-symbolic")
        menu.set_popover(self._build_menu())
        header.pack_end(menu)

        self.select_button = Gtk.MenuButton(
            icon_name="checkbox-checked-symbolic", tooltip_text="Change selection"
        )
        self.select_button.set_popover(self._build_select_popover())
        self.select_button.set_visible(False)
        header.pack_end(self.select_button)

        return header

    def _build_menu(self) -> Gtk.Popover:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6, margin_top=8,
                      margin_bottom=8, margin_start=8, margin_end=8)

        self.deep_switch = Gtk.Switch(active=False, valign=Gtk.Align.CENTER)
        self.deep_switch.connect(
            "notify::active", lambda s, _: setattr(self, "deep_scan", s.get_active())
        )
        box.append(self._switch_row(
            "Deep scan",
            "Also look for project build output, duplicates and your largest "
            "files. Much slower on a big home directory.",
            self.deep_switch,
        ))

        self.dry_switch = Gtk.Switch(active=False, valign=Gtk.Align.CENTER)
        self.dry_switch.connect(
            "notify::active", lambda s, _: setattr(self, "dry_run", s.get_active())
        )
        box.append(self._switch_row(
            "Dry run",
            "Report what would be removed without touching anything.",
            self.dry_switch,
        ))

        box.append(Gtk.Separator())
        log_btn = Gtk.Button(label="Show last log")
        log_btn.add_css_class("flat")
        log_btn.connect("clicked", lambda *_: self.stack.set_visible_child_name("log"))
        box.append(log_btn)

        about = Gtk.Button(label="About pacdiet")
        about.add_css_class("flat")
        about.connect("clicked", lambda *_: self._show_about())
        box.append(about)

        popover = Gtk.Popover()
        popover.set_child(box)
        return popover

    def _switch_row(self, title: str, subtitle: str, switch: Gtk.Switch) -> Gtk.Widget:
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        text = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2, hexpand=True)
        label = Gtk.Label(label=title, xalign=0)
        label.add_css_class("heading")
        sub = Gtk.Label(label=subtitle, xalign=0, wrap=True, max_width_chars=34)
        sub.add_css_class("dim-label")
        sub.add_css_class("caption")
        text.append(label)
        text.append(sub)
        row.append(text)
        row.append(switch)
        return row

    def _build_select_popover(self) -> Gtk.Popover:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4, margin_top=8,
                      margin_bottom=8, margin_start=8, margin_end=8)
        for label, mode in (
            ("Select safe items only", "safe"),
            ("Select safe + review", "review"),
            ("Select everything", "all"),
            ("Deselect all", "none"),
        ):
            button = Gtk.Button(label=label)
            button.add_css_class("flat")
            button.connect("clicked", self._on_select_mode, mode)
            box.append(button)
        popover = Gtk.Popover()
        popover.set_child(box)
        return popover

    def _on_select_mode(self, _button: Gtk.Button, mode: str) -> None:
        for group in self.groups:
            group.apply_selection(mode)
        self._refresh_totals()

    def _build_body(self) -> Gtk.Widget:
        self.stack = Adw.ViewStack()

        # Welcome
        self.welcome = Adw.StatusPage(
            icon_name="drive-harddisk-symbolic",
            title="Reclaim your disk",
        )
        welcome_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=18,
                              halign=Gtk.Align.CENTER)
        self.disk_bar = Gtk.LevelBar()
        self.disk_bar.add_css_class("disk")
        self.disk_bar.set_size_request(380, -1)
        self.disk_bar.set_mode(Gtk.LevelBarMode.CONTINUOUS)
        self.disk_bar.add_offset_value("filled", 0.75)
        self.disk_bar.add_offset_value("high", 0.9)
        self.disk_bar.add_offset_value("full", 1.0)
        self.disk_caption = Gtk.Label()
        self.disk_caption.add_css_class("disk-caption")
        welcome_box.append(self.disk_bar)
        welcome_box.append(self.disk_caption)

        go = Gtk.Button(label="Scan this system")
        go.add_css_class("suggested-action")
        go.add_css_class("pill")
        go.set_halign(Gtk.Align.CENTER)
        go.connect("clicked", lambda *_: self.start_scan())
        welcome_box.append(go)
        self.welcome.set_child(welcome_box)
        self.stack.add_named(self.welcome, "welcome")

        # Scanning
        scanning = Adw.StatusPage(title="Scanning")
        scan_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16,
                           halign=Gtk.Align.CENTER)
        self.progress = Gtk.ProgressBar(show_text=False)
        self.progress.set_size_request(360, -1)
        self.progress_label = Gtk.Label(label="Starting…")
        self.progress_label.add_css_class("dim-label")
        cancel = Gtk.Button(label="Cancel")
        cancel.set_halign(Gtk.Align.CENTER)
        cancel.connect("clicked", lambda *_: self._cancel.set())
        scan_box.append(self.progress)
        scan_box.append(self.progress_label)
        scan_box.append(cancel)
        scanning.set_child(scan_box)
        self.stack.add_named(scanning, "scanning")

        # Results
        scroller = Gtk.ScrolledWindow(vexpand=True)
        self.results_page = Adw.PreferencesPage()
        scroller.set_child(self.results_page)
        self.stack.add_named(scroller, "results")

        # Log
        log_scroller = Gtk.ScrolledWindow(vexpand=True)
        self.log_view = Gtk.TextView(editable=False, monospace=True)
        self.log_view.add_css_class("log-view")
        self.log_view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        log_scroller.set_child(self.log_view)
        self.stack.add_named(log_scroller, "log")

        return self.stack

    def _build_bottom_bar(self) -> Gtk.Widget:
        bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12,
                      margin_top=10, margin_bottom=10, margin_start=16, margin_end=16)

        text = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0, hexpand=True)
        self.total_label = Gtk.Label(label="—", xalign=0)
        self.total_label.add_css_class("reclaim-total")
        self.count_label = Gtk.Label(label="Nothing selected", xalign=0)
        self.count_label.add_css_class("dim-label")
        text.append(self.total_label)
        text.append(self.count_label)
        bar.append(text)

        self.preview_button = Gtk.Button(label="Preview")
        self.preview_button.set_valign(Gtk.Align.CENTER)
        self.preview_button.connect("clicked", lambda *_: self._show_preview())
        self.preview_button.set_sensitive(False)
        bar.append(self.preview_button)

        self.clean_button = Gtk.Button(label="Clean up")
        self.clean_button.add_css_class("destructive-action")
        self.clean_button.set_valign(Gtk.Align.CENTER)
        self.clean_button.connect("clicked", lambda *_: self._confirm_clean())
        self.clean_button.set_sensitive(False)
        bar.append(self.clean_button)

        self.bottom_bar = bar
        return bar

    # -- state -------------------------------------------------------------

    def _show_welcome(self) -> None:
        usage = disk_usage("/")
        self.disk_bar.set_value(min(usage.percent / 100.0, 1.0))
        self.disk_caption.set_label(
            f"{human(usage.used)} used of {human(usage.total)} — "
            f"{human(usage.free)} free ({usage.percent:.0f}% full)"
        )
        self.welcome.set_description(
            "pacdiet looks through your package cache, logs, application and "
            "toolchain caches, containers and games, then shows you exactly what "
            "it proposes to delete before anything happens."
        )
        self.stack.set_visible_child_name("welcome")

    def start_scan(self) -> None:
        if self._scan_thread and self._scan_thread.is_alive():
            return
        self._cancel.clear()
        self.scan_button.set_sensitive(False)
        self.select_button.set_visible(False)
        self.clean_button.set_sensitive(False)
        self.preview_button.set_sensitive(False)
        self.progress.set_fraction(0.0)
        self.progress_label.set_label("Starting…")
        self.stack.set_visible_child_name("scanning")

        deep = self.deep_scan

        def worker() -> None:
            result = scan(
                deep=deep,
                on_progress=lambda title, done, total: GLib.idle_add(
                    self._on_progress, title, done, total
                ),
                cancelled=self._cancel.is_set,
            )
            GLib.idle_add(self._on_scan_done, result)

        self._scan_thread = threading.Thread(target=worker, daemon=True)
        self._scan_thread.start()

    def _on_progress(self, title: str, done: int, total: int) -> bool:
        self.progress.set_fraction(done / total if total else 0.0)
        self.progress_label.set_label(f"{title}  ({done} of {total})")
        return False

    def _on_scan_done(self, result) -> bool:
        self.result = result
        self.scan_button.set_sensitive(True)
        self.scan_button.set_label("Rescan")

        child = self.results_page
        for group in self.groups:
            child.remove(group)
        self.groups = []

        with_findings = [c for c in result.categories if c.findings]
        without = [c for c in result.categories if not c.findings]

        for category in with_findings + without:
            group = CategoryGroup(category, self._refresh_totals)
            self.groups.append(group)
            self.results_page.add(group)

        self.select_button.set_visible(True)
        self.stack.set_visible_child_name("results")
        self._refresh_totals()

        found = human(result.total)
        self.toasts.add_toast(Adw.Toast(
            title=f"Scan finished — {found} reclaimable across "
                  f"{len(with_findings)} categories",
            timeout=4,
        ))
        return False

    def _refresh_totals(self) -> None:
        if not self.result:
            return
        size = self.result.selected_size
        count = len(self.result.selected())
        self.total_label.set_label(human(size) if count else "—")
        if count:
            self.count_label.set_label(
                f"{count} item{'s' if count != 1 else ''} selected"
                + ("  ·  dry run" if self.dry_run else "")
            )
        else:
            self.count_label.set_label("Nothing selected")
        self.clean_button.set_sensitive(count > 0)
        self.preview_button.set_sensitive(count > 0)

    # -- actions -----------------------------------------------------------

    def _show_preview(self) -> None:
        plan = build_plan(self.result.selected())
        dialog = AlertDialog(
            heading="Exactly what will happen",
            body=f"{plan.count} items, {human(plan.size)}."
                 + (" You will be asked to authenticate once." if plan.needs_root else ""),
        )
        buffer = Gtk.TextView(editable=False, monospace=True)
        buffer.add_css_class("log-view")
        buffer.get_buffer().set_text(preview(plan))
        scroller = Gtk.ScrolledWindow()
        scroller.set_size_request(640, 360)
        scroller.set_child(buffer)
        dialog.set_extra_child(scroller)
        dialog.add_response("close", "Close")
        self._present(dialog)

    def _confirm_clean(self) -> None:
        plan = build_plan(self.result.selected())
        careful = [f for f in self.result.selected() if f.risk is Risk.CAREFUL]

        body = f"{plan.count} items will be removed, freeing about {human(plan.size)}."

        # Package removal gets its own callout: `pacman -Rns` cascades into
        # dependencies, so the real blast radius is wider than the list shown.
        packages = [
            f.label for f in self.result.selected()
            if f.action.command and f.action.command[:2] == ["pacman", "-Rns"]
        ]
        if packages:
            shown = ", ".join(packages[:12]) + ("…" if len(packages) > 12 else "")
            body += (
                f"\n\nThis uninstalls {len(packages)} packages: {shown}\n\n"
                "pacman -Rns also removes their dependencies, so more than "
                "these will go. Make sure none of them is something you use — "
                "a lock screen, a theme engine or a password manager can appear "
                "in this list."
            )
        if careful:
            body += (
                f"\n\n{len(careful)} selected items are marked Careful — save "
                "games, container volumes, packages or your own files. This "
                "cannot be undone."
            )
        if plan.needs_root:
            body += "\n\nYou will be asked for your password once."
        if self.dry_run:
            body = "Dry run is on. Nothing will be deleted; you will get a report instead."

        dialog = AlertDialog(heading="Clean up now?", body=body)
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("go", "Dry run" if self.dry_run else "Delete")
        dialog.set_response_appearance(
            "go",
            Adw.ResponseAppearance.SUGGESTED if self.dry_run else Adw.ResponseAppearance.DESTRUCTIVE,
        )
        dialog.set_default_response("cancel")
        dialog.set_close_response("cancel")
        dialog.connect("response", self._on_confirm_response, plan)
        self._present(dialog)

    def _on_confirm_response(self, dialog, response: str, plan) -> None:
        if response != "go":
            return
        self.clean_button.set_sensitive(False)
        self.preview_button.set_sensitive(False)
        self.scan_button.set_sensitive(False)
        self.count_label.set_label("Working…")

        dry = self.dry_run

        def worker() -> None:
            outcome = execute(plan, dry_run=dry)
            GLib.idle_add(self._on_clean_done, outcome, plan)

        threading.Thread(target=worker, daemon=True).start()

    def _on_clean_done(self, outcome, plan) -> bool:
        self.scan_button.set_sensitive(True)
        self.log_view.get_buffer().set_text("\n".join(outcome.log) or "(no output)")
        self.stack.set_visible_child_name("log")

        if outcome.denied:
            self.toasts.add_toast(Adw.Toast(title=outcome.message, timeout=6))
        elif plan is not None and getattr(plan, "count", 0):
            freed = outcome.freed or plan.size
            title = (
                f"Dry run complete — {human(plan.size)} would be freed"
                if "DRY RUN" in (outcome.log[0] if outcome.log else "")
                else f"Freed about {human(freed)}"
            )
            self.toasts.add_toast(Adw.Toast(title=title, timeout=5))

        self.count_label.set_label("Rescan to see the new state")
        self.total_label.set_label("—")
        return False

    def _present(self, dialog) -> None:
        """Adw 1.5+ dialogs attach to a parent widget; older ones are windows."""
        if HAS_NEW_DIALOGS and hasattr(dialog, "present") and not isinstance(dialog, Gtk.Window):
            dialog.present(self)
        else:
            dialog.set_transient_for(self)
            dialog.present()

    def _show_about(self) -> None:
        about = AboutDialog(
            application_name="pacdiet",
            application_icon="drive-harddisk-symbolic",
            version="0.1.0",
            developer_name="Jorge Restrepo",
            comments=(
                "A disk cleanup tool for Arch Linux that explains itself. Every "
                "finding says what it is, what you lose by deleting it, and how "
                "risky that is — and nothing happens until you say so."
            ),
            license_type=Gtk.License.GPL_3_0,
            website="https://github.com/HenSeries/pacdiet",
            issue_url="https://github.com/HenSeries/pacdiet/issues",
        )
        self._present(about)


class PacdietApp(Adw.Application):
    def __init__(self) -> None:
        super().__init__(application_id=APP_ID)
        self.window: PacdietWindow | None = None

    def do_startup(self) -> None:
        Adw.Application.do_startup(self)
        display = Gdk.Display.get_default()
        if display is None:
            return
        css = Gtk.CssProvider()
        path = Path(__file__).parent / "style.css"
        try:
            css.load_from_path(str(path))
        except GLib.Error:
            return
        Gtk.StyleContext.add_provider_for_display(
            display, css, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
        )

    def do_activate(self) -> None:
        if not self.window:
            self.window = PacdietWindow(application=self)
        self.window.present()
