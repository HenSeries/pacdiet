# pacdiet

A disk cleanup tool for Arch Linux that explains itself.

Most cleanup tools give you a list of checkboxes and a number. pacdiet tells
you, for every single item, **what it is, what you lose by deleting it, and how
much thought it deserves** — then shows you the exact commands before anything
runs.

## Why another cleaner

Arch gives you plenty of rope. The usual advice — `pacman -Scc`,
`pacman -Rns $(pacman -Qdtq)` — is handed around as a one-liner with no
mention of what it costs. Blanket orphan removal in particular is a trap:
"orphan" only means *no other installed package depends on this*, so your lock
screen, your Qt theme engine and your password manager all qualify the moment
they were pulled in as a dependency. Running that one-liner unreviewed is how
people end up reinstalling a hundred packages.

pacdiet is built around that lesson:

- **Three risk tiers.** *Safe* is regenerated automatically and nothing is
  lost. *Review* is fine for most people but worth a glance. *Careful* might
  be something you actually want.
- **Only Safe is ever preselected.** This is enforced in the engine, not left
  to each scanner to remember, so one click can never remove something
  irreplaceable.
- **Every finding explains itself.** Not "1.2 GiB in compatdata" but "a
  Windows prefix left behind after the game was uninstalled; for titles that
  do not use Steam Cloud this is where your save games live".
- **Scanning never writes.** Scanners only read. No dry-run flags that might
  be misparsed into a real uninstall.
- **One password prompt.** Privileged work is batched into a single script run
  through `pkexec`, not one prompt per item.
- **Preview before you commit.** The Preview button shows the literal commands
  and paths.

## What it looks at

| Area | Examples |
| --- | --- |
| Pacman | package cache (per-version and full), orphans, `.pacnew`/`.pacsave`, orphaned kernel modules |
| AUR helpers | paru and yay clone and build caches |
| System | journal, crash dumps, rotated logs, firmware/man/printer caches, stale `/var/tmp` |
| Your home | per-application caches, trash, data left by uninstalled apps |
| Development | npm, Gradle, Cargo, pip, uv, pub, Go, Maven, ccache, Playwright, Android SDK images, and idle `node_modules` / `target` / `.venv` / `__pycache__` |
| Containers | Docker and Podman images, build cache, stopped containers, unused volumes |
| Flatpak / Snap | unused runtimes, disabled revisions |
| Games | Steam shader caches, orphaned Proton prefixes, stalled downloads, Wine and launcher caches |
| Anything else | largest files, forgotten downloads, byte-verified duplicates |

Installed games and the like are listed **for context only** — pacdiet will not
delete a game behind Steam's back, it points you at Steam.

## Install

From the AUR (once published):

```bash
paru -S pacdiet
```

From a checkout:

```bash
sudo pacman -S --needed python python-gobject gtk4 libadwaita polkit pacman-contrib
makepkg -si
```

Or run it straight from the source tree, with no install at all:

```bash
python3 -m pacdiet
```

## Using it

Launch **pacdiet** from your application menu, or:

```bash
pacdiet --gui
```

Press **Scan**. Safe items come preselected; everything else is yours to tick.
**Preview** shows the exact commands. **Clean up** asks once, then does it.

**Deep scan** (in the menu) additionally looks for project build output,
duplicate files and your largest files. It is much slower on a large home
directory, because it has to walk and size the whole thing.

**Dry run** (also in the menu) reports what would happen and changes nothing.

### Terminal

The same engine runs headless, which is handy on a server or over SSH:

```bash
pacdiet --cli
```

```bash
pacdiet --cli --deep --only toolchain --only user-cache
```

```bash
pacdiet --cli --clean --risk safe --yes
```

`--risk` picks the highest tier to select automatically (`safe`, `review`,
`all`); it defaults to `safe`. `--dry-run` prints the commands without running
them. Scanner keys come from the listing a plain `--cli` run prints.

## Keeping it clean

Two settings do more than any amount of periodic cleaning:

```bash
sudo sed -i 's/^#\?SystemMaxUse=.*/SystemMaxUse=500M/' /etc/systemd/journald.conf
```

```bash
sudo systemctl enable --now paccache.timer
```

The first caps the journal permanently. The second (from `pacman-contrib`)
prunes old cached package versions weekly, so the package cache stops being
the biggest thing on your disk.

## Development

```bash
python3 tests_quick.py
```

These are invariant checks rather than unit tests, and the ones that matter
are: nothing above Safe is ever preselected, protected paths are always
refused, and a plan can only ever contain items the user ticked.

Adding a scanner means writing a function that returns `Finding` objects and
listing it in that module's `scanners()`. Give every finding an honest `risk`
and a `detail` that says what the user loses. The engine enforces the
preselection rule for you.

## License

GPL-3.0-or-later.
