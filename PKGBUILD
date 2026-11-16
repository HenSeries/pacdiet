# Maintainer: Jorge Restrepo <gi.dev.labs@gmail.com>
#
# Local build: compiles the working tree as it is, so `makepkg -si` works
# before the project is published anywhere. PKGBUILD.aur is the version to
# ship to the AUR once the GitHub repo exists.
pkgname=pacdiet
pkgver=0.1.0
pkgrel=1
pkgdesc="A disk cleanup tool for Arch Linux that explains itself"
arch=('any')
url="https://github.com/HenSeries/pacdiet"
license=('GPL-3.0-or-later')
depends=('python' 'python-gobject' 'gtk4' 'libadwaita' 'polkit' 'pacman-contrib')
optdepends=(
  'docker: scan container images, build cache and volumes'
  'podman: scan container images, build cache and volumes'
  'flatpak: scan unused runtimes'
  'paru: scan the paru build cache'
  'yay: scan the yay build cache'
)
makedepends=('python-build' 'python-installer' 'python-setuptools' 'python-wheel')
source=()
sha256sums=()

build() {
  cd "$startdir"
  rm -rf build dist
  python -m build --wheel --no-isolation
}

check() {
  cd "$startdir"
  python tests_quick.py
}

package() {
  cd "$startdir"
  python -m installer --destdir="$pkgdir" dist/*.whl
  install -Dm644 "data/io.github.henseries.$pkgname.desktop" \
    "$pkgdir/usr/share/applications/io.github.henseries.$pkgname.desktop"
  install -Dm644 README.md "$pkgdir/usr/share/doc/$pkgname/README.md"
}
