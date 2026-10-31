#!/bin/sh
# shellcheck shell=dash
# openprotect installer - POSIX form. Non-interactive by construction:
# it runs under `curl -fsSL <entrance> | sh`, so nothing here may
# prompt, elevate, or edit rc files. A failed download or checksum
# leaves any existing install untouched and exits non-zero.
#
#   curl -fsSL https://kyaky.ai/openprotect/install.sh | sh
#   curl -fsSL https://kyaky.ai/openprotect/install.sh | OPENPROTECT_VERSION=v0.2.0-alpha.31 sh
#   curl -fsSL https://kyaky.ai/openprotect/install.sh | sh -s v0.2.0-alpha.31
#
# Environment:
#   OPENPROTECT_VERSION        pin a tag (default latest)
#   OPENPROTECT_INSTALL_DIR    override the install dir (default ~/.openprotect)
#
# The installed layout is a self-contained directory bundle:
#   ~/.openprotect/opc          the CLI (sudo to run: it owns the tunnel)
#   ~/.openprotect/lib/         bundled dylibs (macOS)
#   ~/.openprotect/README.md    docs
# sudo runs it with -E so the PATH carry-over finds it: sudo -E ~/.openprotect/opc …

set -u

# The Asset base: the dist directory the kyaky.ai site deployment
# serves. One place to flip - the cross-platform guidance below derives
# from it, so the printed URL can never drift from the download origin.
ASSET_BASE="https://kyaky.ai/openprotect"

fail() {
	printf 'openprotect: %s\n' "$*" >&2
	exit 1
}

[ "$(id -u)" != "0" ] ||
	fail "refusing to run as root - this installer places the bundle in your own home; run it as yourself (the VPN itself runs under sudo)"

command -v curl >/dev/null 2>&1 ||
	fail "curl is required (macOS and most Linux distros ship it)"
command -v tar >/dev/null 2>&1 || fail "tar is required"

# --- platform: refuse before any network call ---
os=$(uname -s | tr '[:upper:]' '[:lower:]')
arch=$(uname -m)
case "$os" in
	darwin | linux) ;;
	msys* | mingw*)
		fail "this is the POSIX installer; on Windows run: irm $ASSET_BASE/install.ps1 | iex"
		;;
	*) fail "unsupported OS '$os' (this installer supports darwin and linux)" ;;
esac
case "$arch" in
	x86_64 | amd64) arch=x86_64 ;;
	aarch64 | arm64) arch=aarch64 ;;
	*) fail "unsupported architecture '$arch' (need x86_64 or aarch64/arm64)" ;;
esac
asset="openprotect-cli-$os-$arch.tar.gz"

# --- version pin: positional wins over env; 'latest' or a tag ---
version="${OPENPROTECT_VERSION:-latest}"
if [ "${1:-}" != "" ]; then
	[ $# -eq 1 ] || fail "usage: sh -s <version> (one argument: latest or vX.Y.Z(-suffix))"
	version="$1"
fi
case "$version" in
	latest) urlbase="$ASSET_BASE" ;;
	v[0-9]* | [0-9]*)
		case "$version" in [0-9]*) version="v$version" ;; esac
		case "$version" in
			*..* | *..) fail "bad version tag '$version'" ;;
		esac
		urlbase="$ASSET_BASE/$version"
		;;
	*) fail "bad version '$version' (need latest or a v-tag)" ;;
esac

install_dir="${OPENPROTECT_INSTALL_DIR:-$HOME/.openprotect}"

tmp=$(mktemp -d) || fail "mktemp failed"
trap 'rm -rf "$tmp"' EXIT
trap 'exit 1' INT TERM

echo "openprotect: downloading $asset ($version) ..."
curl -fsSL -o "$tmp/$asset" "$urlbase/$asset" ||
	fail "download failed ($urlbase/$asset)"
curl -fsSL -o "$tmp/$asset.sha256" "$urlbase/$asset.sha256" ||
	fail "checksum download failed ($urlbase/$asset.sha256)"

(cd "$tmp" && {
	sha256sum --check "$asset.sha256" 2>/dev/null ||
		shasum -a 256 --check "$asset.sha256"
}) || fail "checksum mismatch - refusing to install"

mkdir -p "$tmp/unpacked"
tar -xzf "$tmp/$asset" -C "$tmp/unpacked" ||
	fail "could not unpack the archive"
[ -f "$tmp/unpacked/opc" ] || fail "the archive has no opc binary (asset grammar drifted?)"

# Whole-tree swap: the bundle (binary + bundled lib/) is replaced as one
# unit, so a half-updated install can never exist.
staged="$install_dir.new.$$"
old="$install_dir.old.$$"
cleanup() { rm -rf "$staged" "$old"; }
trap 'cleanup; rm -rf "$tmp"; exit 1' INT TERM
mkdir -p "$staged" || fail "cannot create the staging dir under $HOME"
cp -R "$tmp/unpacked/." "$staged/" || fail "staging copy failed"

mkdir -p "$install_dir" || fail "cannot create $install_dir"
if [ -e "$install_dir" ] && [ -n "$(ls -A "$install_dir" 2>/dev/null)" ]; then
	mv "$install_dir" "$old" || fail "could not move the old install aside"
fi
mv "$staged" "$install_dir" || fail "could not move the new install into place"
cleanup() { rm -rf "$tmp"; }
rm -rf "$old"

newbin="$install_dir/opc"
chmod 0755 "$newbin" 2>/dev/null || true
resolved=$(command -v opc 2>/dev/null || true)
if [ -n "$resolved" ] && [ "$resolved" != "$newbin" ]; then
	printf 'openprotect: WARNING: an existing opc resolves to %s - it may keep winning PATH resolution over %s\n' "$resolved" "$newbin" >&2
fi
case ":$PATH:" in
	*":$install_dir:"*) ;;
	*)
		printf 'openprotect: %s is not on PATH; paste this to use it now:\n  export PATH="%s:$PATH"\n' "$install_dir" "$install_dir"
		;;
esac

if [ "$os" = linux ]; then
	# The Linux build links the system libopenconnect dynamically.
	if ! ldd "$newbin" 2>/dev/null | grep -q "not found"; then
		:
	elif command -v apt-get >/dev/null 2>&1; then
		printf 'openprotect: NOTE: missing shared libraries - install them with: sudo apt-get install openconnect\n' >&2
	elif command -v dnf >/dev/null 2>&1; then
		printf 'openprotect: NOTE: missing shared libraries - install them with: sudo dnf install openconnect\n' >&2
	else
		printf 'openprotect: NOTE: install system openconnect if the binary fails to start (it links libopenconnect)\n' >&2
	fi
fi

printf 'openprotect: installed %s\n' "$newbin"
"$newbin" --version ||
	printf 'openprotect: WARNING: the installed binary did not run cleanly\n' >&2
printf 'openprotect: next steps:\n'
printf '  sudo -E %s connect <portal> --auth-mode headless --user <you>  # tunnel (needs sudo)\n' "$newbin"
printf '  opc status    # via the PATH hint above, or the full path\n'
