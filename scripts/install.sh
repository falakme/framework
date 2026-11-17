#!/bin/sh
# Install the Falak programs (falak, falak-office, falak-studio) from a GitHub release.
#
#   curl -fsSL https://raw.githubusercontent.com/falakme/framework/main/scripts/install.sh | sh
#
# Then start Office and finish setup in the browser:
#
#   falak-office serve
#
# Options, as environment variables:
#   FALAK_VERSION      a tag such as v1.0.0 (default: the newest release)
#   FALAK_INSTALL_DIR  where to put the programs (default: ~/.local/bin)
#
# The download is checked against the release's SHA256SUMS before anything is installed.
set -eu

repo="falakme/framework"
dir="${FALAK_INSTALL_DIR:-$HOME/.local/bin}"

say() { printf '%s\n' "$*"; }
fail() { printf 'error: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || fail "$1 is needed and was not found"; }

need curl
need tar

# https only, including after a redirect.
fetch() { curl -fsSL --proto '=https' --tlsv1.2 "$@"; }

case "$(uname -s)" in
  Darwin) os=darwin ;;
  Linux) os=linux ;;
  *) fail "this system ($(uname -s)) has no build yet" ;;
esac
case "$(uname -m)" in
  arm64 | aarch64) arch=arm64 ;;
  x86_64 | amd64) arch=x86_64 ;;
  *) fail "this processor ($(uname -m)) has no build yet" ;;
esac
# Builds that exist: darwin-arm64 and linux-x86_64.
case "$os-$arch" in
  darwin-arm64 | linux-x86_64) ;;
  *) fail "there is no build for $os-$arch yet. Build from source: cargo build --release -p falak-cli -p falak-office -p falak-studio" ;;
esac

version="${FALAK_VERSION:-}"
if [ -n "$version" ]; then
  # It goes into a download address: a release tag, nothing else.
  case "$version" in
    v[0-9]*.[0-9]*.[0-9]* ) ;;
    *) fail "FALAK_VERSION must be a release tag such as v1.1.0" ;;
  esac
  case "$version" in
    *[!0-9A-Za-z.-]* ) fail "FALAK_VERSION must be a release tag such as v1.1.0" ;;
  esac
fi
if [ -z "$version" ]; then
  # The newest release, including a pre-release while there is no other.
  version=$(fetch "https://api.github.com/repos/$repo/releases?per_page=1" \
    | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)
  [ -n "$version" ] || fail "cannot find a release of $repo"
fi

asset="falak-$version-$os-$arch.tar.gz"
base="https://github.com/$repo/releases/download/$version"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

say "Installing Falak $version for $os-$arch"
fetch "$base/$asset" -o "$tmp/$asset" || fail "cannot download $base/$asset"
fetch "$base/SHA256SUMS" -o "$tmp/SHA256SUMS" || fail "cannot download the checksums"

want=$(awk -v a="$asset" '$2 == a { print $1 }' "$tmp/SHA256SUMS")
[ -n "$want" ] || fail "$asset is not in SHA256SUMS"
if command -v sha256sum >/dev/null 2>&1; then
  got=$(sha256sum "$tmp/$asset" | awk '{print $1}')
else
  got=$(shasum -a 256 "$tmp/$asset" | awk '{print $1}')
fi
[ "$want" = "$got" ] || fail "the download does not match its checksum; nothing was installed"

mkdir -p "$dir"
# Only the three programs are taken out of the archive, whatever else it holds.
tar -xzf "$tmp/$asset" -C "$tmp" falak falak-office falak-studio
for p in falak falak-office falak-studio; do
  [ -f "$tmp/$p" ] || fail "$p is not in the download"
  install -m 0755 "$tmp/$p" "$dir/$p"
done

say "Installed falak, falak-office and falak-studio in $dir"
case ":$PATH:" in
  *":$dir:"*) ;;
  *) say "Add it to your PATH:  export PATH=\"$dir:\$PATH\"" ;;
esac
say ""
say "Next:"
say "  falak-office serve        # then open the address it prints and finish setup in the browser"
say "  # or, without a browser:"
say "  falak-office setup --email you@example.com --password-env OFFICE_PASSWORD"
