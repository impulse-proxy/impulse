#!/usr/bin/env bash
set -euo pipefail

# ---------------------------------------------------------------------------
# make-deb.sh — build a Debian .deb package for impulse
#
# Usage:
#   ./make-deb.sh [--version <ver>] [--arch <arch>] [--skip-build] [--no-start]
#
#   --version     package version (default: [workspace.package].version from
#                 Cargo.toml, with "-beta" appended unless --version is given)
#   --arch        target architecture: amd64 | arm64 (default: host arch)
#   --skip-build  reuse an existing release binary instead of running cargo
#   --no-start    package does not auto-start the service on install; it is
#                 only enabled. Use when certs/config are provisioned after
#                 install (the common case for a fresh host).
#   --outdir      directory to write the .deb into (default: repo root)
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT"

# ---- defaults --------------------------------------------------------------
# Left EMPTY on purpose so the auto-detection below is reachable. Setting a
# literal default here is what made version/arch detection dead code before.
PKG_NAME="impulse"
PKG_VERSION="0.7.2"
PKG_ARCH="amd64"
SKIP_BUILD=0
AUTO_START=1
OUT_DIR="$REPO_ROOT"

# ---- parse args ------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)
      [[ $# -ge 2 ]] || { echo "ERROR: --version needs a value" >&2; exit 1; }
      PKG_VERSION="$2"; shift 2 ;;
    --arch)
      [[ $# -ge 2 ]] || { echo "ERROR: --arch needs a value" >&2; exit 1; }
      PKG_ARCH="$2"; shift 2 ;;
    --skip-build) SKIP_BUILD=1; shift ;;
    --no-start)   AUTO_START=0; shift ;;
    --outdir)
      [[ $# -ge 2 ]] || { echo "ERROR: --outdir needs a value" >&2; exit 1; }
      OUT_DIR="$2"; shift 2 ;;
    -h|--help)    sed -n '4,18p' "${BASH_SOURCE[0]}" | sed 's/^# \?//'; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

# ---- resolve version -------------------------------------------------------
# Authoritative source is [workspace.package].version. A bare '^version' grep
# would match the wrong key, so anchor the search to that table.
CARGO_VERSION="$(awk '
  /^\[workspace\.package\]/ { in_ws = 1; next }
  /^\[/                     { in_ws = 0 }
  in_ws && /^version[[:space:]]*=/ {
    gsub(/^version[[:space:]]*=[[:space:]]*"|"[[:space:]]*$/, "")
    print; exit
  }
' Cargo.toml)"

if [[ -z "$CARGO_VERSION" ]]; then
  echo "ERROR: could not read [workspace.package].version from Cargo.toml" >&2
  exit 1
fi

if [[ -z "$PKG_VERSION" ]]; then
  PKG_VERSION="${CARGO_VERSION}-beta"
else
  # An explicit --version that disagrees with Cargo.toml produces a package
  # whose label does not match the binary inside it. Warn loudly rather than
  # shipping an artifact nobody can identify later.
  if [[ "$PKG_VERSION" != "$CARGO_VERSION"* ]]; then
    echo "WARNING: --version '$PKG_VERSION' does not match Cargo.toml version '$CARGO_VERSION'." >&2
    echo "         The package label will not reflect the binary it contains." >&2
  fi
fi

# ---- resolve architecture --------------------------------------------------
HOST_ARCH=""
case "$(uname -m)" in
  x86_64)  HOST_ARCH="amd64" ;;
  aarch64) HOST_ARCH="arm64" ;;
  *)       HOST_ARCH="$(uname -m)" ;;
esac

if [[ -z "$PKG_ARCH" ]]; then
  PKG_ARCH="$HOST_ARCH"
fi

# Map Debian arch -> Rust target triple for cross builds.
RUST_TARGET=""
case "$PKG_ARCH" in
  amd64) RUST_TARGET="x86_64-unknown-linux-gnu" ;;
  arm64) RUST_TARGET="aarch64-unknown-linux-gnu" ;;
  *) echo "ERROR: unsupported --arch '$PKG_ARCH' (want amd64 or arm64)" >&2; exit 1 ;;
esac

CROSS=0
if [[ "$PKG_ARCH" != "$HOST_ARCH" ]]; then
  CROSS=1
fi

PKG_FULL="${PKG_NAME}_${PKG_VERSION}_${PKG_ARCH}"
BUILD_DIR="$(mktemp -d "${TMPDIR:-/tmp}/${PKG_NAME}-deb-XXXXXX")"
trap 'rm -rf "$BUILD_DIR"' EXIT

echo "==> Building package: ${PKG_FULL}.deb"
echo "    version : ${PKG_VERSION}  (Cargo.toml: ${CARGO_VERSION})"
echo "    arch    : ${PKG_ARCH}  (host: ${HOST_ARCH})"
echo "    autostart: $([[ $AUTO_START -eq 1 ]] && echo yes || echo 'no (enable only)')"

# ---- build binary ----------------------------------------------------------
# Cross builds go to target/<triple>/release; native builds to target/release.
if [[ $CROSS -eq 1 ]]; then
  BINARY_SRC="target/${RUST_TARGET}/release/${PKG_NAME}"
else
  BINARY_SRC="target/release/${PKG_NAME}"
fi

if [[ "$SKIP_BUILD" -eq 0 ]]; then
  if [[ $CROSS -eq 1 ]]; then
    echo "==> cargo build --release --target ${RUST_TARGET}"
    cargo build --release --target "$RUST_TARGET"
  else
    echo "==> cargo build --release"
    cargo build --release
  fi
fi

if [[ ! -f "$BINARY_SRC" ]]; then
  echo "ERROR: binary not found at $BINARY_SRC" >&2
  echo "       Run without --skip-build, or build for ${PKG_ARCH} first." >&2
  exit 1
fi

# Guard against the silent failure mode of shipping the wrong architecture:
# a package labeled amd64 containing an arm64 binary installs cleanly and then
# fails to exec.
if command -v file > /dev/null 2>&1; then
  BIN_INFO="$(file -b "$BINARY_SRC")"
  case "$PKG_ARCH" in
    amd64) EXPECT="x86-64" ;;
    arm64) EXPECT="aarch64|ARM aarch64" ;;
  esac
  if ! echo "$BIN_INFO" | grep -Eq "$EXPECT"; then
    echo "ERROR: binary at $BINARY_SRC does not look like $PKG_ARCH." >&2
    echo "       file says: $BIN_INFO" >&2
    exit 1
  fi
fi

# ---- prepare package tree --------------------------------------------------
mkdir -p \
  "$BUILD_DIR/DEBIAN" \
  "$BUILD_DIR/usr/bin" \
  "$BUILD_DIR/etc/impulse/certs" \
  "$BUILD_DIR/var/log/impulse" \
  "$BUILD_DIR/lib/systemd/system"

# binary
install -m 0755 "$BINARY_SRC" "$BUILD_DIR/usr/bin/${PKG_NAME}"

# default config (marked as conffile so dpkg won't clobber on upgrade)
install -m 0640 "packaging/deb/debian/config.yaml" "$BUILD_DIR/etc/impulse/config.yaml"

# systemd unit
install -m 0644 "packaging/deb/debian/impulse.service" "$BUILD_DIR/lib/systemd/system/impulse.service"

INSTALLED_SIZE="$(du -ks "$BUILD_DIR" | cut -f1)"

# ---- DEBIAN/control --------------------------------------------------------
# libc6/libgcc: the release binary links against the system glibc.
# adduser: postinst uses groupadd/useradd.
cat > "$BUILD_DIR/DEBIAN/control" <<EOF
Package: ${PKG_NAME}
Version: ${PKG_VERSION}
Architecture: ${PKG_ARCH}
Maintainer: Supernova Labs <noreply@supernova-labs.dev>
Section: net
Priority: optional
Homepage: https://github.com/Supernova-Labs-Org/impulse
Depends: libc6, adduser
Installed-Size: ${INSTALLED_SIZE}
Description: Impulse QUIC/HTTP3 reverse proxy and load balancer
 A high-performance HTTP/3 and QUIC reverse proxy with adaptive load balancing,
 circuit breaking, and observability built in.
EOF

# ---- DEBIAN/conffiles ------------------------------------------------------
cat > "$BUILD_DIR/DEBIAN/conffiles" <<EOF
/etc/impulse/config.yaml
EOF

# ---- DEBIAN/postinst -------------------------------------------------------
# AUTO_START is baked in at build time so the script itself stays POSIX sh.
cat > "$BUILD_DIR/DEBIAN/postinst" <<EOF
#!/bin/sh
set -e

AUTO_START=${AUTO_START}
EOF

cat >> "$BUILD_DIR/DEBIAN/postinst" <<'EOF'

# create system user/group if missing
if ! getent group impulse > /dev/null 2>&1; then
  groupadd --system impulse
fi
if ! getent passwd impulse > /dev/null 2>&1; then
  useradd --system --gid impulse --no-create-home \
          --home-dir /etc/impulse --shell /usr/sbin/nologin \
          --comment "Impulse reverse proxy" impulse
fi

# Ownership. Deliberately NOT recursive over /etc/impulse: operators place TLS
# key material in /etc/impulse/certs and set its permissions themselves, and a
# blanket chown -R on every upgrade would silently rewrite those.
chown impulse:impulse /etc/impulse
chmod 750 /etc/impulse
chown impulse:impulse /etc/impulse/config.yaml
chmod 640 /etc/impulse/config.yaml

# The certs directory itself must be owned/traversable, but leave its contents
# to the operator.
chown impulse:impulse /etc/impulse/certs
chmod 750 /etc/impulse/certs

chown -R impulse:impulse /var/log/impulse
chmod 750 /var/log/impulse

# --- service activation ----------------------------------------------------
# Detect systemd by checking for a real systemd PID 1, NOT via
# `systemctl is-system-running`: that command exits non-zero when the system is
# merely "degraded" (any failed unit present), which would silently skip both
# enable and start and leave the package installed but dead.
has_systemd() {
  [ -d /run/systemd/system ] && command -v systemctl > /dev/null 2>&1
}

if has_systemd; then
  systemctl daemon-reload || true

  # Enable unconditionally so the service survives reboot even when we choose
  # not to start it now.
  systemctl enable impulse.service > /dev/null 2>&1 || true

  if [ "$AUTO_START" = "1" ]; then
    # A fresh install has no certs yet, so a start attempt is expected to fail.
    # Report it rather than hiding it behind `|| true`.
    if ! systemctl restart impulse.service; then
      echo "Impulse: service did not start." >&2
      echo "Impulse: this is expected on a fresh install until you provide" >&2
      echo "Impulse:   /etc/impulse/certs/fullchain.pem" >&2
      echo "Impulse:   /etc/impulse/certs/privkey.pem" >&2
      echo "Impulse: and edit /etc/impulse/config.yaml, then:" >&2
      echo "Impulse:   sudo systemctl restart impulse" >&2
      echo "Impulse: check 'journalctl -u impulse -n 50' for the reason." >&2
    fi
  else
    echo "Impulse: enabled but not started (--no-start build)."
    echo "Impulse: provide certs in /etc/impulse/certs, edit /etc/impulse/config.yaml, then:"
    echo "Impulse:   sudo systemctl start impulse"
  fi
fi
EOF
chmod 0755 "$BUILD_DIR/DEBIAN/postinst"

# ---- DEBIAN/prerm ----------------------------------------------------------
cat > "$BUILD_DIR/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e

# Only stop/disable when the package is going away, not on upgrade — dpkg runs
# prerm for both, and tearing the unit down mid-upgrade is needless downtime.
# (postinst restarts the service on upgrade.)
if [ "$1" = "remove" ] || [ "$1" = "purge" ] || [ "$1" = "deconfigure" ]; then
  if [ -d /run/systemd/system ] && command -v systemctl > /dev/null 2>&1; then
    systemctl stop impulse.service 2>/dev/null || true
    systemctl disable impulse.service 2>/dev/null || true
  fi
fi
EOF
chmod 0755 "$BUILD_DIR/DEBIAN/prerm"

# ---- DEBIAN/postrm ---------------------------------------------------------
cat > "$BUILD_DIR/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e

if [ "$1" = "purge" ]; then
  # Remove only what this package created. TLS key material in
  # /etc/impulse/certs is operator-supplied and never installed by us, so
  # destroying it on purge would be data loss well beyond our remit.
  rm -f /etc/impulse/config.yaml
  # rmdir, not rm -rf: succeeds only when the operator left nothing behind.
  rmdir /etc/impulse/certs 2>/dev/null || true
  rmdir /etc/impulse       2>/dev/null || true

  if [ -d /etc/impulse ]; then
    echo "Impulse: kept /etc/impulse — it still holds files this package did not install." >&2
  fi

  rm -f /var/log/impulse/impulse.log
  rmdir /var/log/impulse 2>/dev/null || true

  # Drop the service account only once nothing of ours remains.
  if [ ! -d /etc/impulse ]; then
    if getent passwd impulse > /dev/null 2>&1; then
      userdel impulse 2>/dev/null || true
    fi
    if getent group impulse > /dev/null 2>&1; then
      groupdel impulse 2>/dev/null || true
    fi
  fi
fi

if [ -d /run/systemd/system ] && command -v systemctl > /dev/null 2>&1; then
  systemctl daemon-reload || true
fi
EOF
chmod 0755 "$BUILD_DIR/DEBIAN/postrm"

# ---- build .deb ------------------------------------------------------------
echo "==> dpkg-deb --build ${PKG_FULL}"
mkdir -p "$OUT_DIR"
OUT_DEB="${OUT_DIR%/}/${PKG_FULL}.deb"
dpkg-deb --root-owner-group --build "$BUILD_DIR" "$OUT_DEB"

echo ""
echo "Done: ${OUT_DEB}"
echo ""
echo "Install with:"
echo "  sudo dpkg -i ${PKG_FULL}.deb"
echo ""
echo "After install:"
echo "  1. place TLS certs (PKCS#8 key) at:"
echo "       /etc/impulse/certs/fullchain.pem"
echo "       /etc/impulse/certs/privkey.pem"
echo "     and: sudo chown impulse:impulse /etc/impulse/certs/*.pem"
echo "          sudo chmod 640 /etc/impulse/certs/privkey.pem"
echo "  2. edit /etc/impulse/config.yaml (set a control-api token)"
echo "  3. sudo systemctl restart impulse && journalctl -u impulse -n 50"
