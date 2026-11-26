#!/bin/bash
# Builds the Boxent base rootfs into an empty directory.
#
#   build.sh TARGET [SUITE] [MIRROR]
#
# The result is used read-only by every sandbox. It contains the mount points the sandbox needs
# (/workspace, /home/sandbox, /.boxent/agent) because a read-only root cannot gain them later.
set -euo pipefail

target=$1
suite=${2:-resolute}
mirror=${3:-http://ports.ubuntu.com/ubuntu-ports}
[ "$(uname -m)" = x86_64 ] && mirror=${3:-http://archive.ubuntu.com/ubuntu}

packages=(
  bash coreutils util-linux findutils grep sed gawk diffutils
  tar gzip xz-utils unzip file less procps psmisc iproute2
  ca-certificates curl git python3
)

keyring=()
[ -f /usr/share/keyrings/ubuntu-archive-keyring.gpg ] &&
  keyring=(--keyring=/usr/share/keyrings/ubuntu-archive-keyring.gpg)

mmdebstrap \
  --variant=minbase \
  --components=main,universe \
  "${keyring[@]}" \
  --include="$(IFS=,; echo "${packages[*]}")" \
  --customize-hook='chroot "$1" useradd --uid 1000 --user-group --create-home --home-dir /home/sandbox --shell /bin/bash sandbox' \
  --customize-hook='mkdir -p "$1/workspace" "$1/.boxent" && touch "$1/.boxent/agent" && chown 1000:1000 "$1/workspace"' \
  --customize-hook=': > "$1/etc/resolv.conf"; echo sandbox > "$1/etc/hostname"; printf "127.0.0.1 localhost sandbox\n::1 localhost\n" > "$1/etc/hosts"' \
  --customize-hook='rm -rf "$1"/var/lib/apt/lists/* "$1"/var/cache/apt/* "$1"/var/log/*' \
  "$suite" "$target" "$mirror"
