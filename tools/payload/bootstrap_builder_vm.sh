#!/usr/bin/env bash
set -euo pipefail

SNAPSHOT=${1:?immutable Debian snapshot URL}
TOOLS_FILE=${2:?builder tool package request list}
[[ "$SNAPSHOT" =~ ^https://snapshot\.debian\.org/archive/debian/[0-9]{8}T[0-9]{6}Z/?$ ]] || {
    echo "refusing non-snapshot Debian repository: $SNAPSHOT" >&2
    exit 2
}
[[ -r "$TOOLS_FILE" ]] || { echo "tool package list is not readable" >&2; exit 2; }
[[ $(id -u) -eq 0 ]] || { echo "run builder bootstrap as root" >&2; exit 2; }
SNAPSHOT=${SNAPSHOT%/}/

cat > /etc/apt/sources.list.d/debian.sources <<EOF
Types: deb
URIs: $SNAPSHOT
Suites: trixie
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
Check-Valid-Until: no
EOF
find /etc/apt/sources.list.d -maxdepth 1 -type f ! -name debian.sources -exec sh -c ': > "$1"' _ {} \;
: > /etc/apt/sources.list

apt-get -o Acquire::Check-Valid-Until=false update
mapfile -t packages < <(sed -e 's/#.*//' -e '/^[[:space:]]*$/d' "$TOOLS_FILE")
(( ${#packages[@]} > 0 )) || { echo "empty builder tool package list" >&2; exit 2; }
DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y "${packages[@]}"

if grep -R -E 'deb\.debian\.org|security\.debian\.org' /etc/apt/sources.list /etc/apt/sources.list.d 2>/dev/null; then
    echo "mutable Debian mirror remains configured" >&2
    exit 42
fi
printf 'builder VM bootstrapped from %s\n' "$SNAPSHOT"
