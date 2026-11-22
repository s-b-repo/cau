#!/usr/bin/env bash
# Sign the staged public assets and verify them before the publisher runs.
set -euo pipefail

if [[ $# -ne 2 || ! $1 =~ ^[0-9A-Za-z.+-]+$ || ! -d $2 ]]; then
    echo "usage: sign-release.sh VERSION DIST" >&2
    exit 2
fi
if [[ -z ${CAU_RELEASE_SIGNING_KEY:-} || -z ${CAU_RELEASE_PUBLIC_KEY:-} ]]; then
    echo "release signing requires the signing key and its trusted public key" >&2
    exit 1
fi

version=$1
dist=$2
engine="$dist/cau-$version-linux-amd64"

required=("cau-$version.tar.gz")
for tool in cau cau-mcp; do
    binary="$tool-$version-linux-amd64"
    required+=("$binary" "$binary.tar.gz" "$binary.cdx.json")
done
for name in "${required[@]}"; do
    if [[ ! -f $dist/$name || ! -s $dist/$name || -L $dist/$name ]]; then
        printf 'required release asset missing or invalid: %s\n' "$name" >&2
        exit 1
    fi
done
shopt -s dotglob nullglob
for asset in "$dist"/*; do
    name=${asset##*/}
    if [[ ! $name =~ ^[0-9A-Za-z][0-9A-Za-z._+-]*$ || ! -f $asset || -L $asset ||
          $name == SHA256SUMS* || $name == release-pubkey.hex ]]; then
        printf 'unexpected staged release input: %q\n' "$name" >&2
        exit 1
    fi
done

umask 077
keyfile=$(mktemp)
trap 'shred -u -- "$keyfile" || rm -f -- "$keyfile"' EXIT
printf '%s' "$CAU_RELEASE_SIGNING_KEY" > "$keyfile"
unset CAU_RELEASE_SIGNING_KEY
chmod 0755 "$engine" "$dist/cau-mcp-$version-linux-amd64"

"$engine" bundle update --db signatures/hashes.txt --sign-key "$keyfile" \
    --out "$dist" --db-version "$version" --min-engine "$version"
"$engine" selftest --record --sign-key "$keyfile" --manifest "$dist/integrity.json"
printf '%s\n' "$CAU_RELEASE_PUBLIC_KEY" > "$dist/release-pubkey.hex"
"$engine" bundle checksums --sign-key "$keyfile" --out "$dist" "$dist"/*
"$engine" verify-self --from "$dist" --pubkey "$dist/release-pubkey.hex"
(
    cd "$dist"
    sha256sum --strict --check SHA256SUMS
)
