#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 3 || ! $2 =~ ^[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.+-]+)?$ ]]; then
    echo 'usage: build-macos-installer.sh PAYLOAD VERSION OUTPUT' >&2
    exit 2
fi
payload=$1
version=$2
output=$3
repo=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
root="$work/root"
app="$root/Library/Application Support/CAU"
mkdir -p "$app/rules" "$app/signatures" "$root/Library/LaunchDaemons" "$root/private/var/log/cau" "$work/scripts"
chmod 0700 "$root/private/var/log/cau"
for binary in cau cau-mcp; do
    dependencies=$(/usr/bin/otool -L "$payload/$binary" | tail -n +2 | awk '{print $1}')
    while IFS= read -r dependency; do
        case "$dependency" in
            /usr/lib/*|/System/Library/*) ;;
            *) echo "unexpected dependency for $binary: $dependency" >&2; exit 1 ;;
        esac
    done <<< "$dependencies"
    install -m 0755 "$payload/$binary" "$app/$binary"
done
install -m 0644 "$payload/LICENSE" "$app/"
install -m 0755 "$repo/packaging/macos/uninstall.sh" "$app/"
install -m 0644 "$payload/rules/rule_list.yar" "$app/rules/"
install -m 0644 "$payload/signatures/hashes.txt" "$payload/signatures/fuzzy.txt" "$app/signatures/"
for job in org.cau.defend org.cau.peer-blocks; do
    /usr/bin/plutil -lint "$repo/packaging/macos/$job.plist"
done
install -m 0644 "$repo/packaging/macos/org.cau.defend.plist" "$root/Library/LaunchDaemons/"
install -m 0644 "$repo/packaging/macos/org.cau.peer-blocks.plist" "$app/"
for step in preinstall postinstall; do
    install -m 0755 "$repo/packaging/macos/scripts/$step" "$work/scripts/"
done
/usr/bin/pkgbuild --root "$root" --scripts "$work/scripts" --ownership recommended \
    --identifier org.cau.edr --version "${version%%[+-]*}" --install-location / "$output"
test -s "$output"
