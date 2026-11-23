#!/usr/bin/env bash
set -euo pipefail

[[ $# == 2 ]]
repo=$(cd "$(dirname "$0")/.." && pwd)
root="/Library/Application Support/CAU"
if [[ -e $root || -e /Library/LaunchDaemons/org.cau.defend.plist ]]; then
    echo 'native installer smoke requires a fresh runner' >&2
    exit 1
fi
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT

assert_cau_inventory() {
    local code=0
    "$1/cau" inventory --format json > "$work/inventory.json" || code=$?
    [[ $code == 0 || $code == 2 ]]
    shift
    python3 - "$work/inventory.json" "$@" <<'PYTHON'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as report:
    snapshot = json.load(report)
collections = [c for c in snapshot["collections"] if c["provider"] == "macos-receipts"]
if len(collections) != 1 or collections[0]["status"] not in {"complete", "partial"}:
    raise SystemExit("Inventory could not read the macOS package receipts")
versions = [package["version"] for package in collections[0]["packages"] if package["id"] == "org.cau.edr"]
if versions != sys.argv[2:]:
    raise SystemExit(f"Expected CAU inventory versions {sys.argv[2:]!r}, got {versions!r}")
PYTHON
}

wait_for_service() {
    for attempt in {1..30}; do
        if sudo -n /bin/launchctl print system/org.cau.defend > "$work/service.txt" &&
            grep -Fq 'state = running' "$work/service.txt"; then
            return
        fi
        sleep 1
    done
    cat "$work/service.txt" >&2
    sudo -n tail -40 /var/log/cau/defend.log >&2
    return 1
}

install_fixture() {
    if ! sudo -n /usr/sbin/installer -dumplog -pkg "$1" -target /; then
        sudo -n tail -100 /var/log/install.log >&2
        return 1
    fi
}

bash "$repo/scripts/build-macos-installer.sh" "$1" 0.0.1 "$work/older.pkg"
bash "$repo/scripts/build-macos-installer.sh" "$1" 0.0.2 "$work/newer.pkg"
assert_cau_inventory "$1"
install_fixture "$work/older.pkg"
wait_for_service
assert_cau_inventory "$1" 0.0.1
printf 'keep across upgrade\n' | sudo -n tee /var/log/cau/upgrade-fixture.txt
install_fixture "$work/newer.pkg"
wait_for_service
assert_cau_inventory "$1" 0.0.2
sudo -n grep -Fq 'keep across upgrade' /var/log/cau/upgrade-fixture.txt
/usr/sbin/pkgutil --pkg-info org.cau.edr | grep -Fq 'version: 0.0.2'
"$root/cau" rules list > "$work/installed-rules.txt"
sudo -n /bin/sh "$root/uninstall.sh"
for attempt in {1..15}; do
    if ! sudo -n /bin/launchctl print system/org.cau.defend > "$work/service-removed.txt" 2>&1; then
        break
    fi
    sleep 1
done
if sudo -n /bin/launchctl print system/org.cau.defend > "$work/service-removed.txt" 2>&1; then
    cat "$work/service-removed.txt" >&2
    exit 1
fi
if [[ -e $root/cau || -e /Library/LaunchDaemons/org.cau.defend.plist ]]; then
    echo 'macOS uninstall left the agent or its launchd job on disk' >&2
    exit 1
fi
sudo -n grep -Fq 'keep across upgrade' /var/log/cau/upgrade-fixture.txt
assert_cau_inventory "$1"
cp "$work/newer.pkg" "$2"
echo 'Verified macOS PKG install, rule discovery, service start, upgrade, removal and inventory'
