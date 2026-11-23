#!/bin/sh
set -eu

if [ "$(/usr/bin/id -u)" != 0 ]; then
    echo 'CAU removal requires root' >&2
    exit 1
fi
/usr/sbin/pkgutil --pkg-info org.cau.edr >/dev/null
app='/Library/Application Support/CAU'
for path in "$app" "$app/rules" "$app/signatures"; do
    if [ -L "$path" ]; then
        echo "CAU removal requires a real directory at $path" >&2
        exit 1
    fi
    if [ -d "$path" ]; then
        mode=$(/usr/bin/stat -f %Lp "$path")
        if [ "$(/usr/bin/stat -f %u "$path")" != 0 ] || [ "$((0$mode & 022))" != 0 ]; then
            echo "CAU removal requires a protected directory at $path" >&2
            exit 1
        fi
    fi
done

for label in org.cau.defend org.cau.peer-blocks; do
    plist="/Library/LaunchDaemons/$label.plist"
    if /bin/launchctl print "system/$label" >/dev/null 2>&1; then
        /bin/launchctl bootout system "$plist"
    fi
    /bin/rm -f "$plist"
done
/bin/rm -f "$app/cau" "$app/cau-mcp" "$app/LICENSE" "$app/org.cau.peer-blocks.plist" \
    "$app/rules/rule_list.yar" "$app/signatures/hashes.txt" "$app/signatures/fuzzy.txt" "$app/uninstall.sh"
for path in "$app/rules" "$app/signatures" "$app"; do
    if [ -d "$path" ]; then
        contents=$(/bin/ls -A "$path")
        if [ -n "$contents" ]; then
            printf 'Retained directory with local files: %s\n' "$path"
        else
            /bin/rmdir "$path"
        fi
    fi
done
/usr/sbin/pkgutil --forget org.cau.edr >/dev/null
echo 'CAU removed. Service logs remain in /var/log/cau.'
