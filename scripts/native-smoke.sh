#!/usr/bin/env bash
# Build the two Go commands natively and exercise them with a local YARA fixture.
set -euo pipefail

out=${NATIVE_OUT_DIR:-native-out}
mkdir -p "$out"
export CGO_ENABLED=1
flags=(-mod=vendor)
extldflags=
ext=
case "$NATIVE_OS" in
    windows)
        source "$(dirname "${BASH_SOURCE[0]}")/windows-toolchain.sh"
        export CGO_LDFLAGS="${CGO_LDFLAGS:--O2 -g} -L$windows_prefix/lib"
        flags+=(-tags yara_static)
        extldflags=-extldflags=-static
        ext=.exe
        ;;
    darwin)
        export CC=clang
        flags+=(-tags yara_static)
        ;;
    linux) export CC=gcc ;;
    *) echo "Unsupported native OS $NATIVE_OS" >&2; exit 1 ;;
esac
pkgconf_bin=${PKG_CONFIG:-pkg-config}
commit=$(git rev-parse HEAD)
version="ci-${commit:0:12}"
if [[ -n ${NATIVE_RELEASE_VERSION:-} ]]; then
    [[ $NATIVE_RELEASE_VERSION =~ ^[0-9A-Za-z.+-]+$ ]]
    version=$NATIVE_RELEASE_VERSION
elif [[ ${GITHUB_REF_TYPE:-} == tag ]]; then
    version=$GITHUB_REF_NAME
fi

[[ $(go env GOOS) == "$NATIVE_OS" ]]
[[ $(go env GOHOSTARCH) == "$NATIVE_ARCH" && $(go env GOARCH) == "$NATIVE_ARCH" ]]
{
    echo "commit=$commit run=${GITHUB_RUN_ID:-local} version=$version"
    printf 'runner=%s image=%s\n' "${ImageOS:-unknown}" "${ImageVersion:-unknown}"
    uname -a
    go version
    go env -json GOOS GOHOSTOS GOHOSTARCH GOARCH CGO_ENABLED CC
    "$CC" --version
    "$pkgconf_bin" --atleast-version=4.3 yara
    "$pkgconf_bin" --modversion yara
} | tee "$out/toolchain.txt"

cau="$out/cau$ext"
mcp="$out/cau-mcp$ext"
go build "${flags[@]}" -trimpath -ldflags "-X main.version=$version $extldflags" -o "$cau" .
go build "${flags[@]}" -trimpath -ldflags "-X main.version=$version $extldflags" -o "$mcp" ./cmd/cau-mcp
{
    for binary in "$cau" "$mcp"; do
        file "$binary"
        go version -m "$binary"
        case "$NATIVE_OS" in
            linux) ldd "$binary" ;;
            darwin) otool -L "$binary" ;;
            windows)
                imports=$("$MSYSTEM_PREFIX/bin/$windows_objdump" -p "$binary" | sed -n '/DLL Name/p')
                test -n "$imports"
                printf '%s\n' "$imports"
                if grep -Eiq 'DLL Name:[[:space:]]+(libcrypto|libssl|libwinpthread|libgcc|libyara|libunwind|msys-)' <<< "$imports"; then
                    echo "Unexpected native build dependency in $binary" >&2
                    exit 1
                fi
                ;;
        esac
    done
} | tee "$out/linkage.txt"

work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT

assert_version() {
    local actual=$1 expected=$2
    if [[ $actual != "$expected" ]]; then
        printf 'Expected version %s, got %s\n' "$expected" "$actual" >&2
        exit 1
    fi
}

require_match() {
    local pattern=$1 report=$2
    if ! grep -Fq -- "$pattern" "$report"; then
        printf 'Missing %s in %s\n' "$pattern" "$report" >&2
        cat "$report" >&2
        exit 1
    fi
}

assert_version "$("$cau" version)" "CAU EDR $version"
assert_version "$("$mcp" --version)" "cau-mcp $version"

printf '# Empty hash database for the native smoke\n' > "$work/hashes.txt"
printf 'cau-native-fixture-marker\n' > "$work/match.txt"
printf 'plain native smoke control\n' > "$work/control.txt"
cat > "$work/smoke.yar" <<'YARA'
import "hash"

rule CAU_NativeFixture {
    strings:
        $marker = "cau-native-fixture-marker"
    condition:
        $marker and hash.sha256(0, filesize) == "6680cb8a4f3838fc4532618b5567a48b810c8b85dee22e4b11daddb3e5d813a5"
}
YARA

scan=( "$cau" scan --db "$work/hashes.txt" --rules "$work/smoke.yar" --format json --quiet )
code=0
"${scan[@]}" --file "$work/match.txt" > "$work/match.json" || code=$?
[[ $code == 1 ]] || { cat "$work/match.json" >&2; exit 1; }
require_match '"rule":"CAU_NativeFixture"' "$work/match.json"
require_match '"verdict":"malicious"' "$work/match.json"
"${scan[@]}" --file "$work/control.txt" > "$work/control.json"
require_match '"verdict":"clean"' "$work/control.json"

"$mcp" --db "$work/hashes.txt" --rules "$work/smoke.yar" > "$work/mcp.jsonl" <<'MCP'
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/list"}
MCP
require_match '"serverInfo":{"name":"cau-mcp",' "$work/mcp.jsonl"
require_match '"name":"scan_file"' "$work/mcp.jsonl"
echo "Native smoke passed for cau and cau-mcp $version"

# Link all test packages and run representative portable checks.
go test "${flags[@]}" "-ldflags=$extldflags" -run '^$' ./...
go test "${flags[@]}" "-ldflags=$extldflags" -count=1 \
    -run '^(TestYaraStringOffsetsAreAbsolute|TestYaraFileScanOffsetsAreAbsolute|TestInitializeAndToolsList|TestYaraTestRuleMatches|TestRestoreRoundTrip|TestNativeWatcherReportsFileChanges|TestNativeDNSPosture.*|TestInventoryMacBundle|TestWindowsVaultLockAcrossProcesses|TestMacSoftwareUpdateAvailability|Test(Mac|Windows)Posture.*|TestDesktop.*|TestWindowsFilterSessionLifecycle|TestPF.*)$' \
    ./scanner ./internal/mcp ./internal/quarantine ./internal/watch ./internal/netscan ./internal/netblock ./internal/inventory ./internal/patches ./internal/posture ./internal/desktop ./internal/persist ./internal/procscan

if [[ $NATIVE_OS == linux ]]; then
    exit 0
fi
if [[ $NATIVE_OS == darwin ]]; then
    go test "${flags[@]}" -c -o "$work/netblock.test" ./internal/netblock
    sudo -n /usr/bin/env CAU_TEST_NATIVE_PF=1 "$work/netblock.test" -test.run '^TestPFNativeAnchor$' -test.v |
        tee "$out/pf-anchor.txt"
fi

stage="$work/staged"
installed="$work/installed"
mkdir -p "$stage/rules" "$stage/signatures" "$installed"
cp "$cau" "$mcp" LICENSE README.md "$stage/"
cp rules/rule_list.yar "$stage/rules/"
cp signatures/{hashes,fuzzy}.txt "$stage/signatures/"
archive="$(cd "$out" && pwd)/cau-$version-$NATIVE_OS-$NATIVE_ARCH"
members=( "cau$ext" "cau-mcp$ext" LICENSE README.md rules/rule_list.yar signatures/hashes.txt signatures/fuzzy.txt )
if [[ $NATIVE_OS == windows ]]; then
    (cd "$stage" && zip -q "$archive.zip" "${members[@]}")
    unzip -q "$archive.zip" -d "$installed"
    dns_provider="DnsClient connected IP interfaces"
    firewall_provider="windows-firewall-active-store"
    process_provider="windows-cim-process"
    startup_provider="windows-registry-and-services"
    connection_provider="windows-nettcpip"
else
    cp packaging/macos/org.cau.defend.plist packaging/macos/org.cau.peer-blocks.plist "$stage/"
    members+=(org.cau.defend.plist org.cau.peer-blocks.plist)
    tar -czf "$archive.tar.gz" -C "$stage" "${members[@]}"
    tar -xzf "$archive.tar.gz" -C "$installed"
    dns_provider="scutil --dns"
    firewall_provider="application-firewall"
    process_provider="macos-ps"
    startup_provider="macos-launchd-plists"
    connection_provider="macos-lsof"
fi

(
    cd "$work"
    unset CAU_SIGNATURES CAU_RULES CAU_FUZZY
    "$installed/cau$ext" rules list > installed-rules.txt
    "$installed/cau$ext" scan --quiet --format json --file control.txt > installed-scan.json
    if ! "$installed/cau$ext" net dns --format json > dns.json; then
        cat dns.json >&2
        exit 1
    fi
    posture_exit=0
    "$installed/cau$ext" posture --format json > posture.json || posture_exit=$?
    [[ $posture_exit == 0 || $posture_exit == 2 ]]
    for command in ps persist net; do
        code=0
        "$installed/cau$ext" "$command" --format json > "$command.json" || code=$?
        [[ $code == 0 || $code == 1 || $code == 2 ]]
    done
    grep -Eq '"scanned": [1-9][0-9]*' ps.json
    grep -Eq '"sockets": [1-9][0-9]*' net.json
    require_match "$process_provider" ps.json
    require_match "$startup_provider" persist.json
    require_match "$connection_provider" net.json
    cp control.txt vault-fixture.txt
    "$installed/cau$ext" quarantine add vault-fixture.txt --store vault
    test ! -e vault-fixture.txt
    "$installed/cau$ext" quarantine verify --store vault
    "$installed/cau$ext" quarantine list --store vault --format json > vault.json
    entry=$(sed -nE 's/^[[:space:]]*"id": "([0-9a-f]{32})",?[[:space:]]*$/\1/p' vault.json)
    [[ $entry =~ ^[0-9a-f]{32}$ ]]
    "$installed/cau$ext" quarantine restore "$entry" --to restored.txt --store vault
    cmp control.txt restored.txt
)
require_match '"verdict":"clean"' "$work/installed-scan.json"
require_match "$dns_provider" "$work/dns.json"
require_match '"status": "complete"' "$work/dns.json"
require_match "$firewall_provider" "$work/posture.json"
echo "Verified $NATIVE_OS extraction, resource discovery, vault, and live endpoint collection"

if [[ $NATIVE_OS == windows ]]; then
    powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass \
        -File "$(cygpath -aw scripts/native-service-smoke.ps1)" \
        -Binary "$(cygpath -aw "$installed/cau.exe")" -Work "$(cygpath -aw "$work")"
else
    mkdir "$work/watch"
    plist="$work/org.cau.defend.ci.plist"
    label=org.cau.defend.ci
    python3 - "$installed" "$work" "$plist" "$label" <<'PYTHON'
import plistlib
import sys
from pathlib import Path

installed, work, output = (Path(path).resolve() for path in sys.argv[1:4])
job = plistlib.loads((installed / "org.cau.defend.plist").read_bytes())
job["Label"] = sys.argv[4]
job["ProgramArguments"][0] = str(installed / "cau")
job["ProgramArguments"].extend(("--watch", str(work / "watch"), "--rules", str(work / "smoke.yar")))
job["StandardOutPath"] = str(work / "incidents.jsonl")
job["StandardErrorPath"] = str(work / "defend.log")
output.write_bytes(plistlib.dumps(job))
PYTHON
    domain="gui/$(id -u)"
    plutil -lint "$plist"
    launchctl bootstrap "$domain" "$plist"
    cleanup_job() {
        if ! launchctl bootout "$domain/$label"; then
            echo "Could not remove launchd job $domain/$label" >&2
        fi
        rm -rf -- "$work"
    }
    trap cleanup_job EXIT
    for attempt in {1..30}; do
        if [[ -f $work/defend.log ]] && grep -Fq 'REPORT-ONLY' "$work/defend.log"; then
            break
        fi
        sleep 1
    done
    require_match 'watching 1 directory subscriptions' "$work/defend.log"
    require_match 'REPORT-ONLY' "$work/defend.log"
    launchctl print "$domain/$label" > "$out/launchd.txt"
    require_match 'state = running' "$out/launchd.txt"
    cp "$work/match.txt" "$work/watch/"
    for attempt in {1..20}; do
        if grep -Fq 'CAU_NativeFixture' "$work/incidents.jsonl"; then
            break
        fi
        sleep 1
    done
    require_match 'CAU_NativeFixture' "$work/incidents.jsonl"
    launchctl bootout "$domain/$label"
    trap 'rm -rf -- "$work"' EXIT
    echo "Verified launchd bootstrap and bootout"
fi
