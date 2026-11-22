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
        export CC="$(cygpath -m /ucrt64/bin/gcc.exe)"
        export PKG_CONFIG="$(cygpath -m /ucrt64/bin/pkgconf.exe)"
        flags+=(-tags yara_static)
        extldflags=-extldflags=-static
        ext=.exe
        ;;
    darwin) export CC=clang ;;
    linux) export CC=gcc ;;
    *) echo "Unsupported native OS $NATIVE_OS" >&2; exit 1 ;;
esac
pkgconf_bin=${PKG_CONFIG:-pkg-config}
commit=$(git rev-parse HEAD)
version="ci-${commit:0:12}"
if [[ ${GITHUB_REF_TYPE:-} == tag ]]; then
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
            windows) /ucrt64/bin/objdump -p "$binary" | sed -n '/DLL Name/p' ;;
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
rule CAU_NativeFixture {
    strings:
        $marker = "cau-native-fixture-marker"
    condition:
        $marker
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
    -run '^(TestYaraStringOffsetsAreAbsolute|TestYaraFileScanOffsetsAreAbsolute|TestInitializeAndToolsList|TestYaraTestRuleMatches|TestRestoreRoundTrip)$' \
    ./scanner ./internal/mcp ./internal/quarantine
