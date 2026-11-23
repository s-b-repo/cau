#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 1 || $1 != /* ]]; then
    echo 'usage: build-yara-macos.sh ABSOLUTE_PREFIX' >&2
    exit 2
fi
prefix=$1
version=4.6.0
sha=61ab80084e3f83e1b73a95057058e2ae1db5f87f291e32654e191d410297f0e5
openssl=$(brew --prefix openssl@3)
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
cd "$work"
curl --fail --location --retry 3 --silent --show-error \
    --output yara.tar.gz "https://github.com/VirusTotal/yara/archive/v$version.tar.gz"
printf '%s  %s\n' "$sha" yara.tar.gz | shasum -a 256 -c -
tar -xzf yara.tar.gz
cd "yara-$version"
./bootstrap.sh
mkdir -p "$prefix/crypto"
cp "$openssl/lib/libcrypto.a" "$prefix/crypto/"
CPPFLAGS="-I$openssl/include" LDFLAGS="-L$prefix/crypto" \
    ./configure --prefix="$prefix" --enable-static --disable-shared --with-crypto --enable-macho --enable-dex
make -j"$(sysctl -n hw.ncpu)"
make install
# Resolve crypto exclusively to the copied static archive. The standard
# libcrypto.pc from Homebrew would point the linker at a writable dylib.
sed -E -e '/^Requires.private:/d' -e 's|^Libs.private:|Libs.private: -L${prefix}/crypto -lcrypto|' \
    "$prefix/lib/pkgconfig/yara.pc" > "$work/yara.pc"
cp "$work/yara.pc" "$prefix/lib/pkgconfig/yara.pc"
test -s "$prefix/lib/libyara.a"
