#!/bin/sh
# Regression checks for source selection and release artifact preservation.
set -eu
scripts=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM

mkdir -p "$work/repo/packaging/arch" "$work/repo/packaging/systemd" \
    "$work/repo/debian" "$work/repo/.github"
cd "$work/repo"
git init -q
git config user.name pipeline-test
git config user.email pipeline-test@example.invalid
printf 'current source\n' > Makefile
printf 'installed service\n' > packaging/systemd/cau.service
printf 'checksum recipe\n' > packaging/arch/PKGBUILD
printf 'debian metadata\n' > debian/control
printf 'workflow\n' > .github/test.yml
git add .
git commit -qm fixture
"$scripts/source-archive.sh" 1.2.3 "$work/a.tar.gz"
"$scripts/source-archive.sh" 1.2.3 "$work/b.tar.gz"
cmp "$work/a.tar.gz" "$work/b.tar.gz"
tar -tzf "$work/a.tar.gz" > "$work/members"
grep -qx 'cau-1.2.3/Makefile' "$work/members"
grep -qx 'cau-1.2.3/packaging/systemd/cau.service' "$work/members"
if grep -Eq '/(arch|debian|\.github)/' "$work/members"; then
    echo 'source archive includes excluded metadata' >&2; exit 1
fi
# A packaging-only commit must not change the archive bytes the AUR pins.
printf 'changed recipe\n' > packaging/arch/PKGBUILD
git add .
git commit -qm packaging-only
"$scripts/source-archive.sh" 1.2.3 "$work/c.tar.gz"
cmp "$work/a.tar.gz" "$work/c.tar.gz"
# The current checkout, rather than a previous release, supplies the source.
printf 'improved current source\n' > Makefile
git add .
git commit -qm source-change
"$scripts/source-archive.sh" 1.2.3 "$work/current.tar.gz"
if cmp -s "$work/a.tar.gz" "$work/current.tar.gz"; then
    echo 'source archive ignored the source change' >&2; exit 1
fi
# A refusal is only a refusal for the right reason, so the reason is kept and
# printed: a script that failed for an unrelated reason would pass this check.
if out=$("$scripts/source-archive.sh" 1.2.3 "$work/bad.tar.gz" missing-ref 2>&1); then
    echo 'source archive accepted a missing ref' >&2; exit 1
fi
echo "source archive refused the missing ref: $out"
[ ! -e "$work/bad.tar.gz" ]

# Test both ordinary checkout validation and the manifest used by the local
# packaging workflow. The fixture uses a fake asset inside a reviewed root.
mkdir -p marketing
printf 'local draft\n' > marketing/draft.md
"$scripts/source-archive.sh" 1.2.3 "$work/worktree.tar.gz" --worktree
tar -tzf "$work/worktree.tar.gz" > "$work/worktree-members"
if grep -Fq '/marketing/' "$work/worktree-members"; then
    echo 'source archive included local marketing drafts' >&2; exit 1
fi
mkdir -p internal/frontend
printf 'fixture dashboard\n' > internal/frontend/index.html
if out=$("$scripts/source-archive.sh" 1.2.3 "$work/private-tree.tar.gz" --worktree 2>&1); then
    echo 'source archive accepted private frontend worktree files' >&2; exit 1
fi
printf '%s\n' "$out" | grep -Fq 'public source boundary rejects internal/frontend/index.html'
git add internal/frontend/index.html
git commit -qm fixture-private-frontend
if out=$("$scripts/source-archive.sh" 1.2.3 "$work/private-ref.tar.gz" 2>&1); then
    echo 'source archive accepted a committed private frontend' >&2; exit 1
fi
printf '%s\n' "$out" | grep -Fq 'public source boundary rejects internal/frontend/index.html'
[ ! -e "$work/private-tree.tar.gz" ]
[ ! -e "$work/private-ref.tar.gz" ]

if [ -e "$scripts/../.git" ]; then
    (cd "$scripts/.." && "$scripts/source-archive.sh" 0.pipeline "$work/public-source.tar.gz")
fi

artifacts="$work/artifacts"
deb="$work/deb"
archpkg="$work/archpkg"
debugpkg="$work/debugpkg"
mkdir -p "$deb/DEBIAN" "$deb/usr/bin" "$archpkg/usr/bin" "$debugpkg/usr/lib/debug/usr/bin"
printf 'fixture cau\n' > "$deb/usr/bin/cau"
printf 'fixture cau-mcp\n' > "$deb/usr/bin/cau-mcp"
cp "$deb/usr/bin/"* "$archpkg/usr/bin/"
printf 'pkgname = cau\n' > "$archpkg/.PKGINFO"
printf 'pkgname = cau-debug\n' > "$debugpkg/.PKGINFO"
printf 'fixture debug file\n' > "$debugpkg/usr/lib/debug/usr/bin/cau.debug"

make_deb() {
    cat > "$deb/DEBIAN/control" <<EOF
Package: cau
Version: 1.2.3-1
Architecture: $1
Maintainer: Test fixture <test@example.invalid>
Description: Harmless package-boundary fixture
EOF
    dpkg-deb --build --root-owner-group "$deb" "$2" >/dev/null
}

for arch in amd64 arm64; do
    for distro in debian-trixie kali-rolling; do
        mkdir -p "$artifacts/cau-${distro}-${arch}"
        printf '%s/%s\n' "$distro" "$arch" > "$deb/usr/bin/cau"
        make_deb "$arch" "$artifacts/cau-${distro}-${arch}/cau_1.2.3-1_${arch}.deb"
    done
done
for pair in amd64:x86_64 arm64:aarch64; do
    mkdir -p "$artifacts/cau-archlinux-${pair%:*}"
    tar --zstd -cf "$artifacts/cau-archlinux-${pair%:*}/cau-1.2.3-1-${pair#*:}.pkg.tar.zst" -C "$archpkg" .
    tar --zstd -cf "$artifacts/cau-archlinux-${pair%:*}/cau-debug-1.2.3-1-${pair#*:}.pkg.tar.zst" -C "$debugpkg" .
done
"$scripts/stage-release-packages.sh" "$artifacts" "$work/dist"
[ "$(find "$work/dist" -type f | wc -l)" -eq 8 ]
for arch in amd64 arm64; do
    cmp "$artifacts/cau-debian-trixie-${arch}/cau_1.2.3-1_${arch}.deb" "$work/dist/cau_1.2.3-1_${arch}.deb"
    cmp "$artifacts/cau-kali-rolling-${arch}/cau_1.2.3-1_${arch}.deb" "$work/dist/cau-kali_1.2.3-1_${arch}.deb"
done

selected="$artifacts/cau-kali-rolling-arm64/cau_1.2.3-1_arm64.deb"
cp "$selected" "$work/kali-original.deb"
mkdir -p "$deb/etc/cau"
printf 'fixture tenant profile\n' > "$deb/etc/cau/fixture-tenant.json"
make_deb arm64 "$selected"
if out=$("$scripts/stage-release-packages.sh" "$artifacts" "$work/private-dist" 2>&1); then
    echo 'release staging accepted a tenant profile inside a neutral package' >&2; exit 1
fi
printf '%s\n' "$out" | grep -Fq 'public package boundary rejects'
printf '%s\n' "$out" | grep -Fq 'etc/cau/fixture-tenant.json'
[ ! -e "$work/private-dist" ]
mv "$work/kali-original.deb" "$selected"

selected="$artifacts/cau-archlinux-amd64/cau-1.2.3-1-x86_64.pkg.tar.zst"
cp "$selected" "$work/arch-original.pkg.tar.zst"
printf 'fixture managed connector\n' > "$archpkg/usr/bin/cau-managed-agent"
tar --zstd -cf "$selected" -C "$archpkg" .
if out=$("$scripts/stage-release-packages.sh" "$artifacts" "$work/connector-dist" 2>&1); then
    echo 'release staging accepted a managed connector inside an Arch archive' >&2; exit 1
fi
printf '%s\n' "$out" | grep -Fq 'public package boundary rejects'
printf '%s\n' "$out" | grep -Fq 'usr/bin/cau-managed-agent'
[ ! -e "$work/connector-dist" ]
mv "$work/arch-original.pkg.tar.zst" "$selected"

# Neither a successful Debian leg nor a debug package can mask a missing leg.
mv "$artifacts/cau-kali-rolling-arm64" "$work/missing-kali"
if out=$("$scripts/stage-release-packages.sh" "$artifacts" "$work/missing-kali-dist" 2>&1); then
    echo 'release staging accepted a missing Kali package' >&2; exit 1
fi
echo "release staging refused the missing Kali package: $out"
mv "$work/missing-kali" "$artifacts/cau-kali-rolling-arm64"
mv "$artifacts/cau-archlinux-arm64/cau-1.2.3-1-aarch64.pkg.tar.zst" "$work/missing-arch"
if out=$("$scripts/stage-release-packages.sh" "$artifacts" "$work/missing-arch-dist" 2>&1); then
    echo 'release staging accepted a debug package in place of the main package' >&2; exit 1
fi
echo "release staging refused the debug package: $out"
mv "$work/missing-arch" "$artifacts/cau-archlinux-arm64/cau-1.2.3-1-aarch64.pkg.tar.zst"
cp "$artifacts/cau-debian-trixie-amd64/cau_1.2.3-1_amd64.deb" "$artifacts/cau-debian-trixie-amd64/cau_1.2.4-1_amd64.deb"
if out=$("$scripts/stage-release-packages.sh" "$artifacts" "$work/ambiguous-dist" 2>&1); then
    echo 'release staging accepted ambiguous package versions' >&2; exit 1
fi
echo "release staging refused the ambiguous versions: $out"

mkdir "$work/unsigned-dist"
if out=$(env -u CAU_RELEASE_SIGNING_KEY -u CAU_RELEASE_PUBLIC_KEY \
    bash "$scripts/sign-release.sh" 1.2.3 "$work/unsigned-dist" 2>&1); then
    echo 'release signing accepted an unsigned publication' >&2
    exit 1
fi
printf '%s\n' "$out" | grep -Fq 'release signing requires the signing key and its trusted public key'
[ ! -e "$work/unsigned-dist/SHA256SUMS" ]

echo 'pipeline regressions: passed'
