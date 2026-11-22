#!/usr/bin/env python3
"""Inspect public Debian, Kali and Arch package member names without extracting them."""

import posixpath
import re
import subprocess
import sys
import tarfile
from pathlib import Path


BASE_BINARIES = {"usr/bin/cau", "usr/bin/cau-mcp"}
SYSTEMD_UNITS = {
    "cau-daemon.service", "cau-defend.service", "cau-scan.service", "cau-scan.timer",
    "cau-update.service", "cau-update.timer",
}
PUBLIC_PAYLOAD = BASE_BINARIES | {
    "etc/cau/cau.conf", "etc/logrotate.d/cau", "usr/lib/sysusers.d/cau.conf",
    "usr/share/bash-completion/completions/cau", "usr/share/fish/vendor_completions.d/cau.fish",
    "usr/share/zsh/site-functions/_cau", "usr/share/licenses/cau/LICENSE",
    "usr/share/lintian/overrides/cau", "usr/share/cau/rules/rule_list.yar",
    "usr/share/cau/signatures/fuzzy.txt", "usr/share/cau/signatures/hashes.txt",
} | {
    f"{prefix}lib/systemd/system/{unit}" for prefix in ("", "usr/") for unit in SYSTEMD_UNITS
} | {
    f"usr/share/doc/cau/{filename}{suffix}"
    for filename in ("LICENSE", "README.md", "README.Debian", "CHANGELOG.md", "changelog", "changelog.Debian", "copyright")
    for suffix in ("", ".gz")
} | {
    f"usr/share/man/man1/{binary}.1{suffix}"
    for binary in ("cau", "cau-mcp") for suffix in ("", ".gz")
}
DEB_CONTROL = {"control", "conffiles", "md5sums", "preinst", "postinst", "prerm", "postrm", "triggers"}
ARCH_METADATA = {".PKGINFO", ".BUILDINFO", ".MTREE"}
ARCH_DEBUG = ARCH_METADATA | {f"usr/lib/debug/{binary}.debug" for binary in BASE_BINARIES}
DEBUG_ID = re.compile(r"usr/lib/debug/\.build-id/[a-f0-9]{2}(/[a-f0-9]+\.debug)?\Z")


def inspect(stream, allowed, required, debug=False):
    directories = {"."}
    for path in allowed:
        while (path := posixpath.dirname(path)):
            directories.add(path)
    if debug:
        directories.add("usr/lib/debug/.build-id")

    seen = set()
    with tarfile.open(fileobj=stream, mode="r|") as archive:
        for entry in archive:
            path = entry.name.removeprefix("./") or "."
            debug_id = debug and DEBUG_ID.fullmatch(path)
            if entry.isdir():
                accepted = path in directories or (debug_id and path.count("/") == 4)
            elif entry.isreg() or entry.issym() or entry.islnk():
                accepted = path in allowed or (debug_id and path.endswith(".debug"))
            else:
                accepted = False
            if path in required and not entry.isreg():
                accepted = False
            if not accepted or path in seen or len(seen) >= 4096:
                raise ValueError(f"unexpected package member {entry.name!r}")
            if entry.issym() or entry.islnk():
                parent = posixpath.dirname(path) if entry.issym() else ""
                target = posixpath.normpath(posixpath.join(parent, entry.linkname)).lstrip("/")
                if target not in allowed or target == path:
                    raise ValueError(f"unexpected link target for {entry.name!r}")
            seen.add(path)
    if not required <= seen:
        raise ValueError(f"missing required package files {', '.join(sorted(required - seen))}")


def inspect_command(command, allowed, required, debug=False):
    with subprocess.Popen(command, stdout=subprocess.PIPE) as process:
        try:
            inspect(process.stdout, allowed, required, debug)
            # Drain transport bytes after the tar end marker before checking its status.
            while process.stdout.read(65536):
                pass
        except Exception:
            if process.poll() is None:
                process.kill()
            raise
        if process.wait() != 0:
            raise ValueError(f"{command[0]} could not read the package")


def check(path):
    if path.suffix == ".deb":
        inspect_command(["dpkg-deb", "--fsys-tarfile", path], PUBLIC_PAYLOAD, BASE_BINARIES)
        inspect_command(["dpkg-deb", "--ctrl-tarfile", path], DEB_CONTROL, {"control"})
    elif path.name.endswith((".pkg.tar.zst", ".pkg.tar.xz")):
        decoder = "zstd" if path.suffix == ".zst" else "xz"
        if path.name.startswith("cau-debug-"):
            inspect_command([decoder, "-dc", "--", path], ARCH_DEBUG, {".PKGINFO"}, debug=True)
        else:
            inspect_command([decoder, "-dc", "--", path], PUBLIC_PAYLOAD | ARCH_METADATA, BASE_BINARIES | {".PKGINFO"})
    else:
        raise ValueError("unrecognized release package format")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: check-release-package.py PACKAGE")
    package = Path(sys.argv[1]).resolve()
    try:
        check(package)
    except (OSError, ValueError, tarfile.TarError) as error:
        sys.exit(f"public package boundary rejects {package.name}: {error}")
