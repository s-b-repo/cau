# Source from the Windows MSYS2 build to select native tools for the runner.
set -euo pipefail

case "${NATIVE_ARCH:-}:${MSYSTEM:-}" in
    amd64:UCRT64)
        windows_compiler=gcc
        windows_objdump=objdump
        windows_host=x86_64-w64-mingw32
        ;;
    arm64:CLANGARM64)
        windows_compiler=clang
        windows_objdump=llvm-objdump
        windows_host=aarch64-w64-mingw32
        ;;
    *)
        printf 'Unsupported Windows build environment: %s in %s\n' "${NATIVE_ARCH:-unset}" "${MSYSTEM:-unset}" >&2
        return 1
        ;;
esac

windows_prefix=$(cygpath -m "$MSYSTEM_PREFIX")
export CC="$windows_prefix/bin/$windows_compiler.exe"
export PKG_CONFIG="$windows_prefix/bin/pkgconf.exe"
