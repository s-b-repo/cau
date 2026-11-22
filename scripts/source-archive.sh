#!/usr/bin/env bash
# Build the same fixed-byte source archive for releases and the packaging gate.
# Usage: source-archive.sh VERSION OUTPUT [GIT_REF|--worktree]
set -euo pipefail

[ "$#" -ge 2 ] && [ "$#" -le 3 ] || {
    echo "usage: $0 VERSION OUTPUT [GIT_REF|--worktree]" >&2
    exit 2
}
version=$1
output=$2
ref=${3:-HEAD}
case "$version" in
    ''|*[!0-9A-Za-z._+-]*) echo "invalid source version: $version" >&2; exit 2 ;;
esac

# GitHub's source archive includes the whole committed tree. Review new
# top-level source areas and public entry points here before shipping them.
public_source_path() {
    local path=$1
    case "/${path,,}/" in
        */cau-console/*|*/cau-managed-agent/*|*/frontend/*|*/web/*|*/client-overlays/*|*/tenant-overlays/*|*/brand-profiles/*)
            return 1 ;;
    esac
    if [[ $path != */* ]]; then
        case "$path" in
            .gitattributes|.gitignore|*.go|go.mod|go.sum|Makefile|LICENSE|CHANGELOG.md|PLAN.md|README.md|SECURITY.md|SUPPORT.md|gaps.md|pricing.toml|cau-guide.html|cau-guide.pdf)
                return 0 ;;
        esac
    fi
    case "$path" in
        .github/*|cmd/cau-mcp/*|baselines/*|completions/*|corpus/*|debian/*|docs/*|internal/*|packaging/*|rules/*|scanner/*|scripts/*|signatures/*|vendor/*|vmtest/*|wiki/*)
            return 0 ;;
    esac
    return 1
}

refuse_source() {
    printf 'public source boundary rejects %q\n' "$1" >&2
    exit 1
}

stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT HUP INT TERM
# Keep packaging/systemd and the shared configuration: make install needs them.
# The Arch recipe hashes this archive, so exclude it to avoid a checksum cycle.
if [ "$ref" = --worktree ]; then
    # A local build must include edits and new source files, while leaving
    # ignored build products and nested working copies out of its archive.
    # A NUL-delimited manifest handles spaces and newlines in source paths.
    git ls-files -z --cached --deduplicate -- . > "$stage/worktree"
    # Local marketing drafts are outside the build. Keep tracked paths in the
    # boundary check even if someone stages one of those drafts.
    git ls-files -z --others --exclude-standard -- . ':(exclude)marketing' >> "$stage/worktree"
    while IFS= read -r -d '' source_file; do
        [ -e "$source_file" ] || [ -L "$source_file" ] || continue
        public_source_path "$source_file" && [ -f "$source_file" ] && [ ! -L "$source_file" ] || refuse_source "$source_file"
        case "$source_file" in packaging/arch/*|debian/*|.github/*) continue ;; esac
        printf '%s\0' "$source_file"
    done < "$stage/worktree" > "$stage/paths"
    mkdir "$stage/cau-${version}"
    tar --null --verbatim-files-from --no-recursion -T "$stage/paths" \
        -cf "$stage/source.tar"
    tar -xf "$stage/source.tar" -C "$stage/cau-${version}"
else
    commit=$(git rev-parse --verify --end-of-options "${ref}^{commit}")
    git ls-tree -rz --full-tree "$commit" > "$stage/tree"
    while IFS= read -r -d '' entry; do
        mode=${entry%% *}
        source_file=${entry#*$'\t'}
        case "$mode" in 100644|100755) ;; *) refuse_source "$source_file" ;; esac
        public_source_path "$source_file" || refuse_source "$source_file"
    done < "$stage/tree"
    git archive --format=tar --prefix="cau-${version}/" "$commit" -- . \
        ':(exclude)packaging/arch' ':(exclude)debian' ':(exclude).github' > "$stage/source.tar"
    tar -xf "$stage/source.tar" -C "$stage"
fi
tar --sort=name --mtime='@1735689600' --owner=0 --group=0 \
    --numeric-owner --format=gnu -C "$stage" -cf "$stage/normalized.tar" "cau-${version}"
gzip -9n < "$stage/normalized.tar" > "$output"
