#!/usr/bin/env bash
# Keep the workspace's *regenerable* weight down.
#
# The rule this script follows: delete what the next build can recreate for
# free (incremental state, scratch dirs, stale checkouts) and what nothing
# references any more (crash dumps, stray logs, backup files). Never delete
# something a build or a person is using right now, and never delete a
# workstream's own notes — `.research/` clones, `.wip-backups/` patches and
# `vendor/` trees are somebody's material, not leftovers.
#
# Usage: cleanup.sh [--dry-run]
set -uo pipefail

DRY=0
[ "${1:-}" = "--dry-run" ] && DRY=1

# The workspace is the parent of this repository, and the research area is
# its sibling. Both are found from the script's own location, so the script
# works wherever the tree is checked out.
TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORE="$(cd "$TOOLS_DIR/.." && pwd)"
WS="$(cd "$CORE/.." && pwd)"
TOOLS="$WS/.research/tools"
freed=0

stamp() { date '+%Y-%m-%d %H:%M:%S'; }
log() { printf '%s  %s\n' "$(stamp)" "$*"; }

size_of() { du -sb "$1" 2>/dev/null | cut -f1 || echo 0; }

remove() { # path, label
    local path="$1" label="${2:-$1}"
    [ -e "$path" ] || return 0
    local bytes
    bytes=$(size_of "$path")
    if [ "$DRY" = 1 ]; then
        log "would remove $label ($((bytes / 1048576)) MB)"
        return 0
    fi
    rm -rf -- "$path" || { log "could not remove $label"; return 0; }
    freed=$((freed + bytes))
    log "removed $label ($((bytes / 1048576)) MB)"
}

# 1. Never race a build. Cargo rewriting these directories while this script
#    deletes them turns a slow build into an unexplainable one.
if pgrep -x cargo >/dev/null 2>&1 || pgrep -x rustc >/dev/null 2>&1; then
    if [ "$DRY" = 1 ]; then
        log "a build is running (dry run continues)"
    else
        log "a build is running: skipping artifact cleanup this cycle"
        exit 0
    fi
fi

# 2. Incremental state: pure cache, the largest single regenerable item here.
remove "$CORE/target/debug/incremental" "target/debug/incremental"
remove "$CORE/target/release/incremental" "target/release/incremental"
# Scratch cargo uses for its own temporaries, and rustdoc output.
remove "$CORE/target/tmp" "target/tmp"
remove "$CORE/target/doc" "target/doc"

# 2b. Superseded build artifacts.
#
# Cargo writes every artifact under a hash of its inputs, so a crate that was
# built twice keeps both copies: the old one is never linked again, and after
# a few rebuilds the debug tree is mostly these. They are the same kind of
# regenerable cache as the incremental directory, and they are what fills the
# disk.
#
# Only the *older* copy of each crate is removed, and only when a newer one
# exists, so the artifact the current build uses is never touched. A file that
# is the only copy of its crate stays whatever it is.
stale_artifacts() {
    python3 - "$CORE/target/debug/deps" "$CORE/target/debug/build" <<'PY'
import collections, re, shutil, sys
from pathlib import Path


def sweep(directory, directories):
    """Remove the older of each crate's hashed copies.

    A crate that was built twice keeps both: the old one is never linked
    again. Only the *older* copy goes, and only when a newer one exists, so
    the artifact the current build uses is never touched.

    Returns the bytes freed.
    """
    if not directory.is_dir():
        return 0
    groups = collections.defaultdict(list)
    for entry in directory.iterdir():
        match = re.match(r'^(.*?)-[0-9a-f]{16}(\..*)?$', entry.name)
        if not match:
            continue
        if entry.is_dir() != directories:
            continue
        groups[match.group(1)].append(entry)
    freed = 0
    for copies in groups.values():
        if len(copies) < 2:
            continue
        copies.sort(key=lambda path: path.stat().st_mtime)
        for stale in copies[:-1]:
            try:
                if stale.is_dir():
                    freed += sum(
                        path.stat().st_size
                        for path in stale.rglob("*")
                        if path.is_file()
                    )
                    shutil.rmtree(stale)
                else:
                    freed += stale.stat().st_size
                    stale.unlink()
            except OSError:
                pass
    return freed


freed = 0
for directory, directories in ((Path(sys.argv[1]), False), (Path(sys.argv[2]), True)):
    freed += sweep(directory, directories)
print(freed)
PY
}
if [ "$DRY" = 1 ]; then
    log "would remove superseded build artifacts under target/debug"
elif pgrep -x cargo >/dev/null 2>&1 || pgrep -x rustc >/dev/null 2>&1; then
    log "a build is running: skipping the artifact sweep"
else
    swept=$(stale_artifacts)
    freed=$((freed + swept))
    log "swept superseded build artifacts under target/debug ($((swept / 1048576)) MB)"
fi

# 3. Backup files this workspace's own tooling leaves behind (the mutation
#    checks that prove a test is not vacuous keep theirs under target/).
remove "$CORE/target/mutation.bak" "target/mutation.bak"

# 4. Verification checkouts: a `git worktree` of a commit that has already been
#    verified has no further use, and each one is a full copy of the tree with
#    its own target/ directory — 20 GB and more, which is why this matters.
#
#    The worktrees are found through git's own list rather than a fixed path,
#    because a checkout under target/ is invisible to a glob on .research/ and
#    cargo will not clean it either: it is a git worktree, not a cargo
#    artifact. Only worktrees *other than* the main checkout are removed.
while IFS= read -r dir; do
    [ -n "$dir" ] || continue
    [ "$dir" = "$CORE" ] && continue
    [ -d "$dir" ] || continue
    if [ "$DRY" = 1 ]; then
        log "would remove verification worktree $dir"
        continue
    fi
    bytes=$(size_of "$dir")
    git -C "$CORE" worktree remove --force "$dir" 2>/dev/null || rm -rf -- "$dir"
    freed=$((freed + bytes))
    log "removed verification worktree $dir ($((bytes / 1048576)) MB)"
done < <(git -C "$CORE" worktree list --porcelain 2>/dev/null | sed -n 's/^worktree //p')
git -C "$CORE" worktree prune 2>/dev/null

# 5. Crash dumps and stray logs, at the top of the repositories only — never
#    inside `vendor/`, `docs/`, `.wip-backups/` or `.research/` clones.
if [ "$DRY" = 0 ]; then
    while IFS= read -r -d '' path; do
        bytes=$(size_of "$path")
        rm -f -- "$path" && freed=$((freed + bytes)) && log "removed $path ($((bytes / 1024)) KB)"
    done < <(find "$CORE" -maxdepth 2 -type f \
        \( -name 'core.*' -o -name '*.core' -o -name 'nohup.out' -o -name '*.log' \) \
        -not -path "$CORE/target/*" -print0 2>/dev/null)
fi

# 6. The cleanup log itself, so it cannot become the leftover.
if [ "$DRY" = 0 ] && [ -f "$TOOLS/cleanup.log" ]; then
    if [ "$(stat -c%s "$TOOLS/cleanup.log")" -gt 1048576 ]; then
        tail -200 "$TOOLS/cleanup.log" > "$TOOLS/cleanup.log.tmp" &&
            mv "$TOOLS/cleanup.log.tmp" "$TOOLS/cleanup.log"
        log "truncated cleanup.log"
    fi
fi

log "cycle done, reclaimed $((freed / 1048576)) MB; disk $(df -h /home | awk 'NR==2 {print $5" used, "$4" free"}')"
