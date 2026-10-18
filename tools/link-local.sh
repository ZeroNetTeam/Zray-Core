#!/usr/bin/env bash
# Build a consumer repository against this checkout of Zray-Core instead of the
# pinned git revision, so a change here and the change that uses it can be
# tried together before either is pushed.
#
#   tools/link-local.sh ../ZeroNet-Desktop
#   tools/link-local.sh ../ZeroNet-Mobile/native
#
# It writes <consumer>/.cargo/config.toml with two kinds of [patch]:
#   * every crate of this workspace, patched over the git dependency;
#   * the vendored rustls and netstack-smoltcp, patched over crates.io, because
#     a consumer repeats that patch (Cargo ignores a dependency's own).
# .cargo/ is ignored by the consumers, so it never reaches a commit. Delete the
# file to go back to the pinned revision. While it exists Cargo rewrites the
# consumer's Cargo.lock to match your local checkout: run
# `git checkout Cargo.lock` before committing there, and use
# `cargo update -p zero-core` after the core change has been pushed.
set -euo pipefail

if [[ $# -ne 1 || ! -f "$1/Cargo.toml" ]]; then
    echo "usage: $0 <directory with the consumer's Cargo.toml>" >&2
    exit 2
fi
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
consumer="$(cd "$1" && pwd)"
repo="https://github.com/ZeroNetTeam/Zray-Core"

mkdir -p "$consumer/.cargo"
python3 - "$here" "$repo" > "$consumer/.cargo/config.toml" <<'PY'
import pathlib, sys, tomllib

root, repo = pathlib.Path(sys.argv[1]), sys.argv[2]
print(f'# Written by Zray-Core/tools/link-local.sh. Not committed.\n[patch."{repo}"]')
for manifest in sorted(root.glob("crates/*/Cargo.toml")):
    name = tomllib.loads(manifest.read_text())["package"]["name"]
    print(f'{name} = {{ path = "{manifest.parent}" }}')
print("\n[patch.crates-io]")
for vendored in ("rustls", "netstack-smoltcp"):
    print(f'{vendored} = {{ path = "{root / "vendor" / vendored}" }}')
PY
echo "wrote $consumer/.cargo/config.toml"
