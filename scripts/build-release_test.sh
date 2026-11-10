#!/usr/bin/env bash
set -euo pipefail

SOURCE_ROOT=$(git rev-parse --show-toplevel)
TAG=v1.2.3
REAL_GO=$(command -v go)

TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/build-release-test.XXXXXX")
GO_ARGS_LOG="$TEST_ROOT/go-build-args"
export REAL_GO GO_ARGS_LOG
trap 'rm -rf "$TEST_ROOT"' EXIT
REPO="$TEST_ROOT/repo"
LOG="$TEST_ROOT/release.log"
mkdir -p "$REPO/scripts" "$REPO/cmd/uservone-mtproto" "$TEST_ROOT/bin"
cp "$SOURCE_ROOT/scripts/build-release.sh" "$REPO/scripts/build-release.sh"
cat > "$REPO/go.mod" <<'EOF'
module releasefixture

go 1.25
EOF
cat > "$REPO/cmd/uservone-mtproto/main.go" <<'EOF'
package main

import "fmt"

var version = "v0.3.0"

func main() { fmt.Print(version) }
EOF
cat > "$REPO/.gitignore" <<'EOF'
/dist/
/cmd/uservone-mtproto/ignored.go
EOF
cat > "$TEST_ROOT/bin/go" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == build ]]; then
  printf '%s\n' "$@" > "$GO_ARGS_LOG"
fi
exec "$REAL_GO" "$@"
EOF
chmod +x "$TEST_ROOT/bin/go"
TEST_BIN="$TEST_ROOT/bin"
if command -v cygpath >/dev/null 2>&1; then
  TEST_BIN=$(cygpath -u "$TEST_BIN")
fi

git_repo() {
  if command -v cygpath >/dev/null 2>&1; then
    git -C "$(cygpath -m "$REPO")" "$@"
  else
    git -C "$REPO" "$@"
  fi
}

git_repo init -q
git_repo config user.name 'Release Test'
git_repo config user.email 'release-test@example.invalid'
git_repo add .
git_repo commit -qm 'fixture'
git_repo tag "$TAG"

run_release() {
  (cd "$REPO" && PATH="$TEST_BIN:$PATH" bash scripts/build-release.sh "$1") >"$LOG" 2>&1
}

expect_rejection() {
  if run_release "$1"; then
    cat "$LOG"
    echo "release unexpectedly accepted $1" >&2
    return 1
  fi
}

reset_repo() {
  git_repo reset --hard -q "$TAG"
  git_repo clean -fdxq
}

test_dirty_tree() {
  printf '\n// dirty\n' >> "$REPO/cmd/uservone-mtproto/main.go"
  expect_rejection "$TAG"
}

test_untracked_file() {
  printf 'untracked\n' > "$REPO/untracked.txt"
  expect_rejection "$TAG"
}

test_non_exact_tag() {
  printf '\n// new commit\n' >> "$REPO/cmd/uservone-mtproto/main.go"
  git_repo add .
  git_repo commit -qm 'after tag'
  expect_rejection "$TAG"
}

test_tag_mismatch() {
  expect_rejection v9.9.9
}

test_malformed_tag() {
  local malformed='v1.2'
  git_repo tag "$malformed" || return 1
  local status=0
  expect_rejection "$malformed" || status=$?
  git_repo tag -d "$malformed" >/dev/null || return 1
  return "$status"
}

test_version_and_metadata() {
  run_release "$TAG" || { cat "$LOG"; return 1; }
  local out="$REPO/dist/release-$TAG"
  local outNative="$out"
  if command -v cygpath >/dev/null 2>&1; then
    outNative=$(cygpath -m "$out")
  fi
  if ! grep -F -- "-X main.version=$TAG" "$GO_ARGS_LOG" >/dev/null; then
    echo "go build did not inject main.version=$TAG" >&2
    return 1
  fi
  python3 - "$outNative/buildinfo.json" "$outNative/sbom.spdx.json" "$TAG" "$(git_repo rev-parse "$TAG^{commit}")" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as file:
    build = json.load(file)
with open(sys.argv[2], encoding="utf-8") as file:
    sbom = json.load(file)
assert build["version"] == sys.argv[3]
assert build["commit"] == sys.argv[4]
assert sbom["packages"][0]["versionInfo"] == sys.argv[3]
PY
}

test_ignored_go_source_excluded() {
  printf 'package main\nfunc init() {\n' > "$REPO/cmd/uservone-mtproto/ignored.go"
  run_release "$TAG" || { cat "$LOG"; return 1; }
  local out="$REPO/dist/release-$TAG"
  local outNative="$out"
  if command -v cygpath >/dev/null 2>&1; then
    outNative=$(cygpath -m "$out")
  fi
  python3 - "$outNative/uservone-mtproto-source.zip" <<'PY'
import sys
import zipfile

with zipfile.ZipFile(sys.argv[1]) as archive:
    assert all(not name.endswith("/cmd/uservone-mtproto/ignored.go") for name in archive.namelist())
PY
}

test_clean_output() {
  run_release "$TAG" || { cat "$LOG"; return 1; }
  local stale="$REPO/dist/release-$TAG/stale-artifact"
  printf 'stale\n' > "$stale"
  run_release "$TAG" || { cat "$LOG"; return 1; }
  if [[ -e "$stale" ]]; then
    echo 'stale output survived a subsequent release build' >&2
    return 1
  fi
}

test_publish_job_has_checkout() {
  local workflow="$SOURCE_ROOT/.github/workflows/release.yml"
  if command -v cygpath >/dev/null 2>&1; then
    workflow=$(cygpath -m "$workflow")
  fi
  python3 - "$workflow" <<'PY'
import sys

lines = open(sys.argv[1], encoding="utf-8").read().splitlines()
start = next((index for index, line in enumerate(lines) if line.startswith("  publish:")), None)
assert start is not None, "publish job is missing"
end = next((index for index in range(start + 1, len(lines))
            if lines[index] and not lines[index].startswith("    ")), len(lines))
block = "\n".join(lines[start:end])
assert "actions/checkout@v4" in block, "publish job must create a Git repository for gh release create"
assert "persist-credentials: false" in block, "publish checkout must not persist credentials"
PY
}

failures=0
for test in \
  test_dirty_tree \
  test_untracked_file \
  test_non_exact_tag \
  test_tag_mismatch \
  test_malformed_tag \
  test_version_and_metadata \
  test_ignored_go_source_excluded \
  test_clean_output \
  test_publish_job_has_checkout; do
  reset_repo
  if (set -e; "$test"); then
    printf 'ok - %s\n' "$test"
  else
    printf 'FAIL - %s\n' "$test" >&2
    failures=$((failures + 1))
  fi
done

if ((failures > 0)); then
  printf '%d release test(s) failed\n' "$failures" >&2
  exit 1
fi
