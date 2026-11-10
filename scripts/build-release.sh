#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:-v0.3.0}"
if [[ ! "$VERSION" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
  echo "version must be a strict vMAJOR.MINOR.PATCH tag" >&2
  exit 2
fi

ROOT=$(git rev-parse --show-toplevel)
if [[ -n "$(git status --porcelain --untracked-files=all)" ]]; then
  echo "release source must not contain modified or untracked files" >&2
  exit 1
fi
EXACT_TAG=$(git describe --tags --exact-match HEAD 2>/dev/null) || {
  echo "release source HEAD must have an exact tag" >&2
  exit 1
}
if [[ "$EXACT_TAG" != "$VERSION" ]]; then
  echo "version $VERSION does not match HEAD tag $EXACT_TAG" >&2
  exit 1
fi

COMMIT=$(git rev-parse HEAD)
OUT="$ROOT/dist/release-$VERSION"
GO_VERSION=$(go version)
BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
SOURCE_EXPORT=$(mktemp -d "${TMPDIR:-/tmp}/uservone-release.XXXXXX")
trap 'rm -rf "$SOURCE_EXPORT"' EXIT
git archive --format=tar HEAD | tar -x -C "$SOURCE_EXPORT"

rm -rf -- "$OUT"
mkdir -p "$OUT"
(
  cd "$SOURCE_EXPORT"
  for ARCH in amd64 arm64; do
    CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build \
      -trimpath -ldflags="-s -w -buildid= -X main.version=$VERSION" \
      -o "$OUT/uservone-mtproto-linux-$ARCH" ./cmd/uservone-mtproto
  done
)
git archive --format=zip --prefix=uservone-mtproto/ -o "$OUT/uservone-mtproto-source.zip" HEAD

cat > "$OUT/buildinfo.json" <<EOF
{
  "name": "uservone-mtproto",
  "version": "$VERSION",
  "commit": "$COMMIT",
  "build_date": "$BUILD_DATE",
  "go_version": "$GO_VERSION",
  "targets": ["linux/amd64", "linux/arm64"],
  "docker_image": "ghcr.io/userv-one/uservone-mtproto:$VERSION"
}
EOF

cat > "$OUT/sbom.spdx.json" <<EOF
{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "uservone-mtproto-$VERSION",
  "documentNamespace": "https://github.com/userv-one/uservone-mtproto/releases/tag/$VERSION#$COMMIT",
  "creationInfo": {
    "created": "$BUILD_DATE",
    "creators": ["Tool: uservone-mtproto-release-script"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-Package-uservone-mtproto",
      "name": "uservone-mtproto",
      "versionInfo": "$VERSION",
      "downloadLocation": "https://github.com/userv-one/uservone-mtproto",
      "filesAnalyzed": false,
      "licenseConcluded": "MIT",
      "supplier": "Organization: userv-one"
    }
  ],
  "relationships": [
    {
      "spdxElementId": "SPDXRef-DOCUMENT",
      "relationshipType": "DESCRIBES",
      "relatedSpdxElement": "SPDXRef-Package-uservone-mtproto"
    }
  ]
}
EOF

cd "$OUT"
sha256sum uservone-mtproto-linux-amd64 uservone-mtproto-linux-arm64 uservone-mtproto-source.zip buildinfo.json sbom.spdx.json > SHA256SUMS
sha256sum -c SHA256SUMS
