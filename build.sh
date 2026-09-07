```bash
#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIST_DIR="${ROOT_DIR}/dist"

VERSION="${VERSION:-$(git -C "${ROOT_DIR}" describe --tags --always --dirty 2>/dev/null || echo "dev")}"
COMMIT="${COMMIT:-$(git -C "${ROOT_DIR}" rev-parse --short HEAD 2>/dev/null || echo "unknown")}"
BUILD_TIME="${BUILD_TIME:-$(date -u '+%Y-%m-%dT%H:%M:%SZ')}"

LDFLAGS="-s -w \
-X RealityChecker/internal/version.Version=${VERSION} \
-X RealityChecker/internal/version.Commit=${COMMIT} \
-X RealityChecker/internal/version.BuildTime=${BUILD_TIME}"

rm -rf "${DIST_DIR}"
mkdir -p "${DIST_DIR}"

build_target() {
    local os="$1"
    local arch="$2"

    local name="reality-checker-${os}-${arch}"
    local binary="${name}"

    if [[ "${os}" == "windows" ]]; then
        binary="${name}.exe"
    fi

    echo
    echo "======================================"
    echo "Building ${os}/${arch}"
    echo "======================================"

    CGO_ENABLED=0 \
    GOOS="${os}" \
    GOARCH="${arch}" \
        go build \
            -trimpath \
            -ldflags "${LDFLAGS}" \
            -o "${DIST_DIR}/${binary}" \
            "${ROOT_DIR}"

    echo "Built: ${binary}"

    # Create ZIP package
    if command -v zip >/dev/null 2>&1; then
        (
            cd "${DIST_DIR}"
            zip -q -j "${name}.zip" "${binary}"
        )

        echo "Packaged: ${name}.zip"
    fi
}

echo "======================================"
echo "RealityChecker Build"
echo "======================================"
echo "Version   : ${VERSION}"
echo "Commit    : ${COMMIT}"
echo "Build time: ${BUILD_TIME}"
echo "======================================"

# Linux
build_target linux amd64
build_target linux arm64

# macOS
build_target darwin amd64
build_target darwin arm64

# Windows
build_target windows amd64

# Generate SHA256 checksums for all binaries and ZIP packages
(
    cd "${DIST_DIR}"

    sha256sum reality-checker-* > SHA256SUMS
)

echo
echo "======================================"
echo "Build artifacts"
echo "======================================"

ls -lh "${DIST_DIR}"

echo
echo "SHA256:"
cat "${DIST_DIR}/SHA256SUMS"

echo
echo "Build completed successfully."
```
