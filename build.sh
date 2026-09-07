#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIST_DIR="${ROOT_DIR}/dist"

VERSION="${VERSION:-$(git -C "${ROOT_DIR}" describe --tags --always --dirty 2>/dev/null || echo "dev")}"
COMMIT="${COMMIT:-$(git -C "${ROOT_DIR}" rev-parse --short HEAD 2>/dev/null || echo "unknown")}"
BUILD_TIME="${BUILD_TIME:-$(date -u '+%Y-%m-%dT%H:%M:%SZ')}"

# 默认构建目标（可通过 TARGETS 环境变量覆盖，空格分隔）
# 例: TARGETS="linux/amd64 darwin/arm64" ./build.sh
TARGETS="${TARGETS:-linux/amd64 linux/arm64 windows/amd64 darwin/amd64 darwin/arm64}"

LDFLAGS="-s -w \
  -X RealityChecker/internal/version.Version=${VERSION} \
  -X RealityChecker/internal/version.Commit=${COMMIT} \
  -X RealityChecker/internal/version.BuildTime=${BUILD_TIME}"

rm -rf "${DIST_DIR}"
mkdir -p "${DIST_DIR}"

build_target() {
  local os="$1"
  local arch="$2"
  local suffix=""
  local name="reality-checker-${os}-${arch}"

  if [[ "${os}" == "windows" ]]; then
    suffix=".exe"
  fi

  echo "→ Building ${os}/${arch}..."
  CGO_ENABLED=0 GOOS="${os}" GOARCH="${arch}" \
    go build -trimpath -ldflags "${LDFLAGS}" \
    -o "${DIST_DIR}/${name}${suffix}" "${ROOT_DIR}"

  # 打包
  (
    cd "${DIST_DIR}"
    if [[ "${os}" == "windows" ]]; then
      if command -v zip >/dev/null 2>&1; then
        zip -q -j "${name}.zip" "${name}${suffix}"
      else
        echo "Warning: zip not found, skip packaging ${name}"
      fi
    else
      # Linux / macOS 使用 tar.gz（更通用）
      tar -czf "${name}.tar.gz" "${name}${suffix}"
    fi
  )
}

echo "========================================"
echo "Version   : ${VERSION}"
echo "Commit    : ${COMMIT}"
echo "BuildTime : ${BUILD_TIME}"
echo "Targets   : ${TARGETS}"
echo "========================================"

for target in ${TARGETS}; do
  os="${target%/*}"
  arch="${target#*/}"
  build_target "${os}" "${arch}"
done

# 生成校验和
(
  cd "${DIST_DIR}"
  # 只对最终发布文件做校验（排除裸二进制）
  shopt -s nullglob
  files=(*.zip *.tar.gz)
  if (( ${#files[@]} > 0 )); then
    if command -v sha256sum >/dev/null 2>&1; then
      sha256sum "${files[@]}" > checksums.txt
    elif command -v shasum >/dev/null 2>&1; then
      shasum -a 256 "${files[@]}" > checksums.txt
    fi
  fi
)

echo
echo "Build artifacts in ${DIST_DIR}:"
ls -lh "${DIST_DIR}"
