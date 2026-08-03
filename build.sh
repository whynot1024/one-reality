#!/usr/bin/env bash

set -euo pipefail

# 获取 Git 版本、Commit 哈希及当前 UTC 时间
VERSION=$(git describe --tags --always --dirty 2>/dev/null || echo "v3.0.0-embedded")
COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "custom")
BUILD_TIME=$(date -u '+%Y-%m-%d_%H:%M:%S')

echo "=========================================="
echo "正在编译 REALITY 单二进制工具..."
echo "版本 (Version):    ${VERSION}"
echo "提交 (Commit):     ${COMMIT}"
echo "时间 (BuildTime):  ${BUILD_TIME}"
echo "=========================================="

go build -ldflags "-s -w \
  -X RealityChecker/internal/version.Version=${VERSION} \
  -X RealityChecker/internal/version.Commit=${COMMIT} \
  -X RealityChecker/internal/version.BuildTime=${BUILD_TIME}" \
  -o ../reality-checker .

echo "编译完成！二进制位置: /home/ryu/script/reality/reality-checker"
