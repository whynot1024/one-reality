# RealityChecker

RealityChecker 是一个用于发现、检测和筛选 Reality SNI 目标的网站检测工具。它把
ASN 网段发现、IP 扫描结果解析、TLS/证书/网络特征检测和推荐排序串成一条工作流，
帮助你从入口 VPS 的 IP 出发，快速找到更适合作为 Reality 目标的真实网站。

> 本项目仅用于技术研究和学习。请遵守当地法律法规，并合理使用网络资源。

## 核心工作流

### 工作流一：根据 VPS IP 自动查询并筛选目标（推荐）

这是最完整的使用方式。输入一个 VPS IP 后，程序会：

1. 查询该 IP 所属 ASN；
2. 通过公开的 RIPEstat API 获取该 ASN 当前宣布的网段；
3. 根据入口 IP 的国家或 `--country` 指定的国家过滤网段；
4. 并发扫描候选网段中的 IP，解析其证书 SNI；
5. 对域名执行 Reality 适配性检测，并按推荐星级输出结果。

```bash
./reality-checker auto 85.155.184.100 --limit 5
```

单个 IP 会按就近原则扩展为 IPv4 `/24` 或 IPv6 `/64` 网段用于扫描；
如果输入的是 CIDR，则直接扫描该网段：

```bash
./reality-checker auto 5.45.102.0/24 --limit 10
```

指定国家过滤（ISO 两位代码，也支持 GeoIP 数据库中的国家名称）：

```bash
./reality-checker auto 85.155.184.100 --country US --limit 10
```

`--limit` 是最终保留的合适目标数量上限，不是扫描 IP 数量。默认值为 5。
自动流程会持续扫描候选 IP，直到找到足够的合适目标或候选网段扫描结束。

### 工作流二：先查询 ASN 网段，再自定义扫描

只想获取某个 ASN 在指定国家的 CIDR 时：

```bash
./reality-checker asn AS15169 US > as15169-us.txt
```

也可以使用 `--country` 和自定义 GeoIP 数据库：

```bash
./reality-checker asn --country DE --db data/Country.mmdb AS12345 > as12345-de.txt
```

然后扫描文件中的网段（每行一个 CIDR 或 IP）：

```bash
./reality-checker auto --in ./as15169-us.txt --limit 10
```

`--in` 适合混合使用自动查询结果和手工整理的网段。空行会被忽略，输入会自动去重。

### 工作流三：配合 RealiTLScanner 的 CSV 结果

先使用 RealiTLScanner 获取候选结果，再让 RealityChecker 根据证书域名重新检测：

```bash
./RealiTLScanner -addr 85.155.184.0/23 -port 443 \
  -thread 100 -timeout 5 -out result.csv

./reality-checker csv result.csv
```

程序优先读取 CSV 的 `CERT_DOMAIN` 列，会自动去重并跳过通配符、明显的占位域名
和 IP 地址。建议 RealiTLScanner 在本地直连网络运行，避免代理影响检测结果。

### 工作流四：从标准输入流式检测

`pipe` 可以接收纯域名列表，也可以接收 RealiTLScanner 的 CSV 或 CSV 行，
适合实时处理扫描输出：

```bash
./RealiTLScanner -addr 85.155.184.0/23 -out /dev/stdout |
  ./reality-checker pipe
```

也可以直接检测域名列表：

```bash
printf "example.com\nexample.org\n" | ./reality-checker pipe
```

管道模式会自动去重，并即时打印发现的可用 Reality 目标，结束时输出排序后的表格。

## 检测内容与结果

只有通过核心 Reality 条件的结果才会被标记为适合目标。检测内容包括：

- TLS 1.3、X25519 和 HTTP/2 支持；
- TLS 握手延迟；
- 证书有效性、剩余有效期和 SNI 匹配；
- HTTP 状态码、网络连通性和重定向；
- 目标 IP 的地理位置；
- CDN 使用情况及 CDN 提供商；
- 热门网站识别和 GFWList 被墙检测。

自动、批量和管道模式会输出推荐星级及排序结果。单域名检测会同时显示适合性和
不适合原因，便于定位是 CDN、热门站点、证书、协议还是网络条件不满足。

典型结果关注以下字段：

```text
域名              IP              TLS1.3  X25519  HTTP/2  SNI匹配  证书  握手  推荐
example.com       203.0.113.10    是      是      是       是       有效  180ms ★★★★
```

“可用 Reality 目标”表示硬性协议和证书条件通过；最终选择时仍建议手动打开域名，
确认它是正常运营的真实网站，而不是默认页、演示站、管理面板或明显的占位服务。

## 命令速查

```text
reality-checker asn <ASN> <国家>             查询并按国家过滤 ASN CIDR
reality-checker auto <ip/cidr> [选项]        从 IP/CIDR 自动发现并筛选目标
reality-checker auto --in <文件> [选项]     扫描文件中的 IP/CIDR
reality-checker pipe                         从 stdin 流式检测域名或 CSV
reality-checker check <domain>               检测单个域名
reality-checker batch <d1> <d2> ...          并发检测多个域名
reality-checker csv <csv_file>               检测 RealiTLScanner CSV
reality-checker version                      显示版本、提交和构建信息
```

自动模式常用选项：

```text
--country CODE          指定国家过滤
--limit N               合适目标数量上限，默认 5
--no-cdn / --allow-cdn  是否排除 CDN，默认排除
--no-hot / --allow-hot  是否排除热门大站，默认排除
--max-handshake MS      最大 TLS 握手延迟
--min-cert-days DAYS    证书最低剩余有效天数
--min-stars STARS       最低推荐星级（1-5）
--debug                 输出逐 IP 调试日志
--log-level LEVEL       设置日志级别
```

## 快速开始

### 直接下载

从 [Releases](https://github.com/qualvey/RealityChecker/releases) 下载对应平台的压缩包。

### 本地构建

需要 Go 1.25 或更高版本。构建产物输出到 `dist/`，包含 Linux `amd64`/`arm64`
和 Windows `amd64`：

```bash
# Linux/macOS
./build.sh
```

```powershell
# Windows PowerShell
.\build.ps1
```

### 数据文件

首次运行会尝试准备检测所需数据。若自动下载失败，请将以下文件放入 `data/`：

- [Country.mmdb](https://github.com/Loyalsoldier/geoip/releases/latest/download/Country.mmdb)
- [gfwlist.conf](https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/gfw.txt)
- [cdn_keywords.txt](https://raw.githubusercontent.com/V2RaySSR/RealityChecker/main/data/cdn_keywords.txt)
- [hot_websites.txt](https://raw.githubusercontent.com/V2RaySSR/RealityChecker/main/data/hot_websites.txt)

## 配置

程序会读取同目录的 `config.yaml`。常用配置如下：

```yaml
reality_filter:
  require_no_cdn: true
  require_no_hot: true
  max_handshake_ms: 400
  min_cert_days: 10
  min_stars: 3

network:
  timeout: 3s
  retries: 1

concurrency:
  max_concurrent: 10
  check_timeout: 3s
```

命令行选项可以覆盖自动模式中的筛选策略，适合临时放宽或收紧条件。

## 致谢

- [Loyalsoldier/geoip](https://github.com/Loyalsoldier/geoip) - GeoIP 数据库
- [Loyalsoldier/clash-rules](https://github.com/Loyalsoldier/clash-rules) - GFW 规则
