# Reality Target 寻找和分析工具

一键找到符合最佳实践的SNI

基于原项目，整合Xray官方RealiTLScanner的功能，简化了操作步骤，实现 `输入ip段，返回符合条件的域名`,大大减少了心智负担和操作难度

Reality SNI目标域名的最佳实践

- 不使用CDN
- 非热门大厂
- 和入口机ip同ASN
- TLS握手延迟尽量低

## ✨ 功能特性

* **被墙检测** - 基于GFWList检测网站是否被墙
* **地理位置检测** - 检测IP地理位置，国内网站直接终止
* **TLS协议检测** - 检测TLS 1.3和X25519支持
* **证书检测** - 检测证书有效性和SNI匹配
* **CDN检测** - 智能检测CDN使用情况
* **热门网站检测** - 检测是否为热门网站
* **重定向检测** - 检测域名重定向
* **批量检测** - 支持多域名并发检测，可与RealiTLScanner配合使用
* **智能报告** - 生成详细的检测分析报告

### 推荐工作流程

1.确认vps ip 

2.手动查找和第一步的ip同ASN同国家的ip段（比如在[ipinfo](https://ipinfo.io)),

3.把找到的ip range填入一个文件(比如as7203.txt)，一行一条

4.开始检测(在客户端运行，也就是本地电脑，这样测出来的握手时间才有参考性,保证直连[不会分流请关闭代理])

```bash
./reality-checker auto --in ./as7203.txt  --limit 10
```

5.手动测试符合条件的域名，观察是否像真实上线的网站(不是demo，不是初始部署欢迎页),最好有真实的功能和业务

## 📊 检测结果说明

### 检测结果示例

原本设计为

```
输入vps的ip -> 自动查询ASN以及对应国家的同ASN ip段 -> 并发扫描所有ip -> 返回符合条件的结果
```

但是自动查询ASN下的ip段目前没找到免费的数据库方案。
所以折中的做法是

### 过滤条件

二进制同目录下 congfig.yaml

```yaml
reality_filter:
    #是否要求无cdn，默认true(推荐)
    require_no_cdn:true
    #TLS握手延迟上限，根据具体情况调整，默认800ms
    max_hadshake_ms: 800
    #最少证书有效期（如果过低可能是无人维护的死站）
    min_cert_days: 20

#并发性能
concurrency:
    max_concurrent: 10
    check_timeout: 3s
```

**实际运行效果：**

![RealityChecker检测结果示例](RealityChecker.png)

**只有满足Reality目标域名硬性条件的（TLS1.3、X25519、H2、SNI匹配、证书有效），才会在列表中显示**


### 热门网站说明

热门网站（如 apple.com、tesla.com、microsoft.com 等）由于使用人群多，容易被识别和封禁，因此不太推荐作为 Reality 协议的目标域名。

**结果分析：**
- 所有域名都支持TLS 1.3、X25519、HTTP/2和SNI匹配
- 证书有效期充足
- 部分使用了CDN且为热门网站
- 部分虽然技术指标优秀，但由于CDN和热门网站特性，推荐度有所降低


## 🚀 快速开始

### 系统要求

* **Linux VPS** - 主要针对VPS环境使用
* **Windows、macOS** - 等自行编译
* **Go 1.21+** - 用于本地编译（Windows、macOS可选）

### 安装步骤

**方法1：直接下载（推荐）**

从 [Releases](https://github.com/qualvey/RealityChecker/releases) 页面下载对应架构的zip文件：


## 🔍 使用示例

### 单域名检测

```bash
# 基础检测
./reality-checker check apple.com
```

### 批量检测

```bash
# 批量检测多个域名（空格分隔）
./reality-checker batch apple.com tesla.com microsoft.com
```

### CSV文件检测

```bash
# 从CSV文件批量检测域名
./reality-checker csv file.csv
```


### 查看帮助

```bash
# 显示使用说明
./reality-checker

# 查看版本信息
./reality-checker version
```

## 🔧常见问题

**1. 数据文件下载失败**

如果自动下载失败，请手动下载以下文件到 `data/` 目录：

- [Country.mmdb](https://github.com/Loyalsoldier/geoip/releases/latest/download/Country.mmdb)
- [gfwlist.conf](https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/gfw.txt)
- [cdn_keywords.txt](https://raw.githubusercontent.com/V2RaySSR/RealityChecker/main/data/cdn_keywords.txt)
- [hot_websites.txt](https://raw.githubusercontent.com/V2RaySSR/RealityChecker/main/data/hot_websites.txt)


## 🏆 致谢

感谢以下开源项目：

* [Loyalsoldier/geoip](https://github.com/Loyalsoldier/geoip) - GeoIP数据库
* [Loyalsoldier/clash-rules](https://github.com/Loyalsoldier/clash-rules) - GFW规则

---

**注意**: 本工具仅用于技术研究和学习目的，请遵守当地法律法规，合理使用网络资源。
