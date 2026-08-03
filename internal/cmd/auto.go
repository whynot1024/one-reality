package cmd

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"RealityChecker/internal/scanner"
	"RealityChecker/internal/types"
	"RealityChecker/internal/ui"
)

// executeAuto 处理 CIDR/IP 列表，内存中调用内置 TLS 扫描器并根据 REALITY 策略输出彩色表格结果
func (r *RootCmd) executeAuto(cidrs []string, maxTargets int, filter types.RealityFilterConfig) {
	if len(cidrs) == 0 {
		ui.PrintError("错误：未提供有效的 CIDR 扫描网段")
		return
	}

	ui.PrintTimestampedMessage("开启内嵌自动化扫描与检测模式 (Native Engine)...")
	ui.PrintTimestampedMessage("应用 REALITY 选型策略: [非CDN=%v, 最大握手=%dms, 排除热门=%v, 最小证书天数=%d天, 最低星级=%d星]",
		filter.RequireNoCDN, filter.MaxHandshakeMS, filter.RequireNoHot, filter.MinCertDays, filter.MinStars)

	ui.PrintTimestampedMessage("待扫描网段总数: %d 个。排序如下:", len(cidrs))
	for i, c := range cidrs {
		if i < 5 {
			fmt.Printf("  [%d] %s\n", i+1, c)
		}
	}
	if len(cidrs) > 5 {
		fmt.Printf("  ...以及其余 %d 个网段\n", len(cidrs)-5)
	}

	// 1. 初始化内嵌 Go 扫描器
	scannerEngine := scanner.NewScanner()
	defer scannerEngine.Close()

	// 2. 构造流水线 Channel
	scanResultChan := make(chan *scanner.ScanResult, 100)
	domainSet := make(map[string]bool)
	var mu sync.Mutex

	var suitableResults []*types.DetectionResult
	concurrency := 10
	var workerWg sync.WaitGroup

	ctx, cancel := context.WithCancel(r.ctx)
	defer cancel()

	// 启动检测 Worker 协程池
	for i := 0; i < concurrency; i++ {
		go func() {
			for scanRes := range scanResultChan {
				func() {
					defer workerWg.Done()
					if scanRes == nil {
						return
					}

					// 检查是否已经达到上限，若达到立刻放弃
					mu.Lock()
					if maxTargets > 0 && len(suitableResults) >= maxTargets {
						mu.Unlock()
						return
					}
					mu.Unlock()

					select {
					case <-ctx.Done():
						return
					default:
					}

					d := scanRes.CertDomain
					res, err := r.engine.CheckDomain(ctx, d)

					mu.Lock()
					defer mu.Unlock()

					// 再次检查二次确认
					if maxTargets > 0 && len(suitableResults) >= maxTargets {
						return
					}

					// 检验是否完全符合 Xray REALITY 选型策略
					if isSatisfiedRealityPolicy(res, err, filter) {
						suitableResults = append(suitableResults, res)
						suitableCount := len(suitableResults)

						var handshakeMs int64 = 0
						if res.TLS != nil {
							handshakeMs = res.TLS.HandshakeTime.Milliseconds()
						}
						var statusCode int = 0
						if res.Network != nil {
							statusCode = res.Network.StatusCode
						}

						timestamp := time.Now().Format("15:04:05")
						fmt.Printf("[%s] ★ [发现优质 REALITY 目标 #%d] %-35s (IP: %s, 握手: %dms, 页面: %d)\n",
							timestamp, suitableCount, d, scanRes.IP, handshakeMs, statusCode)

						if maxTargets > 0 && suitableCount >= maxTargets {
							ui.PrintTimestampedMessage("已达到设定的目标数量限制 (%d 个)，即刻刹车并停止扫描...", maxTargets)
							cancel()
						}
					}
				}()
			}
		}()
	}

	// 3. 顺序调度 CIDR 扫描（内存直接推入通道）
	for idx, cidr := range cidrs {
		select {
		case <-ctx.Done():
			break
		default:
		}

		mu.Lock()
		sc := len(suitableResults)
		mu.Unlock()
		if maxTargets > 0 && sc >= maxTargets {
			break
		}

		ui.PrintTimestampedMessage("[%d/%d] 正在内嵌并发扫描网段: %s ...", idx+1, len(cidrs), cidr)

		// 单个 CIDR 的扫描输出中间通道
		subChan := make(chan *scanner.ScanResult, 50)

		// 异步收纳单个 CIDR 的扫描结果
		var pipeWg sync.WaitGroup
		pipeWg.Add(1)
		go func() {
			defer pipeWg.Done()
			for res := range subChan {
				if res == nil || res.CertDomain == "" || shouldExcludeDomain(res.CertDomain) {
					continue
				}

				mu.Lock()
				if maxTargets > 0 && len(suitableResults) >= maxTargets {
					mu.Unlock()
					continue
				}

				if !domainSet[res.CertDomain] {
					domainSet[res.CertDomain] = true
					workerWg.Add(1)
					select {
					case scanResultChan <- res:
					case <-ctx.Done():
						workerWg.Done()
					}
				}
				mu.Unlock()
			}
		}()

		// 执行并发 TLS 握手扫描
		scannerEngine.ScanCIDRStream(ctx, cidr, 443, 100, 5, false, subChan)
		close(subChan)
		pipeWg.Wait()
	}

	workerWg.Wait()
	close(scanResultChan)

	// 严密裁剪结果数量，保证精确等于 maxTargets
	if maxTargets > 0 && len(suitableResults) > maxTargets {
		suitableResults = suitableResults[:maxTargets]
	}

	ui.PrintTimestampedMessage("扫描与检测完成！共找到 %d 个符合策略的优质 REALITY 目标域名。", len(suitableResults))

	// 渲染经典带颜色 ASCII 表格
	if len(suitableResults) > 0 {
		r.batchManager.SortByRecommendationStars(suitableResults)
		fmt.Println("\n适合的域名:")
		fmt.Println(r.batchManager.FormatSuitableTable(suitableResults))
	}
}

// isSatisfiedRealityPolicy 检查检测结果是否符合 REALITY 最佳实践筛选策略
func isSatisfiedRealityPolicy(res *types.DetectionResult, err error, filter types.RealityFilterConfig) bool {
	if err != nil || res == nil || !res.Suitable || res.Error != nil {
		return false
	}

	// 1. 基础条件必须满足 TLS1.3 与 HTTP/2
	if res.TLS == nil || !res.TLS.SupportsTLS13 || !res.TLS.SupportsHTTP2 {
		return false
	}

	// 2. 强制非 CDN 过滤
	if filter.RequireNoCDN {
		if res.CDN != nil && res.CDN.IsCDN {
			return false
		}
	}

	// 3. 握手时间延迟上限过滤
	if filter.MaxHandshakeMS > 0 && res.TLS != nil {
		if res.TLS.HandshakeTime.Milliseconds() > filter.MaxHandshakeMS {
			return false
		}
	}

	// 4. 排除热门大站
	if filter.RequireNoHot {
		if res.CDN != nil && res.CDN.IsHotWebsite {
			return false
		}
	}

	// 5. 证书剩余有效天数下限过滤
	if filter.MinCertDays > 0 {
		if res.Certificate == nil || !res.Certificate.Valid || res.Certificate.DaysUntilExpiry < filter.MinCertDays {
			return false
		}
	}

	// 6. 最低推荐星级门槛过滤
	if filter.MinStars > 0 {
		stars := calculateStars(res)
		if stars < filter.MinStars {
			return false
		}
	}

	return true
}

func calculateStars(result *types.DetectionResult) int {
	stars := 0
	if result.TLS != nil && result.TLS.SupportsTLS13 &&
		result.TLS.SupportsX25519 && result.TLS.SupportsHTTP2 &&
		result.SNI != nil && result.SNI.SNIMatch {
		stars++
	}
	if result.TLS != nil && result.TLS.HandshakeTime > 0 {
		if result.TLS.HandshakeTime.Milliseconds() <= 200 {
			stars++
		}
	}
	if result.CDN == nil || !result.CDN.IsCDN {
		stars++
	}
	if result.CDN != nil && !result.CDN.IsHotWebsite {
		stars++
	}
	if result.Certificate != nil && result.Certificate.Valid {
		if result.Certificate.DaysUntilExpiry >= 60 {
			stars++
		}
	}
	return stars
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// resolveInputToCIDRs 原生构建 CIDR 扫描队列（无需依赖易失效的第三方 HTTP API）
func resolveInputToCIDRs(targetInput string, inFile string) []string {
	var cidrs []string

	// 从文件批量读取 CIDRs
	if inFile != "" {
		f, err := os.Open(inFile)
		if err == nil {
			defer f.Close()
			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				cidrs = appendCIDR(cidrs, line)
			}
		}
	}

	// 处理单个命令行目标输入 (支持 CIDR 或 IP)
	if targetInput != "" {
		cidrs = appendCIDR(cidrs, targetInput)
	}

	return cidrs
}

func appendCIDR(list []string, input string) []string {
	input = strings.TrimSpace(input)
	if input == "" {
		return list
	}

	// 如果输入本身是 CIDR (如 5.45.102.0/24)
	if strings.Contains(input, "/") {
		if !contains(list, input) {
			list = append(list, input)
		}
		return list
	}

	// 如果输入是单个 IP (如 5.45.102.196)，原生自动生成该 IP 的近邻 /24 和 /23 网段
	ip := net.ParseIP(input)
	if ip != nil {
		v4 := ip.To4()
		if v4 != nil {
			c24 := fmt.Sprintf("%d.%d.%d.0/24", v4[0], v4[1], v4[2])
			if !contains(list, c24) {
				list = append(list, c24)
			}
			c23 := fmt.Sprintf("%d.%d.%d.0/23", v4[0], v4[1], v4[2]&0xFE)
			if !contains(list, c23) {
				list = append(list, c23)
			}
		}
	}

	return list
}

// parseAndExecuteAuto 解析命令行参数并应用 YAML 策略与 CLI 参数覆盖
func (r *RootCmd) parseAndExecuteAuto(args []string) {
	if len(args) == 0 {
		ui.PrintErrorWithDetails(
			"错误：缺少目标 IP / CIDR 参数或 --in 文件参数",
			"用法:",
			"  reality-checker auto <ip_or_cidr> [选项]",
			"  reality-checker auto --in <cidr_file> [选项]",
			"选项:",
			"  --in FILE            从文件中批量读取 CIDR/IP 列表 (每行一个)",
			"  --limit N            指定获取合适目标的数量上限 (默认 5)",
			"  --no-cdn             强制筛选无 CDN 节点 (默认开启)",
			"  --allow-cdn          允许 CDN 节点",
			"  --max-handshake MS   设置最大握手延迟 (毫秒, 默认 800)",
			"  --no-hot             排除热门大站 (默认开启)",
			"  --allow-hot          允许热门大站",
			"  --min-cert-days DAYS 证书最低剩余天数 (默认 7 天)",
			"  --min-stars STARS    最低推荐星级 1-5 (默认 3)",
			"示例:",
			"  reality-checker auto 5.45.102.0/24 --limit 2",
			"  reality-checker auto 5.45.102.196 --limit 5 --max-handshake 500",
			"  reality-checker auto --in cidrs.txt --limit 5",
		)
		os.Exit(1)
	}

	var targetInput string
	var inFile string
	maxTargets := 5
	filter := r.batchManager.GetConfig().RealityFilter

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !strings.HasPrefix(arg, "-") && targetInput == "" {
			targetInput = arg
			continue
		}

		switch arg {
		case "--in":
			if i+1 < len(args) {
				inFile = args[i+1]
				i++
			}
		case "--limit", "-n":
			if i+1 < len(args) {
				if n, err := strconv.Atoi(args[i+1]); err == nil {
					maxTargets = n
				}
				i++
			}
		case "--no-cdn":
			filter.RequireNoCDN = true
		case "--allow-cdn":
			filter.RequireNoCDN = false
		case "--no-hot":
			filter.RequireNoHot = true
		case "--allow-hot":
			filter.RequireNoHot = false
		case "--max-handshake":
			if i+1 < len(args) {
				if ms, err := strconv.ParseInt(args[i+1], 10, 64); err == nil {
					filter.MaxHandshakeMS = ms
				}
				i++
			}
		case "--min-cert-days":
			if i+1 < len(args) {
				if days, err := strconv.Atoi(args[i+1]); err == nil {
					filter.MinCertDays = days
				}
				i++
			}
		case "--min-stars":
			if i+1 < len(args) {
				if s, err := strconv.Atoi(args[i+1]); err == nil {
					filter.MinStars = s
				}
				i++
			}
		}
	}

	cidrs := resolveInputToCIDRs(targetInput, inFile)
	r.executeAuto(cidrs, maxTargets, filter)
}
