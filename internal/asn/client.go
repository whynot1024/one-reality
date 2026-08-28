package asn

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

const defaultBaseURL = "https://stat.ripe.net/data"

// Client retrieves ASN announcements from RIPEstat.
type Client struct {
	httpClient *http.Client
	baseURL    string
}

type prefixOverviewResponse struct {
	Data struct {
		ASNs []struct {
			ASN int `json:"asn"`
		} `json:"asns"`
	} `json:"data"`
}

type announcedPrefixesResponse struct {
	Data struct {
		Prefixes []struct {
			Prefix string `json:"prefix"`
		} `json:"prefixes"`
	} `json:"data"`
}

func NewClient(timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &Client{
		httpClient: &http.Client{Timeout: timeout},
		baseURL:    defaultBaseURL,
	}
}

// PrefixesForIP returns announced prefixes for the ASN originating the IP.
func (c *Client) PrefixesForIP(ctx context.Context, ip string) (int, []string, error) {
	parsed, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return 0, nil, fmt.Errorf("解析入口 IP 失败: %w", err)
	}

	var overview prefixOverviewResponse
	if err := c.getJSON(ctx, "/prefix-overview/data.json?resource="+parsed.String(), &overview); err != nil {
		return 0, nil, fmt.Errorf("查询 IP ASN 失败: %w", err)
	}
	if len(overview.Data.ASNs) == 0 || overview.Data.ASNs[0].ASN <= 0 {
		return 0, nil, fmt.Errorf("RIPEstat 未返回 %s 的 ASN", parsed)
	}

	asnNumber := overview.Data.ASNs[0].ASN
	var announced announcedPrefixesResponse
	if err := c.getJSON(ctx, fmt.Sprintf("/announced-prefixes/data.json?resource=AS%d", asnNumber), &announced); err != nil {
		return 0, nil, fmt.Errorf("查询 AS%d 宣布网段失败: %w", asnNumber, err)
	}

	prefixes := make([]string, 0, len(announced.Data.Prefixes))
	seen := make(map[string]struct{})
	for _, item := range announced.Data.Prefixes {
		prefix, err := netip.ParsePrefix(item.Prefix)
		if err != nil {
			continue
		}
		normalized := prefix.Masked().String()
		if _, ok := seen[normalized]; !ok {
			seen[normalized] = struct{}{}
			prefixes = append(prefixes, normalized)
		}
	}
	if len(prefixes) == 0 {
		return asnNumber, nil, fmt.Errorf("AS%d 没有可用的宣布网段", asnNumber)
	}
	return asnNumber, prefixes, nil
}

func (c *Client) getJSON(ctx context.Context, path string, result any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "RealityChecker/1.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP 状态码 %d", resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(result); err != nil {
		return fmt.Errorf("解析 RIPEstat 响应失败: %w", err)
	}
	return nil
}
