package utils

import (
	"context"
	"net"
	"time"
)

// DigTraceIP 查询域名解析的 IP 列表（A + AAAA）。
// 说明：开源版 EdgeCommon 缺少该包，此处为本地构建补齐的最小实现。
func DigTraceIP(domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ips, err := net.DefaultResolver.LookupIPAddr(ctx, domain)
	if err != nil {
		return nil, err
	}
	var result = make([]string, 0, len(ips))
	for _, ip := range ips {
		result = append(result, ip.IP.String())
	}
	return result, nil
}
