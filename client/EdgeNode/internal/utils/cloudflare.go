package utils

import (
	"net/netip"
	"os"
	"strings"
	"sync"
)

// Cloudflare 官方 IP 段（https://www.cloudflare.com/ips/）
var defaultCloudflareCIDRs = []string{
	// IPv4
	"173.245.48.0/20",
	"103.21.244.0/22",
	"103.22.200.0/22",
	"103.31.4.0/22",
	"141.101.64.0/18",
	"108.162.192.0/18",
	"190.93.240.0/20",
	"188.114.96.0/20",
	"197.234.240.0/22",
	"198.41.128.0/17",
	"162.158.0.0/15",
	"104.16.0.0/13",
	"104.24.0.0/14",
	"172.64.0.0/13",
	"131.0.72.0/22",
	// IPv6
	"2400:cb00::/32",
	"2606:4700::/32",
	"2803:f800::/32",
	"2405:b500::/32",
	"2405:8100::/32",
	"2a06:98c0::/29",
	"2c0f:f248::/32",
}

// 可通过该文件追加自定义的 Cloudflare 兼容 IP 段（每行一个 CIDR，支持 # 注释）
const CloudflareIPsFile = "/etc/edge-cdn/cloudflare-ips.txt"

var (
	cloudflareOnce     sync.Once
	cloudflarePrefixes []netip.Prefix
)

// IsCloudflareIP 判断给定的 IP 是否属于 Cloudflare 节点
func IsCloudflareIP(ip string) bool {
	cloudflareOnce.Do(loadCloudflarePrefixes)

	var addr, err = netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return false
	}
	addr = addr.Unmap()

	for _, prefix := range cloudflarePrefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func loadCloudflarePrefixes() {
	var cidrs = append([]string{}, defaultCloudflareCIDRs...)

	// 允许通过文件追加自定义 IP 段（例如自建的反向代理或售后测试环境）
	data, err := os.ReadFile(CloudflareIPsFile)
	if err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if len(line) == 0 || strings.HasPrefix(line, "#") {
				continue
			}
			cidrs = append(cidrs, line)
		}
	}

	cloudflarePrefixes = make([]netip.Prefix, 0, len(cidrs))
	for _, cidr := range cidrs {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(cidr))
		if err != nil {
			continue
		}
		cloudflarePrefixes = append(cloudflarePrefixes, prefix)
	}
}
