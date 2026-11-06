package nodes

import (
	"context"
	"net/http"
	"testing"

	"github.com/TeaOSLab/EdgeCommon/pkg/serverconfigs"
)

func newForwardedTestRequest(rawAddr string, header http.Header, remoteAddrConfig *serverconfigs.HTTPRemoteAddrConfig) *HTTPRequest {
	rawReq, err := http.NewRequest(http.MethodGet, "/", nil)
	if err != nil {
		panic(err)
	}
	rawReq.RemoteAddr = rawAddr
	for k, v := range header {
		rawReq.Header[k] = v
	}
	var req = &HTTPRequest{RawReq: rawReq}
	if remoteAddrConfig != nil {
		req.web = &serverconfigs.HTTPWebConfig{RemoteAddr: remoteAddrConfig}
	}
	return req
}

func newTestReverseProxy(t *testing.T) *serverconfigs.ReverseProxyConfig {
	var rp = &serverconfigs.ReverseProxyConfig{}
	if err := rp.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	return rp
}

func newDefaultRemoteAddrConfig(t *testing.T) *serverconfigs.HTTPRemoteAddrConfig {
	var cfg = &serverconfigs.HTTPRemoteAddrConfig{
		IsOn:  true,
		Value: "${rawRemoteAddr}",
		Type:  serverconfigs.HTTPRemoteAddrTypeDefault,
	}
	if err := cfg.Init(); err != nil {
		t.Fatal(err)
	}
	return cfg
}

// 默认（直连）模式下不应信任请求头中的客户端地址
func TestHTTPRequest_RequestRemoteAddr_Default(t *testing.T) {
	var header = http.Header{
		"X-Forwarded-For": []string{"1.2.3.4, 5.6.7.8"},
		"X-Real-Ip":       []string{"1.2.3.4"},
	}

	// 默认配置
	var req = newForwardedTestRequest("203.0.113.7:1234", header, newDefaultRemoteAddrConfig(t))
	if got := req.requestRemoteAddr(true); got != "203.0.113.7" {
		t.Fatalf("expect '203.0.113.7', got '%s'", got)
	}

	// 未配置客户端IP获取方式
	var req2 = newForwardedTestRequest("203.0.113.7:1234", header, nil)
	if got := req2.requestRemoteAddr(true); got != "203.0.113.7" {
		t.Fatalf("expect '203.0.113.7', got '%s'", got)
	}
}

// 代理模式下应信任 X-Forwarded-For
func TestHTTPRequest_RequestRemoteAddr_Proxy(t *testing.T) {
	var cfg = &serverconfigs.HTTPRemoteAddrConfig{
		IsOn:  true,
		Value: "${remoteAddr}",
		Type:  serverconfigs.HTTPRemoteAddrTypeProxy,
	}
	if err := cfg.Init(); err != nil {
		t.Fatal(err)
	}
	var req = newForwardedTestRequest("203.0.113.7:1234", http.Header{
		"X-Forwarded-For": []string{"1.2.3.4, 5.6.7.8"},
	}, cfg)
	// 前置代理以追加方式写入 X-Forwarded-For，最右侧的地址才是代理看到的客户端地址
	if got := req.requestRemoteAddr(true); got != "5.6.7.8" {
		t.Fatalf("expect '5.6.7.8', got '%s'", got)
	}
}

// 回源时应丢弃客户端伪造的来源 IP 头
func TestHTTPRequest_SetForwardHeaders_RemoveForged(t *testing.T) {
	var req = newForwardedTestRequest("203.0.113.7:1234", http.Header{
		"X-Forwarded-For": []string{"1.2.3.4"},
		"X-Real-Ip":       []string{"1.2.3.4"},
		"Forwarded":       []string{"for=1.2.3.4"},
	}, newDefaultRemoteAddrConfig(t))

	req.setForwardHeaders(req.RawReq.Header)

	for _, name := range []string{"X-Forwarded-For", "X-Real-Ip", "Forwarded"} {
		if v, ok := req.RawReq.Header[name]; ok {
			t.Fatalf("header '%s' should be removed, got '%v'", name, v)
		}
	}
}

// 可信代理模式下应保留 X-Forwarded-For 链
func TestHTTPRequest_SetForwardHeaders_KeepTrusted(t *testing.T) {
	var cfg = &serverconfigs.HTTPRemoteAddrConfig{
		IsOn:  true,
		Value: "${remoteAddr}",
		Type:  serverconfigs.HTTPRemoteAddrTypeProxy,
	}
	if err := cfg.Init(); err != nil {
		t.Fatal(err)
	}
	var req = newForwardedTestRequest("203.0.113.7:1234", http.Header{
		"X-Forwarded-For": []string{"1.2.3.4"},
	}, cfg)
	req.reverseProxy = newTestReverseProxy(t)

	req.setForwardHeaders(req.RawReq.Header)

	var v = req.RawReq.Header.Get("X-Forwarded-For")
	if v != "1.2.3.4, 203.0.113.7" {
		t.Fatalf("expect '1.2.3.4, 203.0.113.7', got '%s'", v)
	}
}

// Cloudflare 来源：使用 CF-Connecting-IP 作为真实客户端地址，并回写 CF 头
func TestHTTPRequest_SetForwardHeaders_Cloudflare(t *testing.T) {
	var req = newForwardedTestRequest("162.158.0.1:1234", http.Header{
		"CF-Connecting-IP": []string{"198.51.100.9"},
		"X-Forwarded-For":  []string{"1.2.3.4"},
		"X-Real-Ip":        []string{"1.2.3.4"},
	}, newDefaultRemoteAddrConfig(t))
	req.reverseProxy = newTestReverseProxy(t)

	if got := req.requestRemoteAddr(true); got != "198.51.100.9" {
		t.Fatalf("expect '198.51.100.9', got '%s'", got)
	}

	req.setForwardHeaders(req.RawReq.Header)

	if got := req.RawReq.Header.Get("X-Forwarded-For"); got != "198.51.100.9" {
		t.Fatalf("expect X-Forwarded-For '198.51.100.9', got '%s'", got)
	}
	if got := req.RawReq.Header.Get("X-Real-IP"); got != "198.51.100.9" {
		t.Fatalf("expect X-Real-IP '198.51.100.9', got '%s'", got)
	}
	if got := req.RawReq.Header.Get("CF-Connecting-IP"); got != "198.51.100.9" {
		t.Fatalf("expect CF-Connecting-IP '198.51.100.9', got '%s'", got)
	}
}

// Cloudflare 来源但缺少 CF-Connecting-IP：取 X-Forwarded-For 最右侧地址，丢弃左侧伪造部分
func TestHTTPRequest_RequestRemoteAddr_CloudflareForwardedFor(t *testing.T) {
	var req = newForwardedTestRequest("162.158.0.1:1234", http.Header{
		"X-Forwarded-For": []string{"6.6.6.6, 198.51.100.9"},
	}, newDefaultRemoteAddrConfig(t))

	if got := req.requestRemoteAddr(true); got != "198.51.100.9" {
		t.Fatalf("expect '198.51.100.9', got '%s'", got)
	}
}

// 非 Cloudflare 来源：客户端伪造的 CF 头应被丢弃
func TestHTTPRequest_SetForwardHeaders_FakeCloudflareHeader(t *testing.T) {
	var req = newForwardedTestRequest("203.0.113.7:1234", http.Header{
		"CF-Connecting-IP": []string{"198.51.100.9"},
	}, newDefaultRemoteAddrConfig(t))

	req.setForwardHeaders(req.RawReq.Header)

	if v, ok := req.RawReq.Header["Cf-Connecting-Ip"]; ok {
		t.Fatalf("CF-Connecting-IP should be removed, got '%v'", v)
	}
}
