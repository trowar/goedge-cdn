package checkpoints

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/TeaOSLab/EdgeNode/internal/waf/requests"
	"github.com/iwind/TeaGo/maps"
)

func newAnalysisRequest(t *testing.T, method string, rawURL string, headers http.Header, body string) requests.Request {
	t.Helper()

	var reader io.Reader
	if len(body) > 0 {
		reader = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, rawURL, reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, values := range headers {
		req.Header[name] = values
	}
	return requests.NewTestRequest(req)
}

func TestRequestInjectionAnalysisCheckpoint(t *testing.T) {
	var checkpoint = new(RequestInjectionAnalysisCheckpoint)

	var cases = []struct {
		url      string
		body     string
		expected string
	}{
		{"/search?q=1%27+or+%271%27%3D%271", "", "sqli"},
		{"/search?q=hello&page=2", "", ""},
		{"/search", `{"username":{"$ne":null}}`, "nosql"},
		{"/ping?host=127.0.0.1;+cat+/etc/passwd", "", "cmdi"},
	}

	for _, c := range cases {
		var req = newAnalysisRequest(t, "POST", "http://example.com"+c.url, http.Header{
			"User-Agent": []string{"Mozilla/5.0 (Windows NT 10.0) Chrome/126.0"},
		}, c.body)
		value, _, _, _ := checkpoint.RequestValue(req, "", maps.Map{}, 0)
		var valueString, _ = value.(string)
		if c.expected == "" {
			if len(valueString) > 0 {
				t.Fatalf("expect no injection for '%s', got '%s'", c.url, valueString)
			}
			continue
		}
		if !strings.Contains(valueString, c.expected) {
			t.Fatalf("expect '%s' for '%s', got '%s'", c.expected, c.url, valueString)
		}
	}
}

func TestRequestBotFingerprintCheckpoint(t *testing.T) {
	var checkpoint = new(RequestBotFingerprintCheckpoint)

	var cases = map[string]string{
		"sqlmap/1.7.2#stable (https://sqlmap.org)": "scanner",
		"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)": "search-engine",
		"GPTBot/1.0 (+https://openai.com/gptbot)": "ai-crawler",
		"curl/8.5.0": "http-library",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36": "",
		"": "empty",
	}

	for ua, expected := range cases {
		var req = newAnalysisRequest(t, "GET", "http://example.com/", http.Header{
			"User-Agent": []string{ua},
		}, "")
		value, _, _, _ := checkpoint.RequestValue(req, "", maps.Map{}, 0)
		if value != expected {
			t.Fatalf("expect '%s' for UA '%s', got '%v'", expected, ua, value)
		}
	}
}

func TestRequestHoneypotCheckpoint(t *testing.T) {
	var checkpoint = new(RequestHoneypotCheckpoint)

	var cases = []struct {
		url      string
		headers  http.Header
		expected any
	}{
		{"http://example.com/.env", nil, "path"},
		{"http://example.com/wp-login.php", nil, "path"},
		{"http://example.com/login?__hp_email=test", nil, "param"},
		{"http://example.com/login", http.Header{"X-Honeypot": []string{"1"}}, "header"},
		{"http://example.com/products?page=2", nil, ""},
	}

	for _, c := range cases {
		var headers = http.Header{"User-Agent": []string{"Mozilla/5.0 Chrome/126"}}
		for k, v := range c.headers {
			headers[k] = v
		}
		var req = newAnalysisRequest(t, "GET", c.url, headers, "")
		value, _, _, _ := checkpoint.RequestValue(req, "", maps.Map{}, 0)
		if value != c.expected {
			t.Fatalf("expect '%v' for '%s', got '%v'", c.expected, c.url, value)
		}
	}
}
