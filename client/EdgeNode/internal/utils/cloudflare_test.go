package utils

import "testing"

func TestIsCloudflareIP(t *testing.T) {
	for _, ip := range []string{"162.158.0.1", "104.16.1.1", "2606:4700::1"} {
		if !IsCloudflareIP(ip) {
			t.Fatalf("expect '%s' to be a Cloudflare IP", ip)
		}
	}
	for _, ip := range []string{"1.2.3.4", "192.168.0.62", "2001:4860:4860::8888", "", "abc"} {
		if IsCloudflareIP(ip) {
			t.Fatalf("expect '%s' NOT to be a Cloudflare IP", ip)
		}
	}
}
