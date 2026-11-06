// Copyright 2024 GoEdge CDN goedge.cdn@gmail.com. All rights reserved.

package injectionutils

import (
	"net"
	"net/url"
	"regexp"
	"strings"
)

// 攻击类型常量（与 SafeLine 的语义分析分类对齐）
const (
	InjectionSQL         = "sqli"
	InjectionXSS         = "xss"
	InjectionCommand     = "cmdi"
	InjectionPathTravers = "path-traversal"
	InjectionSSRF        = "ssrf"
	InjectionCRLF        = "crlf"
	InjectionLDAP        = "ldap"
	InjectionXPath       = "xpath"
	InjectionXXE         = "xxe"
	InjectionDeserialize = "deserialization"
	InjectionSSTI        = "ssti"
	InjectionNoSQL       = "nosql"
	InjectionExpression  = "expression"
)

// maxAnalyzeSize 单次检测的最大字节数，超出部分截断，防止超长 payload 拖慢检测
const maxAnalyzeSize = 8192

var (
	// 命令注入：危险分隔符 + 命令关键字（分两步判断，先看分隔符再看命令，减少误报）
	commandSeparators = []string{";", "|", "&&", "||", "$(", "`", "\n", "%0a", "0x0a"}
	commandKeywords   = []string{
		"cat ", "cat/", "ls ", "whoami", "ifconfig", "ipconfig", "netstat",
		"ping ", "curl ", "wget ", "nc ", "ncat ", "telnet ", "bash", "sh -c", "/bin/sh",
		"/bin/bash", "echo ", "rm ", "chmod ", "chown ", "kill ", "sleep ", "python -c",
		"perl -e", "php -r", "powershell", "cmd.exe", "certutil", "/etc/passwd", "/etc/shadow",
	}

	// 路径穿越 / 本地文件包含
	pathTraversalRegexp = regexp.MustCompile(`(?i)(\.\.[/\\]|%2e%2e[%2f\\]|\.\.%2f|\.\.%5c|%252e%252e|\.\.;|\.\.%00)`)
	pathTraversalFiles  = []string{"/etc/passwd", "/etc/shadow", "/etc/hosts", "win.ini", "boot.ini", "web-inf/web.xml", "c:\\windows"}

	// CRLF / 响应拆分 / 头注入
	crlfRegexp = regexp.MustCompile(`(?i)(%0d%0a|%0a|%0d|\r\n)[ \t]*(set-cookie|location|content-length|content-type)\s*:`)

	// LDAP 注入
	ldapRegexp = regexp.MustCompile(`(?i)(\(\s*[a-z0-9_.-]+\s*=\s*\*|\)\s*\(\s*\||\*\)\s*\(\s*[a-z0-9_.-]+\s*=)`)

	// XPath 注入
	xpathRegexp = regexp.MustCompile(`(?i)(\]\s*\|\s*//|\'\s*or\s*\'\d*\'\s*=\s*\'\d*|"\s*or\s*"\d*"\s*=\s*"\d*|count\s*\(\s*//|//\*|\]\[\s*\d*\s*or\s*)`)

	// XXE
	xxeRegexp = regexp.MustCompile(`(?i)(<!entity\s|<!doctype\s+\w+\s+\[\s*<!entity|system\s*["'](file|http|ftp|php|expect|gopher|dict)://)`)
	xxeKeywords = []string{"javax.xml", "org.xml.sax", "unmarshaller", "xmlreader", "xslt", "transformerfactory", "documentbuilder"}

	// 反序列化
	deserializeKeywords = []string{
		"ro0ab",   // Java 序列化 Base64 前缀
		"aced0005", // Java 序列化 Hex 前缀
		"ysoserial", "commonscollections", "invokertransformer",
		"__reduce__", "__setstate__", "c__builtin__", // Python pickle
		"objectstateformatter", "__viewstate", // .NET
		"fastjson", "@type", "autotype", // fastjson
		"processbuilder", "getruntime().exec", "runtime.getruntime", "jndi:ldap", "jndi:rmi", "jndi:dns", "rmi://",
	}

	// XSS 补充语义（libinjection 在非严格模式下会漏掉 javascript: 伪协议等）
	xssRegexp = regexp.MustCompile(`(?i)(javascript\s*:\s*(alert|eval|prompt|confirm|document|window|location|top\.|parent\.|self\.|fetch|xmlhttprequest|string\.fromcharcode|settimeout)|vbscript\s*:|data\s*:\s*text/html|on(error|load|click|mouseover|mousemove|focus|blur|submit|change)\s*=|\bexpression\s*\(|\bdocument\.(cookie|domain)|\bdocument\.write\s*\(|<\s*(script|iframe|svg|math|img|body|object|embed|link|style)\b)`)

	// 模板注入 / 表达式注入（SSTI、SpEL、OGNL、EL）
	sstiRegexp = regexp.MustCompile(`(\{\{.*?(7\*7|7\*\*7|config|self|__class__|__globals__|__init__).*?\}\}|\$\{.*?(7\*7|runtime|classloader|scriptengine|processbuilder|getclass|forname).*\}|\{%.*?(if|for|exec|system).*%\}|<%.*?(runtime|execute|system).*%>|#\{.*?(runtime|processbuilder|getclass|7\*7).*\}|__class__|__globals__|__subclasses__|__mro__)`)
	expressionRegexp = regexp.MustCompile(`(?i)(\b(ognl|spel)\b|\bT\(java\.lang\.|#context|getclass\(\)\.|forname\(\s*["']|scriptenginemanager|expression\$\{|springframework)`)

	// NoSQL 注入
	nosqlRegexp = regexp.MustCompile(`(?i)(\$(ne|gt|gte|lt|lte|in|nin|where|regex|or|and|exists|type|mod|all|size)\b|\{\s*"?\$(ne|gt|where|regex))`)
)

// AnalyzeResult 检测结果
type AnalyzeResult struct {
	// Types 命中的攻击类型
	Types []string
}

// HasInjection 是否命中任意一种注入
func (this *AnalyzeResult) HasInjection() bool {
	return len(this.Types) > 0
}

func (this *AnalyzeResult) String() string {
	return strings.Join(this.Types, ",")
}

// AnalyzeInjection 对单个字符串做多类型语义分析
// 返回命中的攻击类型列表，未命中返回已初始化（Types 为空）的结果
func AnalyzeInjection(input string) *AnalyzeResult {
	var result = &AnalyzeResult{}
	if len(input) == 0 {
		return result
	}

	if len(input) > maxAnalyzeSize {
		input = input[:maxAnalyzeSize]
	}

	var lower = strings.ToLower(input)

	// 语义分析（libinjection）
	if DetectSQLInjection(input, false) {
		result.add(InjectionSQL)
	}
	if DetectXSS(input, false) || xssRegexp.MatchString(input) {
		result.add(InjectionXSS)
	}

	// 命令注入
	if hasAny(lower, commandSeparators) && hasAny(lower, commandKeywords) {
		result.add(InjectionCommand)
	}

	// 路径穿越
	if pathTraversalRegexp.MatchString(input) || (hasAny(lower, []string{"..", "%2e"}) && hasAny(lower, pathTraversalFiles)) {
		result.add(InjectionPathTravers)
	}

	// SSRF
	if detectSSRF(input) {
		result.add(InjectionSSRF)
	}

	// CRLF
	if crlfRegexp.MatchString(input) {
		result.add(InjectionCRLF)
	}

	// LDAP / XPath
	if ldapRegexp.MatchString(input) {
		result.add(InjectionLDAP)
	}
	if xpathRegexp.MatchString(input) {
		result.add(InjectionXPath)
	}

	// XXE
	if xxeRegexp.MatchString(input) || (strings.Contains(lower, "<!entity") && hasAny(lower, xxeKeywords)) {
		result.add(InjectionXXE)
	}

	// 反序列化 / JNDI / 命令执行类 gadget
	if hasAny(lower, deserializeKeywords) {
		result.add(InjectionDeserialize)
	}

	// 模板注入 / 表达式注入
	if sstiRegexp.MatchString(input) {
		result.add(InjectionSSTI)
	} else if expressionRegexp.MatchString(input) {
		result.add(InjectionExpression)
	}

	// NoSQL
	if nosqlRegexp.MatchString(input) {
		result.add(InjectionNoSQL)
	}

	return result
}

func (this *AnalyzeResult) add(t string) {
	for _, item := range this.Types {
		if item == t {
			return
		}
	}
	this.Types = append(this.Types, t)
}

func hasAny(input string, keywords []string) bool {
	for _, keyword := range keywords {
		if strings.Contains(input, keyword) {
			return true
		}
	}
	return false
}

// detectSSRF 检测 SSRF：协议走私 + 内网/元数据地址
func detectSSRF(input string) bool {
	var lower = strings.ToLower(input)

	// 危险协议
	for _, scheme := range []string{"file://", "gopher://", "dict://", "ldap://", "tftp://", "jar://", "netdoc://", "expect://"} {
		if strings.Contains(lower, scheme) {
			return true
		}
	}

	// 云元数据地址
	for _, host := range []string{"169.254.169.254", "metadata.google.internal", "100.100.100.200", "metadata.tencentyun.com"} {
		if strings.Contains(lower, host) {
			return true
		}
	}

	// URL 中的内网地址（仅当整体看起来像 URL 时才做解析，避免误报普通文本）
	if strings.Contains(lower, "://") {
		var index = strings.Index(lower, "://")
		var rest = lower[index+3:]
		if end := strings.IndexAny(rest, "/?# "); end >= 0 {
			rest = rest[:end]
		}
		if at := strings.LastIndex(rest, "@"); at >= 0 {
			rest = rest[at+1:]
		}
		if host, _, err := net.SplitHostPort(rest); err == nil {
			rest = host
		}
		var ip = net.ParseIP(strings.Trim(rest, "[]"))
		if ip != nil && (ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified()) {
			return true
		}
		if rest == "localhost" {
			return true
		}
	}

	return false
}

// AnalyzeArgs 批量分析 URL 参数值，返回合并后的结果
func AnalyzeArgs(rawURL string) *AnalyzeResult {
	var result = &AnalyzeResult{}
	if len(rawURL) == 0 {
		return result
	}

	var argsIndex = strings.Index(rawURL, "?")
	if argsIndex < 0 || argsIndex == len(rawURL)-1 {
		return result
	}

	var args = rawURL[argsIndex+1:]
	var values = strings.Split(args, "&")
	for _, value := range values {
		var equalIndex = strings.Index(value, "=")
		if equalIndex < 0 || equalIndex == len(value)-1 {
			continue
		}
		var valueStr = value[equalIndex+1:]
		var unescaped, err = url.QueryUnescape(valueStr)
		if err == nil {
			valueStr = unescaped
		}
		var one = AnalyzeInjection(valueStr)
		for _, t := range one.Types {
			result.add(t)
		}
	}
	return result
}
