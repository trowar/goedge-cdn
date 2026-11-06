// Copyright 2024 GoEdge CDN goedge.cdn@gmail.com. All rights reserved.

package utils

import (
	"os"
	"strings"
	"sync"
	"sync/atomic"
)

// Bot（自动化程序）分类，与 SafeLine 的爬虫/Bot 识别对齐
const (
	BotCategoryNone        = ""
	BotCategorySearchEngine = "search-engine" // 搜索引擎
	BotCategorySEO          = "seo-tool"      // SEO 工具
	BotCategoryAI           = "ai-crawler"    // AI 训练/抓取
	BotCategoryMonitor      = "monitor"       // 站点监控
	BotCategoryScanner      = "scanner"       // 漏洞扫描器
	BotCategoryHeadless     = "headless"      // 无头浏览器
	BotCategoryHTTPLibrary  = "http-library"  // HTTP 客户端库（脚本）
	BotCategoryEmpty        = "empty"         // 空 User-Agent
)

// BotUAsFile 可在此文件中追加自定义 Bot 特征，每行格式为：分类,关键字
// 例：
//
//	scanner,custom-scanner
//	ai-crawler,my-ai-bot
const BotUAsFile = "/etc/edge-cdn/bot-uas.txt"

type botSignature struct {
	keyword  string
	category string
}

var (
	// 内置特征库，按顺序匹配，越靠前优先级越高
	defaultBotSignatures = []botSignature{
		// 漏洞扫描器（优先级最高，避免被搜索引擎关键字覆盖）
		{"sqlmap", BotCategoryScanner},
		{"nmap", BotCategoryScanner},
		{"nikto", BotCategoryScanner},
		{"nessus", BotCategoryScanner},
		{"openvas", BotCategoryScanner},
		{"masscan", BotCategoryScanner},
		{"zgrab", BotCategoryScanner},
		{"nuclei", BotCategoryScanner},
		{"wpscan", BotCategoryScanner},
		{"acunetix", BotCategoryScanner},
		{"appscan", BotCategoryScanner},
		{"netsparker", BotCategoryScanner},
		{"burpcollaborator", BotCategoryScanner},
		{"xray/", BotCategoryScanner},
		{"dirbuster", BotCategoryScanner},
		{"gobuster", BotCategoryScanner},
		{"ffuf", BotCategoryScanner},
		{"wfuzz", BotCategoryScanner},
		{"hydra", BotCategoryScanner},
		{"metasploit", BotCategoryScanner},
		{"jaeles", BotCategoryScanner},
		{"pocsuite", BotCategoryScanner},

		// 无头浏览器
		{"headlesschrome", BotCategoryHeadless},
		{"headlessfirefox", BotCategoryHeadless},
		{"puppeteer", BotCategoryHeadless},
		{"playwright", BotCategoryHeadless},
		{"phantomjs", BotCategoryHeadless},
		{"selenium", BotCategoryHeadless},
		{"webdriver", BotCategoryHeadless},

		// AI 抓取
		{"gptbot", BotCategoryAI},
		{"chatgpt-user", BotCategoryAI},
		{"claudebot", BotCategoryAI},
		{"claude-web", BotCategoryAI},
		{"anthropic-ai", BotCategoryAI},
		{"ccbot", BotCategoryAI},
		{"perplexitybot", BotCategoryAI},
		{"google-extended", BotCategoryAI},
		{"meta-externalagent", BotCategoryAI},
		{"cohere-ai", BotCategoryAI},
		{"bytespider", BotCategoryAI},
		{"amazonbot", BotCategoryAI},
		{"applebot-extended", BotCategoryAI},

		// SEO 工具
		{"ahrefsbot", BotCategorySEO},
		{"semrushbot", BotCategorySEO},
		{"mj12bot", BotCategorySEO},
		{"dotbot", BotCategorySEO},
		{"screaming frog", BotCategorySEO},
		{"serpstatbot", BotCategorySEO},

		// 搜索引擎
		{"googlebot", BotCategorySearchEngine},
		{"google-inspectiontool", BotCategorySearchEngine},
		{"adsbot-google", BotCategorySearchEngine},
		{"bingbot", BotCategorySearchEngine},
		{"msnbot", BotCategorySearchEngine},
		{"baiduspider", BotCategorySearchEngine},
		{"yandexbot", BotCategorySearchEngine},
		{"sogou web spider", BotCategorySearchEngine},
		{"sogou mobile spider", BotCategorySearchEngine},
		{"360spider", BotCategorySearchEngine},
		{"haosouspider", BotCategorySearchEngine},
		{"duckduckbot", BotCategorySearchEngine},
		{"applebot", BotCategorySearchEngine},
		{"petalbot", BotCategorySearchEngine},
		{"yisouspider", BotCategorySearchEngine},
		{"slurp", BotCategorySearchEngine},
		{"coccocbot", BotCategorySearchEngine},

		// 站点监控
		{"uptimerobot", BotCategoryMonitor},
		{"pingdom", BotCategoryMonitor},
		{"statuscake", BotCategoryMonitor},
		{"site24x7", BotCategoryMonitor},
		{"newrelic", BotCategoryMonitor},
		{"datadog", BotCategoryMonitor},
		{"zabbix", BotCategoryMonitor},
		{"nagios", BotCategoryMonitor},
		{"prometheus", BotCategoryMonitor},
		{"check_http", BotCategoryMonitor},
		{"monitoring", BotCategoryMonitor},

		// HTTP 客户端库 / 脚本
		{"curl/", BotCategoryHTTPLibrary},
		{"wget/", BotCategoryHTTPLibrary},
		{"python-requests", BotCategoryHTTPLibrary},
		{"python-urllib", BotCategoryHTTPLibrary},
		{"aiohttp", BotCategoryHTTPLibrary},
		{"httpx", BotCategoryHTTPLibrary},
		{"go-http-client", BotCategoryHTTPLibrary},
		{"okhttp", BotCategoryHTTPLibrary},
		{"axios", BotCategoryHTTPLibrary},
		{"node-fetch", BotCategoryHTTPLibrary},
		{"undici", BotCategoryHTTPLibrary},
		{"libwww-perl", BotCategoryHTTPLibrary},
		{"apache-httpclient", BotCategoryHTTPLibrary},
		{"java/", BotCategoryHTTPLibrary},
		{"postmanruntime", BotCategoryHTTPLibrary},
		{"insomnia", BotCategoryHTTPLibrary},
		{"httpie", BotCategoryHTTPLibrary},
	}

	botSignaturesOnce sync.Once
	botSignatures     []botSignature

	botCache        sync.Map
	botCacheCount   int64
	botCacheMaxSize = int64(50000)
)

// DetectBotCategory 识别 User-Agent 所属的 Bot 分类，非 Bot 返回空字符串
func DetectBotCategory(ua string) string {
	if len(ua) == 0 {
		return BotCategoryEmpty
	}

	if len(ua) > 1024 {
		ua = ua[:1024]
	}

	// 先查缓存
	if item, ok := botCache.Load(ua); ok {
		return item.(string)
	}

	var category = detectBotCategory(ua)

	// 缓存结果，避免同一 UA 反复匹配（防止内存无限增长）
	if atomic.AddInt64(&botCacheCount, 1) <= botCacheMaxSize {
		botCache.Store(ua, category)
	} else {
		botCacheCount = 0
		botCache.Range(func(key, value any) bool {
			botCache.Delete(key)
			return true
		})
	}

	return category
}

func detectBotCategory(ua string) string {
	botSignaturesOnce.Do(loadBotSignatures)

	var lowerUA = strings.ToLower(ua)
	for _, signature := range botSignatures {
		if strings.Contains(lowerUA, signature.keyword) {
			return signature.category
		}
	}
	return BotCategoryNone
}

func loadBotSignatures() {
	botSignatures = append([]botSignature{}, defaultBotSignatures...)

	// 追加自定义特征（可覆盖内置特征的分类，因为自定义特征优先匹配）
	data, err := os.ReadFile(BotUAsFile)
	if err != nil {
		return
	}

	var custom []botSignature
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if len(line) == 0 || strings.HasPrefix(line, "#") {
			continue
		}
		var parts = strings.SplitN(line, ",", 2)
		if len(parts) != 2 {
			continue
		}
		var category = strings.TrimSpace(parts[0])
		var keyword = strings.ToLower(strings.TrimSpace(parts[1]))
		if len(category) == 0 || len(keyword) == 0 {
			continue
		}
		custom = append(custom, botSignature{keyword: keyword, category: category})
	}

	if len(custom) > 0 {
		botSignatures = append(custom, botSignatures...)
	}
}

// IsBrowserUA 是否像浏览器（用于区分正常用户与脚本）
func IsBrowserUA(ua string) bool {
	var lowerUA = strings.ToLower(ua)
	return strings.Contains(lowerUA, "mozilla/") &&
		(strings.Contains(lowerUA, "chrome") || strings.Contains(lowerUA, "safari") ||
			strings.Contains(lowerUA, "firefox") || strings.Contains(lowerUA, "edg/"))
}
