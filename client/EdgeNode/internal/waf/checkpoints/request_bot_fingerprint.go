// Copyright 2024 GoEdge CDN goedge.cdn@gmail.com. All rights reserved.

package checkpoints

import (
	nodeutils "github.com/TeaOSLab/EdgeNode/internal/utils"
	"github.com/TeaOSLab/EdgeNode/internal/waf/requests"
	"github.com/TeaOSLab/EdgeNode/internal/waf/utils"
	"github.com/iwind/TeaGo/maps"
)

// RequestBotFingerprintCheckpoint ${requestBotFingerprint}
// 根据 User-Agent 识别自动化程序，返回以下分类之一：
//
//	search-engine  搜索引擎
//	seo-tool       SEO 工具
//	ai-crawler     AI 训练/抓取
//	monitor        站点监控
//	scanner        漏洞扫描器
//	headless       无头浏览器
//	http-library   HTTP 客户端库（脚本）
//	empty          User-Agent 为空
//
// 普通浏览器返回空字符串。可通过 /etc/edge-cdn/bot-uas.txt 追加自定义特征（分类,关键字）。
type RequestBotFingerprintCheckpoint struct {
	Checkpoint
}

func (this *RequestBotFingerprintCheckpoint) RequestValue(req requests.Request, param string, options maps.Map, ruleId int64) (value any, hasRequestBody bool, sysErr error, userErr error) {
	var category = nodeutils.DetectBotCategory(req.WAFRaw().UserAgent())

	// 可选：只识别指定的分类，多个分类用逗号分隔，例如 scanner,headless
	var only = options.GetString("only")
	if len(only) > 0 && len(category) > 0 {
		var matched = false
		for _, item := range splitOption(only) {
			if item == category || item == "*" {
				matched = true
				break
			}
		}
		if !matched {
			category = ""
		}
	}

	return category, false, nil, nil
}

func (this *RequestBotFingerprintCheckpoint) ResponseValue(req requests.Request, resp *requests.Response, param string, options maps.Map, ruleId int64) (value any, hasRequestBody bool, sysErr error, userErr error) {
	if this.IsRequest() {
		return this.RequestValue(req, param, options, ruleId)
	}
	return
}

func (this *RequestBotFingerprintCheckpoint) CacheLife() utils.CacheLife {
	return utils.CacheShortLife
}

func splitOption(option string) []string {
	var result = []string{}
	var items = []rune(option)
	var item = make([]rune, 0, 32)
	for _, r := range items {
		if r == ',' || r == ' ' || r == '|' {
			if len(item) > 0 {
				result = append(result, string(item))
				item = item[:0]
			}
			continue
		}
		item = append(item, r)
	}
	if len(item) > 0 {
		result = append(result, string(item))
	}
	return result
}
