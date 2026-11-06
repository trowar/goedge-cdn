// Copyright 2024 GoEdge CDN goedge.cdn@gmail.com. All rights reserved.

package checkpoints

import (
	"strings"

	"github.com/TeaOSLab/EdgeNode/internal/waf/injectionutils"
	"github.com/TeaOSLab/EdgeNode/internal/waf/requests"
	"github.com/TeaOSLab/EdgeNode/internal/waf/utils"
	"github.com/iwind/TeaGo/maps"
)

// RequestInjectionAnalysisCheckpoint ${requestInjectionAnalysis}
// 对请求做多类型语义分析（SQL 注入、XSS、命令注入、路径穿越、SSRF、CRLF、LDAP、XPath、
// XXE、反序列化、模板注入、NoSQL 注入），命中时返回逗号分隔的攻击类型，未命中返回空字符串。
// 规则中建议使用“正则匹配”运算符并填写 .+ 表示命中任意攻击类型，
// 也可以填写具体的类型，例如 sqli、cmdi 只匹配某几类。
type RequestInjectionAnalysisCheckpoint struct {
	Checkpoint
}

func (this *RequestInjectionAnalysisCheckpoint) RequestValue(req requests.Request, param string, options maps.Map, ruleId int64) (value any, hasRequestBody bool, sysErr error, userErr error) {
	var targets = []string{
		req.WAFRaw().URL.RequestURI(),
		req.WAFRaw().UserAgent(),
		req.WAFRaw().Referer(),
	}

	// 可选：检测指定 Header（options.scanHeaders=true 时检测全部 Header 值）
	var scanHeaders = options.GetBool("scanHeaders")
	if scanHeaders {
		for name, values := range req.WAFRaw().Header {
			var lowerName = strings.ToLower(name)
			// 这些 Header 由传输层生成，扫描意义不大且容易误报
			if lowerName == "accept-encoding" || lowerName == "connection" || lowerName == "content-length" {
				continue
			}
			targets = append(targets, values...)
		}
	}

	// 可选：检测请求体（默认开启，可通过 scanBody=false 关闭）
	var scanBody = !options.Has("scanBody") || options.GetBool("scanBody")
	if scanBody && req.WAFRaw().Body != nil && req.WAFRaw().ContentLength != 0 && !this.RequestBodyIsEmpty(req) {
		hasRequestBody = true
		var bodyData = req.WAFGetCacheBody()
		if len(bodyData) == 0 {
			data, err := req.WAFReadBody(req.WAFMaxRequestSize())
			if err != nil {
				return "", hasRequestBody, err, nil
			}
			bodyData = data
			req.WAFSetCacheBody(data)
			req.WAFRestoreBody(data)
		}
		targets = append(targets, string(bodyData))
	}

	var result *injectionutils.AnalyzeResult
	for _, target := range targets {
		if len(target) == 0 {
			continue
		}
		var one = injectionutils.AnalyzeInjection(target)
		if !one.HasInjection() {
			continue
		}
		if result == nil {
			result = one
			continue
		}
		// 合并结果
		for _, t := range one.Types {
			result.Types = append(result.Types, t)
		}
	}

	if result == nil {
		return "", hasRequestBody, nil, nil
	}
	return result.String(), hasRequestBody, nil, nil
}

func (this *RequestInjectionAnalysisCheckpoint) ResponseValue(req requests.Request, resp *requests.Response, param string, options maps.Map, ruleId int64) (value any, hasRequestBody bool, sysErr error, userErr error) {
	if this.IsRequest() {
		return this.RequestValue(req, param, options, ruleId)
	}
	return
}

func (this *RequestInjectionAnalysisCheckpoint) CacheLife() utils.CacheLife {
	return utils.CacheDisabled
}
