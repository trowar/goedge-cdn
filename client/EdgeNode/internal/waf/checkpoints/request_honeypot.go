// Copyright 2024 GoEdge CDN goedge.cdn@gmail.com. All rights reserved.

package checkpoints

import (
	"strings"

	nodeutils "github.com/TeaOSLab/EdgeNode/internal/utils"
	"github.com/TeaOSLab/EdgeNode/internal/waf/requests"
	"github.com/TeaOSLab/EdgeNode/internal/waf/utils"
	"github.com/iwind/TeaGo/maps"
)

// RequestHoneypotCheckpoint ${requestHoneypot}
// 蜜罐检测：正常用户不会访问的后台/配置路径、隐藏表单字段、隐藏请求头，
// 命中后返回 path / param / header，未命中返回空字符串。
// 命中代表请求来自扫描器或自动化脚本，可直接拦截并封禁来源 IP。
// 路径与参数特征可通过 /etc/edge-cdn/honeypot-paths.txt 追加（path:xxx / param:xxx）。
type RequestHoneypotCheckpoint struct {
	Checkpoint
}

func (this *RequestHoneypotCheckpoint) RequestValue(req requests.Request, param string, options maps.Map, ruleId int64) (value any, hasRequestBody bool, sysErr error, userErr error) {
	var rawReq = req.WAFRaw()

	// 1. 路径
	if nodeutils.IsHoneypotPath(rawReq.URL.Path) {
		return "path", false, nil, nil
	}

	// 2. 查询参数名
	for name := range rawReq.URL.Query() {
		if nodeutils.IsHoneypotParam(name) {
			return "param", false, nil, nil
		}
	}

	// 3. 表单参数名
	var scanForm = !options.Has("scanForm") || options.GetBool("scanForm")
	if scanForm && rawReq.Body != nil && rawReq.ContentLength > 0 &&
		strings.Contains(strings.ToLower(rawReq.Header.Get("Content-Type")), "application/x-www-form-urlencoded") {
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
		for _, pair := range strings.Split(string(bodyData), "&") {
			var index = strings.Index(pair, "=")
			if index <= 0 {
				continue
			}
			if nodeutils.IsHoneypotParam(pair[:index]) {
				return "param", hasRequestBody, nil, nil
			}
		}
	}

	// 4. 隐藏请求头
	for name := range rawReq.Header {
		var lowerName = strings.ToLower(name)
		if strings.HasPrefix(lowerName, "x-honeypot") || strings.HasPrefix(lowerName, "x-bot-field") {
			return "header", hasRequestBody, nil, nil
		}
	}

	return "", hasRequestBody, nil, nil
}

func (this *RequestHoneypotCheckpoint) ResponseValue(req requests.Request, resp *requests.Response, param string, options maps.Map, ruleId int64) (value any, hasRequestBody bool, sysErr error, userErr error) {
	if this.IsRequest() {
		return this.RequestValue(req, param, options, ruleId)
	}
	return
}

func (this *RequestHoneypotCheckpoint) CacheLife() utils.CacheLife {
	return utils.CacheDisabled
}
