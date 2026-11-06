// Package dnsla 提供 DNS.la 开放 API 的响应结构。
//
// 说明：上游 TeaOSLab/EdgeAPI 的开源仓库中 internal/dnsclients/dnsla 目录缺失
// （provider_dns_la.go 依赖它），此文件为本地构建补齐的最小实现，
// 仅包含 provider_dns_la.go 实际使用的响应类型。
package dnsla

import "errors"

// baseResponse 通用响应状态
type baseResponse struct {
	Code    int    `json:"code"`
	Message string `json:"msg"`
}

// Success 是否成功
func (this *baseResponse) Success() bool {
	return this.Code == 0 || this.Code == 200
}

// Error 返回错误信息
func (this *baseResponse) Error() error {
	if len(this.Message) > 0 {
		return errors.New(this.Message)
	}
	return errors.New("unknown error")
}

// DomainListResponse 域名列表响应
type DomainListResponse struct {
	baseResponse
	Data struct {
		Results []struct {
			Id     string `json:"id"`
			Domain string `json:"domain"`
		} `json:"results"`
	} `json:"data"`
}

// DomainResponse 单个域名响应
type DomainResponse struct {
	baseResponse
	Data struct {
		Id     string `json:"id"`
		Domain string `json:"domain"`
	} `json:"data"`
}

// RecordListResponse 解析记录列表响应
type RecordListResponse struct {
	baseResponse
	Data struct {
		Results []struct {
			Id       string `json:"id"`
			Host     string `json:"host"`
			Type     int    `json:"type"`
			Data     string `json:"data"`
			LineId   string `json:"lineId"`
			LineCode string `json:"lineCode"`
			TTL      int32  `json:"ttl"`
		} `json:"results"`
	} `json:"data"`
}

// RecordCreateResponse 创建解析记录响应
type RecordCreateResponse struct {
	baseResponse
	Data struct {
		Id string `json:"id"`
	} `json:"data"`
}

// RecordUpdateResponse 修改解析记录响应
type RecordUpdateResponse struct {
	baseResponse
}

// RecordDeleteResponse 删除解析记录响应
type RecordDeleteResponse struct {
	baseResponse
}

// AllLineListResponse 所有线路响应
type AllLineListResponse struct {
	baseResponse
	Data []AllLineListResponseChild `json:"data"`
}

// AllLineListResponseChild 线路
type AllLineListResponseChild struct {
	Id       string                     `json:"id"`
	Code     string                     `json:"code"`
	Name     string                     `json:"name"`
	Children []AllLineListResponseChild `json:"children"`
}
