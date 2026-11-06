// Copyright 2024 GoEdge CDN goedge.cdn@gmail.com. All rights reserved.

package utils

import (
	"os"
	"path"
	"strings"
	"sync"
)

// HoneypotPathsFile 蜜罐路径特征文件，每行一个路径前缀，支持 # 注释
// 命中路径即视为恶意扫描（正常用户不会访问这些地址）
const HoneypotPathsFile = "/etc/edge-cdn/honeypot-paths.txt"

// 内置蜜罐路径（扫描器/爆破工具常探测的后台、配置、管理端点）
var defaultHoneypotPaths = []string{
	"/wp-admin", "/wp-login.php", "/wp-content/", "/xmlrpc.php", "/wp-config.php",
	"/phpmyadmin", "/pma/", "/myadmin", "/adminer.php",
	"/.env", "/.git/", "/.svn/", "/.hg/", "/.DS_Store", "/.aws/", "/.ssh/",
	"/config.php.bak", "/config.json.bak", "/backup.zip", "/backup.sql", "/db.sql",
	"/actuator", "/jolokia", "/console/", "/manager/html", "/host-manager",
	"/druid/", "/solr/", "/elasticsearch", "/_cat/indices",
	"/HNAP1/", "/owa/", "/autodiscover/", "/ecp/", "/remote/login",
	"/cgi-bin/", "/shell.php", "/webshell.php", "/cmd.php", "/upload.php",
	"/vendor/phpunit", "/_ignition/execute-solution", "/api/v1/../../",
	"/server-status", "/server-info", "/.well-known/../",
}

// 蜜罐参数名（隐藏表单字段/查询参数），命中即视为自动化程序
var defaultHoneypotParams = []string{
	"__hp_email", "__hp_username", "__hp_password", "__honeypot", "_honeypot",
	"honeypot", "hp_field", "bot_field", "antispam_field", "website_url_hp",
}

var (
	honeypotOnce   sync.Once
	honeypotPaths  []string
	honeypotParams map[string]struct{}
)

func loadHoneypotConfig() {
	honeypotPaths = append([]string{}, defaultHoneypotPaths...)
	honeypotParams = map[string]struct{}{}
	for _, param := range defaultHoneypotParams {
		honeypotParams[param] = struct{}{}
	}

	data, err := os.ReadFile(HoneypotPathsFile)
	if err != nil {
		return
	}

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if len(line) == 0 || strings.HasPrefix(line, "#") {
			continue
		}
		// 支持 "path:" 和 "param:" 两种前缀
		if strings.HasPrefix(line, "param:") {
			var param = strings.TrimSpace(strings.TrimPrefix(line, "param:"))
			if len(param) > 0 {
				honeypotParams[strings.ToLower(param)] = struct{}{}
			}
			continue
		}
		line = strings.TrimPrefix(line, "path:")
		line = strings.TrimSpace(line)
		if len(line) > 0 {
			honeypotPaths = append(honeypotPaths, line)
		}
	}
}

// IsHoneypotPath 判断请求路径是否命中蜜罐
func IsHoneypotPath(requestPath string) bool {
	if len(requestPath) == 0 {
		return false
	}
	honeypotOnce.Do(loadHoneypotConfig)

	var lowerPath = strings.ToLower(path.Clean("/"+requestPath))
	for _, honeypotPath := range honeypotPaths {
		honeypotPath = strings.ToLower(honeypotPath)
		if strings.HasPrefix(lowerPath, honeypotPath) || strings.Contains(lowerPath, honeypotPath) {
			return true
		}
	}
	return false
}

// IsHoneypotParam 判断参数名是否命中蜜罐字段
func IsHoneypotParam(paramName string) bool {
	if len(paramName) == 0 {
		return false
	}
	honeypotOnce.Do(loadHoneypotConfig)
	_, ok := honeypotParams[strings.ToLower(paramName)]
	return ok
}
