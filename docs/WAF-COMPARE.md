# SafeLine（雷池）与 GoEdge EdgeNode WAF 能力对比与整合方案

> 版本：v1（2026-11-06）
> 对比对象：SafeLine 社区版（Docker 部署，management/webserver/yanshi/blazehttp） vs 本项目 GoEdge EdgeNode v1.4.1 魔改版
> 落地环境：192.168.0.247（EdgeNode）、192.168.0.62（EdgeAdmin + EdgeAPI）

---

## 一、总体结论

| 结论 | 说明 |
| --- | --- |
| **SafeLine 更强在“检测引擎深度 + 开箱可视化”** | 自研 C++ 语义分析引擎（yanshi，FSA 有限状态自动机）对 SQL 注入 / XSS / 命令注入等做语法级判定，误报低；自带攻击态势大屏、攻击日志检索、动态防护（JS 混淆）、应用识别 |
| **GoEdge 更强在“可编排性 + 与 CDN 全链路融合”** | 47 个检查点 × 40+ 运算符的自由规则 DSL、13 种动作、请求/响应双向检测、集群/站点/分组三级策略继承、两级 CC 防护、IP 库与地区封禁、与缓存/回源/限速天然同链路 |
| **两者定位不同** | SafeLine 是“独立反向代理形态的 WAF 产品”，GoEdge 是“CDN/反代平台内置 WAF”。用 GoEdge 承载流量时，缺的不是吞吐与编排，而是**语义级检测、Bot 分类、蜜罐**这三块能力 |
| **本轮整合结果** | 已把上述三项能力以**原生检查点**形式补进 GoEdge WAF，共新增 3 个检查点（44 → 47），双端（EdgeNode 运行时 + EdgeCommon 面板展示）同步注册，并在 192.168.0.247 完成端到端拦截验证 |

---

## 二、能力对比矩阵

图例：✅ 原生支持且较完善　🟡 支持但较弱 / 需手工配置　❌ 不支持

### 2.1 检测引擎

| 能力 | SafeLine | GoEdge（整合前） | GoEdge（整合后） |
| --- | --- | --- | --- |
| SQL 注入检测 | ✅ 语义分析（AST/FSA）+ 规则 | 🟡 libinjection 指纹，仅在 `contains sql injection` 运算符内 | ✅ `contains sql injection` + `${requestInjectionAnalysis}` 语义分析（返回 `sqli`） |
| XSS 检测 | ✅ 语义分析 | 🟡 libinjection 非严格模式 | ✅ 语义分析（返回 `xss`），含 `javascript:` 变体识别 |
| 命令注入 / RCE | ✅ | ❌ 无专用能力，只能拼关键字 | ✅ `cmdi`（分隔符 + 命令关键字判定） |
| 路径穿越 | ✅ | ❌ | ✅ `path-traversal` |
| SSRF | ✅ | ❌ | ✅ `ssrf`（危险协议 + 云元数据地址 + 内网 IP 解析） |
| XXE / 反序列化 | ✅ | ❌ | ✅ `xxe` / `deserialization` |
| SSTI / 表达式注入 | ✅ | ❌ | ✅ `ssti` / `expression` |
| NoSQL 注入 | ✅ | ❌ | ✅ `nosql` |
| CRLF / LDAP / XPath 注入 | ✅（部分） | ❌ | ✅ `crlf` / `ldap` / `xpath` |
| 检测方向 | 请求为主 | 请求 + 响应双向 | 请求 + 响应双向 |
| 检测位置 | URL / Header / Body | 每个检查点独立取值（47 个位置可选） | 新增检查点默认扫描 URI + UA + Referer + Body，可开启全 Header |

### 2.2 Bot 与客户端识别

| 能力 | SafeLine | GoEdge（整合前） | GoEdge（整合后） |
| --- | --- | --- | --- |
| 已知爬虫库 | ✅ 内置 + 在线更新 | 🟡 仅 `ignoreSearchEngine` 开关（是否对搜索引擎放行） | ✅ 8 大分类、约 80 条内置特征（含 Googlebot/Baiduspider/Bingbot/Sogou/360） |
| AI 爬虫识别 | ✅（GPTBot、ClaudeBot、Bytespider 等） | ❌ | ✅ `ai-crawler` |
| 扫描器识别 | ✅ | ❌ | ✅ `scanner`（sqlmap/nuclei/wpscan/acunetix/nmap…） |
| 无头浏览器 | ✅ | ❌ | ✅ `headless`（HeadlessChrome/Puppeteer/Playwright/Selenium） |
| SEO 工具 / 站点监控 | ✅ | ❌ | ✅ `seo-tool` / `monitor` |
| 脚本类 HTTP 库 | 🟡 | ❌ | ✅ `http-library`（curl/wget/python-requests/okhttp/axios…） |
| 空 UA | ✅ | 🟡 需自建规则比较 UA 长度 | ✅ `empty` |
| 自定义特征 | ✅ 面板维护 | ❌ | ✅ 文件驱动 `/etc/edge-cdn/bot-uas.txt`（`分类,关键字`，优先级高于内置） |

### 2.3 防护手段

| 能力 | SafeLine | GoEdge | 备注 |
| --- | --- | --- | --- |
| 蜜罐诱捕 | ✅ 隐藏字段 + 隐藏路径 | ✅（本轮新增 `${requestHoneypot}`） | GoEdge 支持路径 / 参数 / 表单字段 / 隐藏头四类，命中值 `path/param/header` |
| 人机验证 | ✅ 滑块/点选 + 动态令牌 | ✅ captcha 动作（多验证码类型）、`js_cookie` 动作 | GoEdge 无 JS 动态混淆式“动态防护” |
| 动态防护（JS 混淆注入） | ✅ 商业版核心 | ❌ | 见 P2 路线图 |
| CC 限速 | ✅ 频率限制 | ✅ 两级 CC（`cc` / `cc2` 策略 + 阈值分级） | GoEdge 可对 IP + URL 组合计数 |
| IP 黑白名单 | ✅ | ✅ 全局 / 策略 / 站点三级 + 自动封禁（block 动作带 timeout 自动加入） | |
| 地区封禁 | 🟡 国家级 | ✅ 国家 + 省份 + 自定义 IP 库 | GoEdge 更强 |
| 请求体检测 | ✅ | ✅ | 超过 `MaxRequestBodySize` 自动跳过 |
| 文件上传检测 | 🟡 | 🟡 可用 `${requestBody}` + 正则实现，无内置文件类型库 | |
| 应用/CMS 识别 | ✅ 识别框架后自动选用针对性规则 | ❌ | 见 P1 路线图 |
| 攻击结果动作 | 拦截为主 | ✅ 13 种：block / captcha / js_cookie / get_302 / post_307 / record_ip / log / page / redirect / allow / go_group / go_set / notify / tag | GoEdge 明显更灵活（支持降级/挑战/分组跳转） |
| 白名单豁免 | ✅ | ✅ `allow` 动作 + 本地 IP / 搜索引擎 / 检查点 options 三级忽略 | |

### 2.4 运维与可视化

| 能力 | SafeLine | GoEdge |
| --- | --- | --- |
| 攻击态势大屏 | ✅ | 🟡 面板有统计图表，无“攻击大屏” |
| 攻击日志检索 | ✅（按站点/规则/时间/IP） | ✅ WAF 日志 + 访问日志 + 条件检索 |
| 告警通知 | ✅ 钉钉/企微/Webhook | ✅ `notify` 动作 + 消息媒介 |
| 多站点/集群 | ✅ | ✅ 集群 + 站点 + 分组三级策略继承，配置按节点分发 |
| 规则编写方式 | 面板 + 语义规则 + 部分自定义 | 面板可视化 DSL（检查点 + 运算符 + 值 + 选项），也支持 JSON 直接导入 |
| 部署成本 | Docker Compose 三容器（pg/mgt/tengine） | 单二进制 + MySQL，可与 CDN 节点同机 |
| 与 CDN 融合 | ❌ 需串在链路里 | ✅ 同一进程内，先缓存后 WAF 的顺序可控 |

---

## 三、本轮整合实现

新增 3 个运行时检查点，全部位于 EdgeNode：

| 检查点 | 运行时文件 | 面板注册 | CacheLife |
| --- | --- | --- | --- |
| `${requestInjectionAnalysis}` | `internal/waf/checkpoints/request_injection_analysis.go` | EdgeCommon `firewallconfigs/http_firewall_checkpoints.go` | CacheDisabled |
| `${requestBotFingerprint}` | `internal/waf/checkpoints/request_bot_fingerprint.go` | 同上 | CacheShortLife |
| `${requestHoneypot}` | `internal/waf/checkpoints/request_honeypot.go` | 同上 | CacheShortLife |

配套模块：

| 模块 | 路径 | 说明 |
| --- | --- | --- |
| 多类型语义分析引擎 | `internal/waf/injectionutils/analyzer.go` | 统一入口 `AnalyzeInjection()` / `AnalyzeArgs()`，返回命中类型集合 |
| Bot 特征库 | `internal/utils/bot.go` | `DetectBotCategory()` / `IsBrowserUA()`，sync.Map 缓存（上限 5 万条） |
| 蜜罐特征库 | `internal/utils/honeypot.go` | `IsHoneypotPath()` / `IsHoneypotParam()`，文件可扩展 |
| 单元测试 | `internal/waf/injectionutils/analyzer_test.go`、`internal/waf/checkpoints/request_analysis_test.go` | 12 + 3 用例，覆盖正常文本误报回归 |

### 3.1 `${requestInjectionAnalysis}` 语义分析

- **返回值**：命中时返回逗号分隔的攻击类型（如 `sqli,xss`），未命中返回空字符串
- **类型常量**：`sqli` `xss` `cmdi` `path-traversal` `ssrf` `crlf` `ldap` `xpath` `xxe` `deserialization` `ssti` `nosql` `expression`
- **检测目标**：`RequestURI`、`User-Agent`、`Referer`，以及请求体（默认开启，受 `MaxRequestBodySize` 限制，最大分析长度 8192 字节）
- **options**：
  - `scanHeaders=true`：额外扫描全部请求头（跳过 accept-encoding / connection / content-length）
  - `scanBody=false`：关闭请求体扫描
- **推荐写法**：`运算符 = match`，`值 = .+`（命中任意类型）；或 `值 = sqli|cmdi` 只关心部分类型

### 3.2 `${requestBotFingerprint}` Bot 指纹

- **返回值**：`search-engine` `seo-tool` `ai-crawler` `monitor` `scanner` `headless` `http-library` `empty`，普通浏览器返回空
- **options**：`only=scanner,headless` 只识别指定分类（`*` 表示全部）
- **自定义**：`/etc/edge-cdn/bot-uas.txt`，每行 `分类,关键字`，自定义优先于内置；改完重启 edge-node 生效

### 3.3 `${requestHoneypot}` 蜜罐

- **返回值**：`path` / `param` / `header`，未命中返回空
- **检测顺序**：URL 路径 → Query 参数名 → 表单参数名（`scanForm`，默认开启，仅 `application/x-www-form-urlencoded`）→ `x-honeypot*` / `x-bot-field*` 隐藏头
- **内置路径**：`/wp-admin` `/wp-login.php` `/xmlrpc.php` `/phpmyadmin` `/.env` `/.git/` `/.aws/` `/actuator` `/manager/html` `/druid/` `/HNAP1/` `/cgi-bin/` `/server-status` 等
- **自定义**：`/etc/edge-cdn/honeypot-paths.txt`，每行 `path:xxx` 或 `param:xxx`
- **建议动作**：`block(timeout=3600)` + `record_ip` + `log`（蜜罐命中几乎不可能是真人）

### 3.4 注册位置（双端必须同时改）

```
client/EdgeNode/internal/waf/checkpoints/utils.go                 AllCheckpoints 44 → 47
client/EdgeCommon/pkg/serverconfigs/firewallconfigs/http_firewall_checkpoints.go  44 → 47
server/EdgeCommon/pkg/serverconfigs/firewallconfigs/http_firewall_checkpoints.go  同上（需与 client 侧保持一份）
```

---

## 四、面板 / API 配置示例

规则集 JSON（通过 `/servers/components/waf/createSetPopup` 的 `formType=code` 提交，或直接在面板“规则集 → 自定义规则”里拼）：

```json
{
  "name": "语义分析防护",
  "isOn": true,
  "connector": "or",
  "ignoreLocal": false,
  "ignoreSearchEngine": false,
  "rules": [
    {"isOn": true, "param": "${requestInjectionAnalysis}", "operator": "match", "value": ".+"}
  ],
  "actions": [
    {"code": "block", "options": {"timeout": 600}},
    {"code": "log", "options": {}}
  ]
}
```

注意：动作字段是 `{code, options}`（不是 `{type, params}`），写错会存成空动作，WAF 不生效。

本次在 192.168.0.247 环境建的 3 个规则组 / 4 个规则集：

| 规则组 | 规则集 | 规则 | 动作 |
| --- | --- | --- | --- |
| 语义分析防护(23) | 语义分析防护(35) | `${requestInjectionAnalysis} match .+` | block(600) + log |
| Bot拦截(24) | Bot拦截(36) | `${requestBotFingerprint} match ^(scanner\|headless)$`、`^empty$` | block(600) + record_ip + log |
| AI爬虫记录(37 同组 24) | AI爬虫记录(37) | `${requestBotFingerprint} match ^ai-crawler$` | log |
| 蜜罐封禁(25) | 蜜罐封禁(38) | `${requestHoneypot} match .+` | block(3600) + record_ip + log |

---

## 五、端到端验证记录（2026-11-06，节点 192.168.0.247）

| # | 请求 | 结果 | 命中 |
| --- | --- | --- | --- |
| 1 | 正常浏览器请求 `GET /` | 200 | — |
| 2 | `GET /search?q=1' or '1'='1` | 拦截（连接关闭，curl 返回 000） | 语义分析防护(35) → `sqli` |
| 3 | `GET /api/ping?host=127.0.0.1;cat /etc/passwd` | 拦截 | 语义分析防护(35) → `cmdi` |
| 4 | `GET /fetch?url=file:///etc/passwd` | 拦截 | 语义分析防护(35) → `ssrf` |
| 5 | `GET /download?file=../../etc/passwd` | 拦截 | 语义分析防护(35) → `path-traversal` |
| 6 | UA = `sqlmap/1.7.2` | 拦截 | Bot拦截(36) → `scanner` |
| 7 | 无 UA | 拦截 | Bot拦截(36) → `empty` |
| 8 | UA = `GPTBot/1.1` | 200（仅记录） | AI爬虫记录(37) |
| 9 | `GET /.env` | 403（WAF 拦截页） | 蜜罐封禁(38) → `path` |

单元测试：

```
ok  github.com/TeaOSLab/EdgeNode/internal/waf/injectionutils
ok  github.com/TeaOSLab/EdgeNode/internal/waf/checkpoints
```

### 验证时的注意事项

1. `block` 动作命中时会**直接关闭连接**，curl 表现为 `000` 而不是 403；配置了 `page` 动作才会返回自定义页面。判断是否被拦截请看 IP 名单与 WAF 日志。
2. `block.options.timeout > 0` 会把来源 IP 写入黑名单（`edgeIPItems`，reason=触发WAF规则自动加入），由节点下发到 nftables `deny*_set` 直接拒绝，**测试机自己会被封**。清理方式：

```bash
# 通过面板接口删除（推荐）
curl -s -b /tmp/ck2.txt -X POST http://192.168.0.62:7788/servers/iplists/deleteIP \
  --data-urlencode "csrfToken=$CS" --data-urlencode "itemId=<id>"
```

3. 修改 WAF 配置后，节点需要重新加载站点配置；若面板侧只是改了 `edgeHTTPWebs.firewall`，站点版本（`edgeServers.version`）可能不自动递增，最稳妥的做法是重启一次 edge-node（或从面板“保存”一次站点配置）后再验证。
4. 调试期间见过的典型假象：日志无拦截但请求 200，多半是节点还没加载到新策略；用 `curl` + `edgeHTTPLogs` / IP 名单反查比看返回码可靠。

---

## 六、与 SafeLine 语义分析的差异（重要）

| 项 | SafeLine yanshi | 本项目 injectionutils |
| --- | --- | --- |
| 实现 | C++ 有限状态自动机 + 手写文法 | libinjection（C，cgo）+ 正则特征 + 协议/关键字判定 |
| 语法级判定 | 完整（能理解 SQL 语句结构） | SQL/XSS 由 libinjection 承担，其余类型为特征匹配 |
| 误报控制 | 很低的白名单机制 | 已针对常见误报回归（`javascript:var x=1`、普通中文文本等 8 组样本），并对 `javascript:` 收紧为必须跟 alert/eval/document 等 |
| 性能 | 常数级，微秒级 | libinjection 微秒级；正则均为预编译，最大分析 8KB，超长截断 |
| 覆盖 | 更全（含编码变形） | 覆盖常见 payload；对多重 URL/Unicode 编码变形覆盖弱于 SafeLine |

**建议**：先以 `log` 动作观察 1～2 周，确认无误报后再切 `block`；对上传/富文本接口单独用 `scanBody=false` 或 `only` 收敛。

---

## 七、后续路线图

### P1（建议下一轮，成本低收益高）

1. **应用/CMS 识别**：根据响应头/Cookie/路径特征识别 WordPress、ThinkPHP、Spring、Nginx 版本，作为检查点 `${requestAppFingerprint}` 输出，用于“命中已知漏洞路径才拦”的低误报策略。
2. **攻击大屏**：基于 `edgeHTTPLogs` + WAF 命中数据做聚合（按小时/类型/IP/站点），前端复用现有统计组件。
3. **IP 情报**：接入自定义 IP 库（IDC/代理/VPN/Tor 出口），作为检查点 `${remoteAddr.isIDC}` 类输出，配合 CC 提高阈值命中率。
4. **规则包默认模板**：把 OWASP CRS 的部分规则翻译成 GoEdge 规则集，提供“一键启用”模板。

### P2（需要较大改造）

1. **动态防护**：对页面响应注入 JS 计算 challenge，校验后下发 cookie（近似 SafeLine 动态防护）；需要响应改写 + 前端脚本，工作量大。
2. **文件上传检测**：内容魔数 + 扩展名白名单 + 图片二次渲染校验。
3. **语义引擎升级**：把 libinjection 之外的注入类型改为文法解析，或引入 PCRE2/JIT 编译的自定义规则引擎。
4. **多节点策略灰度**：同一策略按节点百分比灰度下发。

---

## 八、风险与运维提示

1. **性能**：`${requestInjectionAnalysis}` 会读取请求体，对上传/大 POST 接口务必用 `scanBody=false` 或提高站点 `MaxRequestBodySize` 上限保护。
2. **误报**：语义分析对富文本、代码分享类站点的 HTML 片段敏感；建议这类站点把该规则集动作改为 `log` 或 `captcha`。
3. **缓存**：Bot / 蜜罐检查点使用短生命周期缓存（CacheShortLife），不影响 CDN 缓存命中率。
4. **配置文件**：`/etc/edge-cdn/bot-uas.txt`、`/etc/edge-cdn/honeypot-paths.txt` 需要重启节点生效，格式错误会被忽略而非报错，改完请用 curl 自测。
5. **双端一致性**：新增检查点必须同时更新 EdgeNode 运行时和 EdgeCommon 面板注册，否则面板里选不到该检查点。
