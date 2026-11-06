# GoEdge CDN 企业内网魔改版

基于 [GoEdge](https://github.com/TeaOSLab) 开源版 **v1.4.1** 的二次开发版本，面向**企业内部 CDN / 反向代理**场景做了三块深度改造：

| # | 改造 | 解决什么问题 |
| --- | --- | --- |
| 1 | **来源 IP 可信化** | 客户端可以随意伪造 `X-Forwarded-For` / `X-Real-IP`，导致源站拿到假 IP；改造后直连场景回传真实对端 IP，经 Cloudflare 回源时用 `CF-Connecting-IP` 还原用户真实 IP |
| 2 | **单用户版** | 内部使用不需要计费、多租户、平台用户、财务、工单，全部移除，只保留管理员 + 集群 + 节点 + 站点 + WAF |
| 3 | **WAF 能力整合** | 把 SafeLine（雷池）最占优的三项能力（语义分析、Bot/AI 爬虫指纹、蜜罐）以**原生检查点**形式补进 EdgeNode WAF，检查点从 44 个增加到 47 个 |

> 上游 GoEdge 使用 BSD 3-Clause 许可，本仓库同样遵循该许可。改造内容与验证过程见 [`docs/`](./docs)。

---

## 一、特性总览

### 1. 来源 IP 可信化

CDN 回源时默认**不信任**客户端自带的转发头，避免源站被假 IP 污染：

| 场景 | 行为 |
| --- | --- |
| 用户直连节点 | 取 TCP 对端地址；客户端伪造的 `X-Forwarded-For` / `X-Real-IP` / `Forwarded` / `CF-Connecting-IP` 全部丢弃并重写 |
| 经 Cloudflare 回源 | 识别来源是否属于 Cloudflare 网段（内置默认段 + `/etc/edge-cdn/cloudflare-ips.txt` 追加），命中则用 `CF-Connecting-IP` 作为真实 IP，并同时回写 `X-Forwarded-For` / `X-Real-IP` / `True-Client-IP` |
| 链路上已有多个 XFF | 统一取**最右侧**一跳（最接近本节点、最不可伪造的那个），左侧伪造值丢弃 |
| 自建多级 CDN | 把上游节点 IP 段加入可信代理列表，逐级还原 |

```bash
# 直连且伪造头 —— 源站看到的仍是真实客户端地址
curl -H 'Host: www.example.com' \
     -H 'X-Forwarded-For: 1.1.1.1' -H 'X-Real-IP: 2.2.2.2' \
     -H 'CF-Connecting-IP: 4.4.4.4' http://<node-ip>/test
```

### 2. 单用户版

移除（面板入口 + 后端 RPC 双重禁用）：

- 用户/租户体系、用户注册与登录、用户套餐与计费、财务/订单、工单系统
- 平台用户相关的菜单、路由、定时任务

保留：管理员账号、集群、节点、站点、证书、DNS、WAF、日志、统计、缓存、IP 名单等全部 CDN 能力。多管理员仍可用，适合“一个人管一批机器，给若干个业务组提供服务”的模式。

### 3. WAF 能力整合（对齐雷池 SafeLine）

新增 3 个运行时检查点（EdgeNode）+ 面板注册（EdgeCommon）：

| 检查点 | 能力 | 返回值 |
| --- | --- | --- |
| `${requestInjectionAnalysis}` | 多类型语义分析：SQL 注入 / XSS / 命令注入 / 路径穿越 / SSRF / CRLF / LDAP / XPath / XXE / 反序列化 / SSTI / NoSQL / 表达式注入 | `sqli` `xss` `cmdi` `path-traversal` `ssrf` `crlf` `ldap` `xpath` `xxe` `deserialization` `ssti` `nosql` `expression`（逗号分隔） |
| `${requestBotFingerprint}` | 客户端指纹分类，约 80 条内置特征，支持 AI 爬虫 | `search-engine` `seo-tool` `ai-crawler` `monitor` `scanner` `headless` `http-library` `empty` |
| `${requestHoneypot}` | 蜜罐诱捕：后台/配置路径、隐藏参数、隐藏表单字段、隐藏头 | `path` `param` `header` |

配套模块：

```
client/EdgeNode/internal/waf/injectionutils/analyzer.go   # 语义分析引擎（libinjection + 预编译正则 + 协议/关键字判定）
client/EdgeNode/internal/utils/bot.go                     # Bot 特征库（/etc/edge-cdn/bot-uas.txt 可扩展）
client/EdgeNode/internal/utils/honeypot.go                # 蜜罐特征库（/etc/edge-cdn/honeypot-paths.txt 可扩展）
```

规则示例（面板「WAF 策略 → 规则集 → 自定义规则」，或用 JSON 导入）：

```json
{
  "name": "语义分析防护",
  "isOn": true,
  "connector": "or",
  "rules": [
    {"isOn": true, "param": "${requestInjectionAnalysis}", "operator": "match", "value": ".+"}
  ],
  "actions": [
    {"code": "block", "options": {"timeout": 600}},
    {"code": "log", "options": {}}
  ]
}
```

> 注意：动作字段是 `{code, options}`，不是 `{type, params}`，写错会存成空动作且不报错。

实测效果（详见 [docs/WAF-COMPARE.md](./docs/WAF-COMPARE.md) 第五节）：

```
正常浏览器请求                        → 200
/search?q=1' or '1'='1               → 拦截（sqli）
?host=127.0.0.1;cat /etc/passwd      → 拦截（cmdi）
?url=file:///etc/passwd              → 拦截（ssrf）
?file=../../etc/passwd               → 拦截（path-traversal）
UA = sqlmap/1.7.2                    → 拦截（scanner）
无 UA                                 → 拦截（empty）
UA = GPTBot/1.1                      → 放行 + 记录（ai-crawler）
GET /.env                            → 403 蜜罐拦截
```

---

## 二、架构

```
                       ┌──────────────────────────────┐
   浏览器 / 客户端  ──▶ │  EdgeNode (边缘节点, :80/:443) │ ──▶ 源站
                       │  · 缓存 / 回源 / 限速 / CC     │
                       │  · WAF（47 检查点 + 13 动作）  │
                       └───────────┬──────────────────┘
                                   │ RPC (:8003)
                       ┌───────────▼──────────────────┐
                       │  EdgeAPI (API 节点)           │  MySQL
                       │  · 配置组装 / 下发 / 统计汇总  │
                       └───────────▲──────────────────┘
                                   │ RPC
                       ┌───────────┴──────────────────┐
                       │  EdgeAdmin (管理面板 :7788)   │
                       └──────────────────────────────┘
```

| 组件 | 默认端口 | 说明 |
| --- | --- | --- |
| EdgeAdmin | 7788 | 管理面板（Go 后端 + Vue 前端） |
| EdgeAPI | 8003 | 管理端与节点端的通信中枢，唯一访问数据库的组件 |
| EdgeNode | 80 / 443 | 边缘节点，实际承载流量、缓存与 WAF |

---

## 三、目录结构

```
.
├── server/                 # 服务端（部署在管理机）
│   ├── EdgeAdmin/          # 管理端
│   ├── EdgeAPI/            # API 节点
│   ├── EdgeCommon/         # 共享库（服务端副本）
│   └── EdgePlus/go.mod     # 私有模块占位（满足 EdgeAdmin 的 replace 指令）
├── client/                 # 节点端（部署在边缘机器）
│   ├── EdgeNode/           # 边缘节点
│   └── EdgeCommon/         # 共享库（客户端副本）
├── docs/
│   ├── MODIFICATIONS.md    # 改造清单与部署验证记录
│   └── WAF-COMPARE.md      # SafeLine vs GoEdge WAF 对比与整合方案
└── README.md
```

> EdgeCommon 在 server/ 与 client/ 各放一份：上游 `go.mod` 里是 `replace => ../EdgeCommon`，
> 两侧必须保持同级目录关系，不能共用一个副本。

---

## 四、快速开始

### 4.1 环境要求

- Go 1.21+、GCC（节点端 WAF 依赖 libinjection 的 cgo 编译）
- MySQL 8（仅 EdgeAPI 所在机器访问）
- Node.js 16+（仅在需要重新构建前端时使用）

### 4.2 构建

```bash
export GOFLAGS=-mod=mod

# 服务端
cd server/EdgeAdmin && go build -o /opt/edge-admin/bin/edge-admin ./cmd/edge-admin
cd server/EdgeAPI   && go build -o /opt/edge-api/bin/edge-api     ./cmd/edge-api

# 节点端（CGO 必须开启）
cd client/EdgeNode  && CGO_ENABLED=1 go build -ldflags "-w -s" -o /opt/edge-node/bin/edge-node ./cmd/edge-node

# 前端（可选，仓库已带 public 静态资源）
cd server/EdgeAdmin/web && npm install && npm run build
```

### 4.3 初始化

```bash
# 1. 准备数据库
mysql -uroot -p -e "CREATE DATABASE db_edge DEFAULT CHARSET utf8mb4;"
mysql -uroot -p -e "CREATE USER 'edge'@'127.0.0.1' IDENTIFIED BY '<你的密码>'; GRANT ALL ON db_edge.* TO 'edge'@'127.0.0.1';"

# 2. 写 configs/db.yaml（TeaGo 的 dbs 格式）
```

```yaml
default:
  db: "prod"
  prefix: ""
dbs:
  prod:
    driver: "mysql"
    dsn: "edge:<你的密码>@tcp(127.0.0.1:3306)/db_edge?charset=utf8mb4&timeout=30s&multiStatements=true"
    prefix: "edge"
    models:
      package: internal/db/models
fields:
  bool: [ "http2Enabled", "http3Enabled", "ignoreLocal", "ignoreSearchEngine" ]
```

```bash
# 3. 初始化表结构
/opt/edge-api/bin/edge-api setup

# 4. 生成管理端与 API 的握手配置
#    EdgeAdmin: ~/.edge-admin/api_admin.yaml（rpc.endpoints 指向 EdgeAPI）
#    EdgeNode : /opt/edge-node/configs/api_node.yaml（nodeId + secret，面板「添加节点」时生成）
```

### 4.4 systemd 托管

```ini
[Unit]
Description=GoEdge Node Service
After=network.target

[Service]
WorkingDirectory=/opt/edge-node          # TeaGo 的 Tea.Root 取进程工作目录，必须设置
ExecStart=/opt/edge-node/bin/edge-node daemon
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload && systemctl enable --now edge-node
```

> 不设置 `WorkingDirectory` 时，节点会因找不到 `configs/` 而启动失败。

---

## 五、运维与排障

```bash
# 管理机
systemctl status edge-api edge-admin
journalctl -u edge-api -f
mysql -uedge -p db_edge

# 节点机
systemctl status edge-node
systemctl restart edge-node     # 修改 WAF 策略 / IP 名单 / 特征库后建议重启，强制重载配置
tail -f /opt/edge-node/logs/run.log
```

常见问题：

| 现象 | 原因与处理 |
| --- | --- |
| 面板改了 WAF 策略但不拦截 | 站点版本未递增，节点没拉到新策略；重启一次 `edge-node` 再验证 |
| 被拦截时 `curl` 返回 `000` 而不是 403 | `block` 动作是直接关闭连接，属正常表现；需要页面请改用 `page` 动作 |
| 测试机突然连不上节点 | `block` 动作带 `timeout` 会把来源 IP 自动写入黑名单并下发 nftables；到面板「IP 名单」删除条目即可（默认 600s 自动过期） |
| 启动报 `can not find database config` | `db.yaml` 必须是 TeaGo `dbs` 格式，不能用简化的 user/password/host 写法 |
| 登录提示「表单已失效」 | 需要先 `GET /csrf/token` 取 `csrfToken` 一并提交 |

---

## 六、文档

- [docs/MODIFICATIONS.md](./docs/MODIFICATIONS.md) —— 改造清单、构建部署步骤、部署验证记录（含实测命令）
- [docs/WAF-COMPARE.md](./docs/WAF-COMPARE.md) —— SafeLine 与 GoEdge WAF 能力对比矩阵、整合实现细节、端到端验证、后续路线图

---

## 七、与上游的关系

- 上游仓库：<https://github.com/TeaOSLab>（EdgeAdmin / EdgeAPI / EdgeNode / EdgeCommon）
- 基线版本：v1.4.1
- 本仓库为**整棵源码树的一次性快照**（各子模块的上游 git 历史已扁平化），改造点见 `docs/MODIFICATIONS.md`
- 本仓库不包含编译产物、部署私钥、数据库口令等敏感信息

## 八、免责声明

本项目仅用于**自有内网环境**的 CDN 与安全防护实践，请勿用于未授权的流量中转或攻击行为。
WAF 规则（尤其是语义分析类）存在误报可能，**上线前请先以 `log` 动作观察一段时间**，确认无业务影响后再切换为 `block`。

## 九、致谢

- [GoEdge](https://goedge.cn) / [TeaOSLab](https://github.com/TeaOSLab) —— 出色的开源 CDN 平台
- [libinjection](https://github.com/libinjection/libinjection) —— SQL 注入与 XSS 词法检测
- [SafeLine 雷池](https://github.com/chaitin/SafeLine) —— WAF 能力设计的对标参考
