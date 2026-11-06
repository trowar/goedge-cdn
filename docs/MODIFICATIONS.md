# 魔改记录

基线：GoEdge v1.4.1（master 2024-07-27）　改造日期：2026-11-06

## 一、来源 IP 可信化

### 问题

默认实现下，客户端可以自带 `X-Forwarded-For` / `X-Real-IP`：
- 回源时原样透传给源站（`setForwardHeaders` 中已存在则保留，仅追加 TCP 地址）；
- `X-Real-IP` 只在“不存在”时才写入，伪造值直接放行；
- 当网站未配置“客户端IP获取方式”时，WAF、IP 黑名单、限速、统计等使用的 `${remoteAddr}` 也会读请求头。

结果：后端拿到的来源 IP 不可信。

### 情况 1：用户直连 CDN 节点

- 一律以 TCP 连接的真实地址为准；
- 回源时 **覆盖**（不是追加）`X-Forwarded-For`、`X-Real-IP`，写入节点观测到的真实地址；
- 客户端自带的 `X-Forwarded-For`、`X-Real-IP`、`Forwarded`、`CF-Connecting-IP`、`True-Client-IP` 全部丢弃。

### 情况 2：用户通过 Cloudflare（小盾牌）访问

- 内置 Cloudflare 官方 IPv4/IPv6 网段（`internal/utils/cloudflare.go`），
  判断 TCP 来源是否为 Cloudflare 节点；
- 来源是 Cloudflare 时，依次取 `CF-Connecting-IP` → `True-Client-IP` → `X-Forwarded-For` **最右侧一跳**，
  得到真实用户 IP（Cloudflare 以追加方式写 XFF，左侧可能是客户端伪造值，只有最右侧是 CF 观测到的客户端）；
- 回源时写入：
  - `X-Forwarded-For: <真实IP>`
  - `X-Real-IP: <真实IP>`
  - `CF-Connecting-IP: <真实IP>`
  - `True-Client-IP: <真实IP>`
  （后两个便于后端沿用已有的 CF 头取 IP 配置）
- 来源不是 Cloudflare 时，客户端伪造的 CF 头一律删除。

Cloudflare 网段可以通过文件**追加**自定义段（每行一个 CIDR，`#` 注释；内置的官方段始终生效）：

```
/etc/edge-cdn/cloudflare-ips.txt
```

> 注意：该文件只在节点进程启动时读取一次，修改后需 `systemctl restart edge-node`。

### 可信前置代理（自建多级 CDN）

若前面还有自己的反向代理，在「网站设置 → 客户端IP获取方式」选择 **代理**，
则保留客户端 XFF 链路并按原有逻辑追加节点地址（受 `XFFMaxAddresses` 限制）。

### 同步修改

- WAF / IP 名单 / 限速 / 统计：`requestRemoteAddr()`、`requestRemoteAddrs()` 使用同一套可信判断；
- FastCGI 回源：同样清理伪造头（PHP 通过 `REMOTE_ADDR` 拿到真实地址）；
- 头部读写改为不区分大小写（避免 `X-Real-Ip` / `CF-Connecting-Ip` 大小写被绕过）。

测试：`client/EdgeNode/internal/nodes/http_request_forwarded_test.go`（6 个用例，全部通过）。

## 二、单用户版本

### 移除的功能

| 位置 | 改动 |
| :-- | :-- |
| EdgeAdmin 主菜单 | 去掉「用户」（`/users`） |
| EdgeAdmin 权限模块 | `AllModuleMaps` 去掉「用户」「财务」 |
| EdgeAdmin 权限判断 | `AllowModule` 对 `user` / `finance` / `plan` / `ticket` 恒返回 false |
| EdgeAdmin 路由 | 不再注册 `/users/*`（访问 404） |
| EdgeAdmin 看板 | 去掉「用户」统计块 |
| EdgeAdmin 网站设置 | 去掉「所属用户 / 指定用户 / 选择套餐」区块 |
| EdgeAPI | `RegisterUser`、`CreateUser` 直接返回“单用户版本已禁用平台用户” |
| EdgeAPI | `LoginUser` 非商业版提示改为“单用户版本已禁用平台用户登录” |

保留：管理员账号（`/admins`，可多个管理员）、多节点集群、节点/网站/证书/WAF 等全部能力。
**财务**：开源版没有 `/finance` 页面，菜单项已移除、权限恒 false，无残留入口。
**工单**：开源版没有工单页面与 API 服务（仅 pb 定义残留，不可达），菜单仅商业版出现，权限恒 false。
**套餐**：网站/证书页面的套餐选择与 `/servers/users/plans` 调用已移除。

计费相关代码（`user_bill` / `server_bill` 模型）在开源版中没有任何入口和定时任务，保持原样未删。

## 三、构建与部署

```bash
cd /data/cdn/server/EdgeAdmin && GOFLAGS=-mod=mod go build -o /data/cdn/bin/edge-admin ./cmd/edge-admin
cd /data/cdn/server/EdgeAPI   && GOFLAGS=-mod=mod go build -o /data/cdn/bin/edge-api   ./cmd/edge-api
cd /data/cdn/client/EdgeNode  && GOFLAGS=-mod=mod go build -o /data/cdn/bin/edge-node  ./cmd/edge-node
```

- EdgeAdmin 的模板在运行时从 `web/` 目录加载，部署时必须把 `server/EdgeAdmin/web` 一起带上；
- 节点端/管理端二进制为静态编译（dynamically linked 仅 libc），可直接拷贝到目标机器。

## 四、验证方法

```bash
# 情况1：伪造头应无效，输出应为节点看到的真实地址
curl -H 'X-Forwarded-For: 1.2.3.4' -H 'X-Real-IP: 1.2.3.4' https://你的域名/
# 源站日志中应看到真实客户端 IP，而不是 1.2.3.4

# 情况2：经 Cloudflare 访问，源站应看到 XFF / X-Real-IP / CF-Connecting-IP 都是用户真实 IP
curl https://cf代理的域名/
```

## 五、部署验证记录（2026-11-06）

### 环境

| 角色 | 主机 | 说明 |
| --- | --- | --- |
| 服务端 | 192.168.0.62 | MySQL 8 + EdgeAPI(8003) + EdgeAdmin(7788)，2G swap，systemd 托管 |
| 边缘节点 | 192.168.0.247 | EdgeNode(80)，同机 8080 运行回显源站 `echo-origin.service` 用于验证 |

### 目录与账号

```
# 服务端
/opt/edge-api/{bin,configs,logs}      # configs: api.yaml, db.yaml
/opt/edge-admin/{bin,configs,logs,web}
# 节点端
/opt/edge-node/{bin,configs,logs,pages}   # configs: api_node.yaml
/opt/echo/server.py                   # 回显源站，监听 0.0.0.0:8080
```

- 管理面板：`http://192.168.0.62:7788`，用户名 `admin`，密码 `********`（首次部署时自行设置）
- 数据库：`db_edge`，账号 `edge` / `********`（MySQL 仅监听本机）
- 集群“内部CDN集群”(id=2)、节点 node247、站点 `www.test.com`、源站 `http://127.0.0.1:8080`

### 验证结果

测试机 192.168.0.62 直连节点并携带伪造头，源站（回显服务）实际收到：

1. **直连（情况 1）**：伪造 `X-Forwarded-For: 1.1.1.1`、`X-Real-IP: 2.2.2.2`、`Forwarded`、`CF-Connecting-IP: 4.4.4.4`
   → 源站收到 `X-Forwarded-For: 192.168.0.62`、`X-Real-Ip: 192.168.0.62`，
   伪造的 `Forwarded`、`CF-Connecting-IP` 已被删除。
2. **Cloudflare（情况 2，用 `/etc/edge-cdn/cloudflare-ips.txt` 把 192.168.0.62 模拟成 CF 节点）**：
   `CF-Connecting-IP: 198.51.100.9` + 伪造 `X-Forwarded-For: 1.1.1.1`
   → 源站收到 `X-Forwarded-For: 198.51.100.9`、`X-Real-Ip: 198.51.100.9`、
   `CF-Connecting-IP: 198.51.100.9`、`True-Client-IP: 198.51.100.9`。
3. **CF 来源但缺少 CF 头**：`X-Forwarded-For: 6.6.6.6, 198.51.100.9`
   → 取最右侧 `198.51.100.9`，左侧伪造值被丢弃。
4. **面板**：`/users`、`/finance`、`/tickets` 均返回 404；菜单仅剩 admin/dashboard/dns/log/node/server/setting；
   平台用户注册/登录 RPC 直接返回“单用户版本已禁用”。

复现命令：

```bash
# 情况1（在 192.168.0.62 上执行）
curl -s -H 'Host: www.test.com' -H 'X-Forwarded-For: 1.1.1.1' -H 'X-Real-IP: 2.2.2.2' \
     -H 'Forwarded: for=3.3.3.3' -H 'CF-Connecting-IP: 4.4.4.4' http://192.168.0.247/test

# 情况2（需先把发起机加入 /etc/edge-cdn/cloudflare-ips.txt 并重启 edge-node）
curl -s -H 'Host: www.test.com' -H 'CF-Connecting-IP: 198.51.100.9' \
     -H 'X-Forwarded-For: 1.1.1.1' -H 'X-Real-IP: 2.2.2.2' http://192.168.0.247/test
```

### 运维命令

```bash
# 服务端 192.168.0.62
systemctl status edge-api edge-admin
journalctl -u edge-api -f
mysql -uedge -p db_edge

# 节点 192.168.0.247
systemctl status edge-node
systemctl restart edge-node          # 修改 cloudflare-ips.txt 后需要重启
tail -f /opt/edge-node/logs/run.log
# 回显源站
systemctl status echo-origin && curl -s http://127.0.0.1:8080/
```

### 上线前需要调整

1. 删除测试用的 `/etc/edge-cdn/cloudflare-ips.txt`（或去掉里面的 `192.168.0.62/32`），
   否则会把测试机当成 Cloudflare 节点；正式使用时可留空文件或只记录真实的自建代理段。
2. 修改面板 `admin` 密码、MySQL 密码。
3. 站点 `www.test.com` 只是验证用，正式接入时按真实域名/证书重新建站。
4. 本机 1C1G 的机器已加 2G swap 并调小 MySQL buffer pool，正式环境建议至少 2C4G。

## 六、WAF 能力整合（对齐 SafeLine / 雷池）

对比矩阵与完整方案见 [WAF-COMPARE.md](./WAF-COMPARE.md)，这里只记录改动点。

### 新增检查点（EdgeNode 运行时 + EdgeCommon 面板注册，44 → 47）

| 检查点 | 运行时文件 | 说明 |
| --- | --- | --- |
| `${requestInjectionAnalysis}` | `internal/waf/checkpoints/request_injection_analysis.go` | 多类型语义分析，返回 `sqli,xss,cmdi,path-traversal,ssrf,crlf,ldap,xpath,xxe,deserialization,ssti,nosql,expression` 中以逗号分隔的命中项 |
| `${requestBotFingerprint}` | `internal/waf/checkpoints/request_bot_fingerprint.go` | 返回 `search-engine,seo-tool,ai-crawler,monitor,scanner,headless,http-library,empty` |
| `${requestHoneypot}` | `internal/waf/checkpoints/request_honeypot.go` | 返回 `path,param,header` |

### 新增模块

| 文件 | 作用 |
| --- | --- |
| `internal/waf/injectionutils/analyzer.go` | 语义分析引擎（libinjection + 预编译正则 + 协议/关键字判定），入口 `AnalyzeInjection()` / `AnalyzeArgs()`，最大分析 8KB |
| `internal/waf/injectionutils/analyzer_test.go` | 12 个用例，含正常文本误报回归 |
| `internal/utils/bot.go` | Bot 特征库（约 80 条内置特征、8 大分类、sync.Map 缓存），自定义文件 `/etc/edge-cdn/bot-uas.txt` |
| `internal/utils/honeypot.go` | 蜜罐特征（路径/参数/隐藏头），自定义文件 `/etc/edge-cdn/honeypot-paths.txt` |
| `internal/waf/checkpoints/request_analysis_test.go` | 3 个检查点用例 |

### 修改文件

```
client/EdgeNode/internal/waf/checkpoints/utils.go
client/EdgeCommon/pkg/serverconfigs/firewallconfigs/http_firewall_checkpoints.go
server/EdgeCommon/pkg/serverconfigs/firewallconfigs/http_firewall_checkpoints.go
```

### 实测（192.168.0.247）

正常请求 200；SQL 注入 / 命令注入 / SSRF / 路径穿越 → 语义分析规则集拦截；`sqlmap` UA、空 UA → Bot 规则集拦截；
`/.env` → 蜜罐规则集 403；`GPTBot` → 放行并记录。详见 WAF-COMPARE.md 第五节。

### 排障备忘

1. 面板改完 WAF 若节点不生效，先重启 `edge-node` 强制拉取一次站点配置。
2. `block` 动作命中时连接直接关闭（curl 显示 `000`），不是 403；要页面请用 `page` 动作。
3. `block.options.timeout > 0` 会自动把来源 IP 加入 `edgeIPItems` 并下发 nftables，测完记得删条目，否则测试机自己被拒。
4. 规则集动作 JSON 字段是 `{code, options}`，写成 `{type, params}` 会变成空动作且无任何报错。
