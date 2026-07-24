<div align="center">

<img src="assets/banner.png" alt="AutoHunter" width="880">

# AutoHunter

多 Agent 协同的 AI 漏洞挖掘与人工复审平台

**原作者：StanleyNull** · **Copyright (c) 2026 StanleyNull**<br>
**许可证：[CC BY-NC 4.0](./LICENSE)** · **仅限非商业使用**

原项目地址：[StanleyNull/AutoHunter](https://github.com/StanleyNull/AutoHunter)

</div>

---

## 版权与版本说明

AutoHunter 原作由 **StanleyNull** 发布，版权归原作者所有。本仓库在原作基础上进行了持续维护和功能扩展，具体修改记录以本仓库 Git 历史为准。

根据 CC BY-NC 4.0 的署名要求，使用、修改或再分发本项目时必须：

- 保留原作者 `StanleyNull` 的姓名、项目内署名和版权声明；
- 保留 [LICENSE](./LICENSE) 并提供 CC BY-NC 4.0 协议链接；
- 明确说明是否对原作进行了修改；
- 不得暗示原作者认可、担保或参与维护后的版本；
- 不得用于商业销售、付费服务、付费分发或其他营利用途。

## 项目现状

当前主流程：

```text
目标搜集/手动录入
        ↓
存活检测、预筛、评分、去重、排队
        ↓
Worker 按目标执行侦察、定位、验证与取证
        ↓
Reviewer 初审：采纳 / 忽略 / 打回深挖
        ↓
人工复审：编辑报告 / 通过 / 驳回 / 标记提交
        ↓
通杀分析、疑似信号复盘、情报沉淀
```


## 工具链与边界

Docker 镜像内包含以下主要工具：

| 类别 | 工具或能力 | 用途 |
| --- | --- | --- |
| HTTP 与指纹 | HTTPX、WhatWeb、curl | 存活、标题、技术栈和基线请求 |
| 端点与参数 | Katana、FFUF、Arjun | 当前目标内的有界端点、目录和参数发现 |
| 防护与端口 | wafw00f、Nmap | WAF 指纹和少量明确 Web 端口验证 |
| 定向验证 | Nuclei、Dalfox、SQLMap | 已有明确入口、参数或模板时的辅助验证 |
| 本地分析 | JS、OpenAPI、认证材料、编码和响应差异分析 | 从已有响应中提取线索与证据 |

扫描器命中只作为候选线索，不能替代真实请求、响应和影响证据。企业 SRC 模式会限制自动化漏洞扫描器；Nuclei 和 Dalfox 不会作为企业模式的可用结构化工具，命令执行同样受企业策略检查。

Worker 以单个目标为边界，按 `recon → locate → verify → evidence` 分阶段工作。SRC CLI 输出是**候选地图而不是漏洞**：实时看板用 `tool_src_cli_started` 记录工具、轮次和阶段，用 `tool_src_cli_result` 记录执行、解析状态和脱敏摘要。工具和 HTTP 请求只跟随**同主机重定向**，跨主机地址仅记录，不自动跟随。


| 场景 | 首选链路 | 结束条件 |
| --- | --- | --- |
| SPA/API | `probe_http → crawl_endpoints → analyze_javascript → http_request` | 高价值端点已经逐条验证并结算 |
| 后台或目录 | `probe_http → discover_content → http_request` | 已排除软 404 和统一跳转 |
| 隐藏参数 | `discover_parameters → http_request → compare_http_responses` | 基线与候选差异已经验证 |
| API 文档 | `http_request → analyze_api_schema → http_request` | 高风险接口的鉴权和对象边界已经验证 |
| 登录与越权 | `http_request → analyze_auth_material → session_set → compare_http_responses` | 不同身份或对象的响应差异已经验证 |
| 企业 SRC | `crawl_endpoints → discover_parameters → http_request` | 通过有界侦察、单请求和本地分析完成取证 |

企业 SRC **严禁使用** Nuclei、Dalfox 等自动化漏洞扫描器。项目策略同时禁止破坏性写入、删除、密码重置、批量导出、全端口宽扫和压力测试。


## 快速部署

### 环境要求

- Docker Engine 或 Docker Desktop
- Docker Compose v2
- 建议至少 `2 核 CPU / 4 GB 内存 / 20 GB 磁盘`
- 可访问所配置的 LLM API、搜索引擎 API 和授权测试目标

Linux 服务器是推荐运行环境。Windows 建议使用 Docker Desktop + WSL2，macOS 可使用 Docker Desktop。

### 一键安装

```bash
git clone https://github.com/ZBHD/AutoHunter.git autohunter
cd autohunter
bash scripts/install.sh
```

启动后访问：

```text
http://<服务器地址>:18800/
```

### 手动安装

```bash
cp .env.example .env
# 编辑 .env，至少配置一个可用的 LLM Provider，并设置访问令牌
docker compose up -d --build
docker compose logs -f autohunter
```

检查服务：

```bash
curl http://127.0.0.1:18800/health
# 正常返回：{"ok":true}
```

> 公网或可达网络部署时，务必设置 `AUTOHUNTER_API_TOKEN`。未配置任何访问令牌时，受保护的 `/api` 接口不会启用身份认证。


### 配置优先级

LLM 实际配置按以下顺序解析：

1. 任务选择专用模型时，使用任务配置；
2. 否则使用数据库中的全局 Provider 池；
3. 全局池为空时，回退到旧单模型设置和 `LLM_*` 环境变量。

FOFA 凭据按以下顺序解析：

1. 任务级 FOFA Key；
2. 非空的全局 FOFA Key 池；
3. 旧数据库 FOFA 配置；
4. 搜索引擎中的 FOFA 配置；
5. `FOFA_KEY` 环境变量。

全局池已经存在但全部被停用时，系统不会静默回退到旧环境变量。应在设置页修复、启用或删除池内配置。

### 任务配置建议

1. 先选择与授权范围一致的任务模式和目标来源。
2. 自动搜集时明确选择引擎并配置对应 Key；FOFA 可选直接语法或自然语言意图。
3. 手动清单每行填写一个 URL；单站协作建议只填写同一授权站点的入口。
4. 用“指定挖掘方向”描述本任务重点，不要把授权范围仅写在自然语言提示中。
5. 小内存机器从 `1-2` 个 Worker 并发开始；默认任务并发为 `3`。
6. 创建后先检查队列、搜集事件和 Provider 健康状态，再提高并发或扩大页数。

## 数据、备份与更新

Docker Compose 使用两个命名卷：

- `ah_data`：SQLite 数据库和持久化证据；
- `ah_work`：Worker 工作目录。

常用命令：

```bash
docker compose ps
docker compose logs -f autohunter
docker compose restart autohunter
docker compose down
docker compose up -d --build
```

`docker compose down` 默认保留命名卷；**不要执行 `docker compose down -v`**，否则会删除数据库和证据。

手动备份：

```bash
bash scripts/backup-data.sh
```

脚本会备份并校验 `ah_data`，同时备份 `.env`，默认保留最近 10 份，文件写入 `backups/`。

服务器更新：

```bash
bash scripts/update-server.sh
```

更新脚本要求工作区没有未提交改动。它会快进拉取 `main`、验证 Compose 配置、构建新镜像、停止旧容器、备份数据、启动并检查 `/health`；新版本未通过健康检查时会尝试回滚旧镜像。脚本也支持通过 `SOURCE_BUNDLE` 使用离线 Git bundle 更新。

## 安全与使用限制

- 本项目仅供已经取得明确授权的安全测试、漏洞研究和教学使用。
- 搜索语法、手动目标、重定向和任务范围都应由使用者复核；自动化系统不能替代授权边界管理。
- 公网部署必须配置强随机全权限令牌，并建议通过 HTTPS 反向代理访问。
- 内置 WAF 不是网络隔离或身份认证的替代品。
- LLM 会产生费用，也可能输出错误判断；漏洞结论必须经过人工复核。
- 目标数、FOFA 页数、Worker 轮数和并发都会影响 API 成本、内存和子进程数量。
- 数据库存放目标、证据、报告和密钥配置；备份文件和 Docker 卷应按敏感数据保护。
- 原作者及维护者不对未授权使用、误报、漏报、数据损失或其他使用后果承担责任；详细说明见下文“免责声明”及 [LICENSE](./LICENSE)。


## 免责声明

请在下载、安装、配置或使用本项目之前完整阅读并理解以下内容：

1. **授权与合规责任**：本项目仅供已取得目标所有者明确授权的安全测试、漏洞研究和教学使用。使用者应自行确认测试对象、时间、方式和影响范围均在授权边界内，并遵守所在地适用的法律法规、行业规范及目标方规则。
2. **自动化结果不保证**：本项目依赖自动化工具、第三方接口和大语言模型，可能产生误报、漏报、错误判断、不完整证据或非预期请求。任何扫描结果、漏洞结论和报告均应由具备相应能力的人员复核，不应直接作为处置、披露或提交依据。
3. **运行与业务风险**：网络请求、目录发现、参数探测和漏洞验证可能对目标系统或使用者自身环境造成负载、告警、封禁、数据变更、服务中断或其他影响。使用者应在执行前完成风险评估、备份和恢复准备，并自行承担操作风险。
4. **费用与第三方服务**：模型 API、搜索引擎、代理、云服务及其他第三方组件可能产生费用，并受各自服务条款、隐私政策和可用性约束。使用者应自行管理凭据、额度、账单和第三方合规要求。
5. **数据与凭据保护**：任务数据库、运行日志、证据、报告、Cookie、Token、账号密码及备份文件可能包含敏感信息。使用者应采取访问控制、加密、脱敏、最小化留存和安全销毁措施，并承担因配置不当、泄露或保管不善造成的后果。
6. **责任限制**：在适用法律允许的最大范围内，原作者、维护者及贡献者不对使用或无法使用本项目所产生的直接或间接损失承担责任，包括但不限于数据损失、业务中断、账号封禁、费用支出、第三方索赔或法律责任。使用本项目即表示使用者理解并接受上述风险。

本节是面向使用者的风险提示，不构成法律意见，也不改变 [LICENSE](./LICENSE) 中的版权归属和许可条件；如本节与许可证文本存在不一致，以许可证文本为准。

## 许可证

本项目采用 **Creative Commons Attribution-NonCommercial 4.0 International（CC BY-NC 4.0）** 协议。协议摘要与免责声明见 [LICENSE](./LICENSE)，完整法律文本见：

- <https://creativecommons.org/licenses/by-nc/4.0/legalcode>
- <https://creativecommons.org/licenses/by-nc/4.0/deed.zh>

本 README 是对当前修改版本的说明，不改变 LICENSE 中属于原作者的版权声明和许可条件。

---

<div align="center">

**Powered By StanleyNull**

Copyright (c) 2026 StanleyNull · CC BY-NC 4.0

</div>
