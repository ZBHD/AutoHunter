<div align="center">

<img src="assets/banner.png" alt="AutoHunter" width="880">

# AutoHunter

多 Agent 协同的 AI 漏洞挖掘与人工复审平台

`锁定 · 侦察 · 出洞`

**原作者：StanleyNull** · **Copyright (c) 2026 StanleyNull**<br>
**许可证：[CC BY-NC 4.0](./LICENSE)** · **仅限非商业使用**

原作者 EduSRC 主页：<https://src.sjtu.edu.cn/profile/46491/>

原项目地址：[StanleyNull/AutoHunter](https://github.com/StanleyNull/AutoHunter)

<img src="assets/proof-results.png" alt="项目成果截图" width="480">

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

> 修改声明：当前仓库属于基于原作的修改版本，并非未经改动的原始发行版。

## 项目现状

它以任务为单位组织目标搜集、排队、AI 驱动的单目标分析、AI 初审、人工复审、通杀分析和报告整理，并把运行状态持久化到 SQLite。

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


## 已实现能力

### 任务与目标

- 支持 `EduSRC` 与 `企业SRC` 两种任务策略。
- 目标来源支持 `FOFA 自动搜`、`手动清单`、`两者` 和 `单站协作`。
- 自动搜集引擎包括 FOFA、360 Quake、Hunter、ZoomEye、Shodan 和 Censys；是否可用取决于对应凭据和接口配置。
- FOFA 查询支持直接语法、自然语言意图和自动判断。
- 单站协作支持完整深挖与轻量入口盘点；轻量模式保留路由能力，但限制站点地图阶段预算。
- 可为任务选择漏洞类型、指定挖掘方向、SRC 规则、Worker 并发数和任务专用模型。
- 目标队列支持人工排序、移除、状态查看；失败或跳过的目标进入硬骨头视图。
- 任务状态、队列、证据和运行事件持久化；默认在进程重启后恢复运行中的任务。

### Agent 工作流

- `Collector`：搜索、探活、预筛、评分、归属标注、聚类与入队。
- `Worker`：以单个目标为边界，按 `recon → locate → verify → evidence` 分阶段工作。
- `Reviewer`：校验证据、范围、重复性和危害等级，可采纳、忽略或打回定向深挖。
- `Killsweep`：围绕已确认线索建立通杀案例，记录事件、验证结果和人工复核状态。
- `Missed Signals`：保留尚未形成正式 Finding 的高价值信号，支持恢复、深挖和草稿处理。
- `Intel`：保存经验证、可复用的凭据、端点或目标画像，供后续 Worker 使用。
- `Report Assistant`：围绕 Finding 整理和编辑报告，并支持把结构化证据交给下一轮深挖。

### 模型与搜索凭据

- 全局 LLM Provider 池支持加权首选和单次请求内故障转移。
- 支持 `OpenAI Chat Completions`、`Anthropic Messages` 和 `OpenAI Responses` 三种协议适配。
- Provider 可独立启停、排序、设置权重和健康检测；健康检测会验证基础请求及工具调用协议。
- FOFA Key 池支持独立启停、排序、检测、限流冷却、日额度冷却、临时故障退避和运行状态持久化。
- API 与界面中的密钥采用脱敏显示，脱敏占位不会覆盖已保存的真实密钥。

### 控制台与运维

- Vue 3 控制台提供任务、指挥台、全局复审、疑似信号、通杀、设置等主要视图。
- 额外提供硬骨头、情报库、漏洞库和运行日志视图。
- 支持全权限、只读和观摩三种访问角色；观摩角色会隐藏敏感字段。
- 内置应用层 WAF、安全响应头、请求体大小限制和可选反向代理信任配置。
- Docker watchdog 定期检查 `/health`；应用无响应时输出诊断并交由 Docker 重启。
- 提供数据备份、服务器更新、健康检查和旧镜像回滚脚本。

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

SRC CLI 输出是**候选地图而不是漏洞**。CLI 结果会先转换为带来源、优先级和验证动作的候选，再通过 HTTP 单请求验证。实时看板用 `tool_src_cli_started` 记录工具、轮次和阶段，用 `tool_src_cli_result` 记录执行状态、解析状态和脱敏后的候选摘要；完整输出只进入私有证据存储。工具和 HTTP 请求只跟随**同主机重定向**，跨主机地址仅记录，不自动跟随。

| 场景 | 首选链路 | 结束条件 |
| --- | --- | --- |
| SPA/API | `probe_http → crawl_endpoints → analyze_javascript → http_request` | 高价值端点已经逐条验证并结算 |
| 后台或目录 | `probe_http → discover_content → http_request` | 已排除软 404 和统一跳转 |
| 隐藏参数 | `discover_parameters → http_request → compare_http_responses` | 基线与候选差异已经验证 |
| API 文档 | `http_request → analyze_api_schema → http_request` | 高风险接口的鉴权和对象边界已经验证 |
| 登录与越权 | `http_request → analyze_auth_material → session_set → compare_http_responses` | 不同身份或对象的响应差异已经验证 |
| 企业 SRC | `crawl_endpoints → discover_parameters → http_request` | 通过有界侦察、单请求和本地分析完成取证 |

企业 SRC **严禁使用** Nuclei、Dalfox 等自动化漏洞扫描器。项目策略同时禁止破坏性写入、删除、密码重置、批量导出、全端口宽扫、压力测试等操作。即使工具存在于镜像中，也不代表所有任务模式都允许调用。

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

安装脚本会检查 Docker，交互式采集 LLM 和 FOFA 配置，生成 `.env`，构建镜像并启动服务。首次构建需要下载前后端依赖及安全工具，耗时取决于网络环境。

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

## 首次配置

### 最小配置

`.env.example` 是应用环境变量的主要参考；Compose 还支持少量部署变量。首次部署重点检查：

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `LLM_BASE_URL` | `https://api.deepseek.com/v1` | 兼容回退 Provider 的 API 基址 |
| `LLM_API_KEY` | 空 | 兼容回退 Provider 的 API Key |
| `LLM_MODEL` | `deepseek-chat` | 兼容回退模型名 |
| `LLM_PROTOCOL` | `openai_chat` | 模型协议适配器 |
| `FOFA_KEY` | 空 | FOFA 单 Key 兼容回退配置 |
| `AUTOHUNTER_API_TOKEN` | 空 | 全权限令牌，生产部署必须设置 |
| `AUTOHUNTER_READ_TOKEN` | 空 | 只读令牌，可查看复审等敏感页面但不能写入 |
| `AUTOHUNTER_OBSERVER_TOKEN` | 空 | 观摩令牌，只返回脱敏信息 |
| `AUTOHUNTER_HOST_PORT` | `18800` | Compose 使用的宿主机端口（可自行加入 `.env`） |
| `AUTOHUNTER_RESTORE_ON_STARTUP` | `1` | 重启后恢复运行中任务 |

可在控制台“设置”页维护 LLM Provider 池、FOFA Key 池、其他搜索引擎凭据、默认并发和 Worker 提示词版本。数据库配置会持久化在 `ah_data` 卷中。

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

## 本地开发与测试

完整运行环境建议继续使用 Docker。本地开发可分别启动后端和前端；本机未安装 Dockerfile 中的外部工具时，与 CLI 工具有关的 Worker 能力不会完整可用。

```powershell
# Python 3.12 环境
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt

# 后端开发服务
python -m uvicorn app.main:app --reload --port 8000
```

另开终端：

```powershell
cd frontend
npm install
npm run dev
```

Vite 开发服务器会把 `/api` 代理到 `http://localhost:8000`。

运行测试：

```powershell
python -m pytest
cd frontend
npm test
npm run build
```

## 安全与使用限制

- 本项目仅供已经取得明确授权的安全测试、漏洞研究和教学使用。
- 搜索语法、手动目标、重定向和任务范围都应由使用者复核；自动化系统不能替代授权边界管理。
- 公网部署必须配置强随机全权限令牌，并建议通过 HTTPS 反向代理访问。
- 内置 WAF 不是网络隔离或身份认证的替代品。
- LLM 会产生费用，也可能输出错误判断；漏洞结论必须经过人工复核。
- 目标数、FOFA 页数、Worker 轮数和并发都会影响 API 成本、内存和子进程数量。
- 数据库存放目标、证据、报告和密钥配置；备份文件和 Docker 卷应按敏感数据保护。
- 原作者及维护者不对未授权使用、误报、漏报、数据损失或其他使用后果承担责任；完整免责声明见 [LICENSE](./LICENSE)。

## 技术栈

- 后端：Python 3.12、FastAPI、SQLAlchemy 2、SQLite、asyncio
- 前端：Vue 3、Vue Router、Vite 5
- 模型接入：OpenAI Chat Completions、Anthropic Messages、OpenAI Responses
- 部署：Docker 多阶段构建、Docker Compose、Uvicorn、watchdog
- 测试：pytest、pytest-asyncio、Node.js test runner

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
