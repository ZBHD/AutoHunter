# 疑似后门与服务器被攻陷识别设计

> 2026-07-15 | status: proposed

## 目标

为 AutoHunter 增加 `backdoor_compromised` 漏洞类型，用于识别目标服务当前完整性已经被破坏的情况，例如网页被篡改、博彩/色情页面、SEO 暗链和可验证的 webshell。

该类型采用本次确认的 **B 方案**：先按证据收录，再进入现有“扩大危害”深挖流程，继续寻找初始入侵入口、权限边界和更高影响。入侵入口暂时未知不会阻塞已实锤的完整性事件收录。

## 非目标

- 不新增数据库列或新的 API 字段；继续使用现有 `Finding.vuln_type` 字符串和 `Task.vuln_types` JSON。
- 不自动把所有异常页面、外链、广告、评论、第三方 iframe 或历史搜索结果认定为服务器被攻陷。
- 不把同一页面、同一 webshell 路径和同一请求响应重复生成升级 Finding。
- 不在识别或深挖过程中执行破坏性写删改、修改真实账号密码、批量导出、持久化或扩大目标范围。
- 不改变现有其它漏洞类型的审核、去重和深挖语义。

## 核心语义

### 规范类型和显示名称

后端、提示词和去重使用规范值：

```text
backdoor_compromised
```

前端显示为：

```text
疑似后门 / 服务器被攻陷
```

新建任务默认选中该类型。编辑已有任务时保留任务当前的类型数组，不自动改写历史配置。

### 识别范围

以下信号可以进入该类型的判断：

- 目标自有服务持续返回与其业务无关的赌博、色情、博彩或明显垃圾页面。
- 页面被植入 SEO 暗链、博彩外链或明显的网页篡改内容。
- 发现当前目标可重复访问的 webshell，并取得无害、确定性的服务端执行证据。
- 正常业务页面被攻击者内容替换，且能用同站身份或正常页面做对照。

“不知道攻击者从哪里进入”只影响后续根因描述，不会否定已经证明的完整性破坏。

## 证据与判定

### Worker 最小证据闭环

Worker 发现可疑内容后，按以下顺序补证：

1. 用未跟随跳转的原始请求记录 Host、状态码、Location、关键响应头和正文；需要跟随跳转时同时保留 redirect chain 和 final URL。
2. 使用随机查询参数或 `Cache-Control: no-cache` 复取一次，确认结果不是浏览器、CDN 或历史缓存。
3. 至少提供一项目标归属依据，例如证书、备案、官网链接、同站品牌或业务路径；仅凭旧 DNS 记录不够。
4. 对 deface/暗链给出恶意正文与正常业务身份的对照；对 webshell 必须给出当前 URL 的可重复、无害执行结果，文件名或目录字符串本身不够。
5. 提交时保证 `raw_request` 和 `raw_response` 来自同一次真实请求，描述中区分事实、推测和未知的初始入口。

### Reviewer 判定矩阵

| 材料状态 | 处理 | 规则 |
| --- | --- | --- |
| 归属明确、当前复取仍返回篡改/暗链，且有正常内容对照 | `accepted` | `backdoor_compromised`，通常高危 7~8 |
| 有可重复的服务端命令/脚本执行证据 | `accepted` | `backdoor_compromised`，严重 9~10；按实际影响落点 |
| 信号可信但当前性、归属或来源对照缺一项 | `deepen` | 指令必须写明下一次复取、跳转链或对照动作 |
| 域名停放/出售页、合法 SSO/活动跳转、白标 SaaS、CDN/WAF 错误页 | `ignored` | 说明排除依据 |
| 只有历史 FOFA/搜索引擎/Wayback 页面、单个关键词、广告、UGC、iframe | `ignored` | 不作为当前完整性证据 |
| 只有 `/shell.php` 等文件名，没有执行证据 | `ignored` 或 `deepen` | 取决于是否存在明确的下一步可验证动作 |

Reviewer 不要求先证明初始入侵手法，但必须检查目标归属、当前性和响应来源。

## 提示词设计

### 统一规则块

在 `app/agents/prompts.py` 中维护共享的后门识别规则，避免不同版本内容漂移。该规则块由实际入口统一附加到：

- EduSRC worker：current/compact、modern、legacy。
- 企业 worker：compact。
- EduSRC reviewer：compact。
- 企业 reviewer：完整版本。

Worker 规则块负责识别信号、最小取证、误报排除和提交格式；Reviewer 规则块负责上面的 accepted/deepen/ignored 矩阵与等级口径。

Collector 的 EduSRC 和企业查询提示词增加类型映射：只有任务包含该类型时，才允许围绕明确的系统/归属锚点生成相关查询；禁止用宽泛的 `博彩`、`异常`、`Error` 等词圈出大量正常资产。

### 扩大危害专用路线

在 `ESCALATE_SYSTEM_PROMPT` 中增加“服务器被攻陷”路线：

1. 复核原始篡改证据仍然成立，并确认不是跳转、缓存或第三方托管。
2. 沿同一目标寻找初始入口：上传、未授权管理面、组件漏洞、文件写入、泄露凭证或其它已观察到的可控点。
3. 每次只做最小、可复核的请求；优先只读验证，写操作只使用自建测试对象并清理。
4. 找到新的 RCE、可用凭证、管理员入口、未授权写或规模化影响时，提交新的升级 Finding，并使用真正对应的漏洞类型。
5. 只有原始页面或原始 webshell 证据重复出现、没有新危害时，调用 `abandon_escalation`，不重复提交。

`backdoor_compromised` accepted Finding 仍按现有等级策略进入持久化 escalation attempt；不在 `should_escalate()` 增加类型排除。

## 升级结果的确定性防重复

现有升级 Finding 使用独立查重键，因此仅依赖普通 dedup 不能阻止同一源 Finding 的重复升级。扩展 `_escalation_is_significant` 的判断时保留现有三条门槛（等级提升、顶格危害、影响面数量级），并增加后门专用约束：

- 源类型归一化为 `backdoor_compromised` 时，升级结果必须有新的 `raw_request` 和 `raw_response`，且至少一项与源证据不同；空证据或完全重复证据直接跳过。
- 若升级结果仍为 `backdoor_compromised`，必须同时满足真实等级提升或新的影响面/执行证据；单纯换标题不算升级。
- 若升级结果改为 `file_upload`、`rce`、`unauthorized_access` 等根因类型，则仍需满足现有显著性门槛和新证据要求。

该判断只负责防止重复产出，最终 Finding 仍进入 Reviewer 审核。

## 去重与类型归一化

在 `app/dedup.py` 的 `_VULN_TYPE_ALIASES` 增加规范类型及常见中英文写法：

```text
backdoorcompromised, 疑似后门, 疑似被黑, 服务器被攻陷, 被攻陷,
被挂马, 挂马, 网页被篡改, 被篡改, 后门, webshell, compromised,
hacked, defaced, 被黑, 植入后门, web后门, 网页挂马, 暗链
```

归一化、数据库预筛和 Python 最终比较继续沿用现有流程，不改查重键格式。

## 前端与接口兼容

`frontend/src/vulnerabilityTypes.js` 是漏洞类型的唯一目录，增加一个 canonical option。`defaultVulnerabilityTypes()` 会自动让创建页默认勾选；创建页和编辑弹窗继续发送字符串数组。

后端 `CreateTaskRequest`、`UpdateTaskRequest`、`Task.vuln_types` 和 Finding schema 继续接受自由字符串，不做数据库迁移。`app/schemas.py` 与 `app/tools/schemas.py` 中的示例描述同步加入该类型，帮助模型输出规范值，但不新增校验分支。

## 数据流

```text
前端类型目录
  -> Task.vuln_types JSON
  -> Collector 根据类型生成受约束的搜集意图
  -> Worker 取证并提交 backdoor_compromised
  -> dedup 归一化并查重
  -> Reviewer 按证据矩阵审核
  -> accepted 后创建 escalation attempt
  -> EscalateHunter 查找初始入口和新危害
  -> 确定性显著性门槛拦截重复结果
  -> 新 Finding 进入现有 Reviewer 流程
```

## 失败与边界处理

- 请求只得到外部 30x：保留跳转证据，但不能直接按服务器被攻陷收录。
- 响应被 CDN/WAF challenge、维护页或缓存头解释：先 `deepen` 补当前性；无法排除则 `ignored`。
- 目标归属无法确认：不把旧 DNS 或单一指纹当作归属证据。
- 找不到初始入口：保留已经 accepted 的完整性 Finding，escalation 以 `abandon` 收尾，不回滚原结果。
- EscalateHunter 超时、额度耗尽或任务停止：沿用现有 attempt 重试/失败状态，不生成半成品 Finding。
- 新增规则块缺失或提示词版本未知：沿用现有基础提示词，不改变任务调度。

## 组件职责与文件范围

- `app/agents/prompts.py`：共享识别/审核规则、Collector 映射和 escalation 专用路线。
- `app/agents/escalate.py`：把类型专属深挖目标注入 `_brief()`。
- `app/orchestrator.py`：后门升级结果的新证据显著性检查。
- `app/dedup.py`：类型别名和归一化。
- `app/schemas.py`、`app/tools/schemas.py`：规范类型示例描述。
- `frontend/src/vulnerabilityTypes.js`：选项目录和默认选择。
- `tests/test_backdoor_prompt_policy.py`：各 profile 的识别、误报和审核规则契约。
- `tests/test_dedup.py`：别名归一化和同端点查重。
- `tests/test_escalation_service.py` 或对应 orchestrator 单测：新证据门槛与重复升级拦截。
- `frontend/tests/taskVulnerabilityTypes.test.js`：中文标签、默认选择和数组请求约束。

## 测试设计

### 提示词

- EduSRC worker 的 current、modern、legacy 和企业 worker 都包含规范类型、无缓存复取、跳转链、归属证据和 webshell 执行证据要求。
- EduSRC 与企业 reviewer 都包含 accepted/deepen/ignored 三档和等级规则。
- escalation prompt 包含查找初始入口、提交新根因类型和禁止重复原证据的要求。
- 提示词不出现“任何无关页面都必须 accepted”之类的无条件规则。

### 去重与升级

- 中文和英文别名都归一化为 `backdoor_compromised`。
- 同 host、同 endpoint、别名不同的 Finding 被识别为重复。
- 后门源 Finding 的相同 raw request/response 升级结果被判定为不显著。
- 新请求/响应且等级或影响面真实提升的结果允许进入新 Finding；无新证据的同标题结果被跳过。

### 前端

- 类型目录包含中文标签，默认数组包含新类型。
- 创建页和编辑弹窗仍使用共享 checkbox selector，并发送数组，不恢复逗号字符串。

## 验收标准

1. 新建任务默认包含 `backdoor_compromised`，已有任务类型数组不被自动修改。
2. 六类实际运行的 worker/reviewer profile 都能指导识别、取证和误报排除。
3. 已确认的篡改/后门 Finding 会进入现有 escalation 队列继续查入口。
4. 重复原始页面证据不会生成第二个升级 Finding；新根因证据可以正常进入审核。
5. 中文/英文别名可稳定去重，前端和 schema 示例使用规范值。
6. 新增测试通过，现有后端和前端测试无回归。
