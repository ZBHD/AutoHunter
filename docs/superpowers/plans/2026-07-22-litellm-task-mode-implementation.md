# LiteLLM 任务模式实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

Goal: 在现有 AutoHunter 24x7 任务编排中落地可扩展的 LiteLLM 网关发现、Secret 泄露识别、无 Key 调用验证和持续复查能力。

Architecture: 新增 src_type=litellm 和 mode_config，保留现有 Task、Target、Orchestrator、Review 主链路。LiteLLM 的查询、指纹、鉴权差异、Secret 提取、Provider 验证和推理验证放入 app/gateway_hunt/，通过 GatewayAsset、GatewaySecret、GatewayObservation 三张扩展表保存专项状态；LiteLLM Target 不进入通用 Worker。

Tech Stack: Python 3.11、FastAPI、Pydantic v2、SQLAlchemy async + SQLite/aiosqlite、httpx、pytest、Vue 3、Vite、Node 内置测试运行器。

---

## 文件地图

后端新增：

- app/gateway_hunt/schemas.py：候选、Probe、鉴权差异、Secret、验证和 FindingCandidate 类型。
- app/gateway_hunt/registry.py：GatewayProfile 注册表。
- app/gateway_hunt/query_planner.py：查询族、scope hash 和独立游标键。
- app/gateway_hunt/fingerprinter.py：产品指纹与挂载路径归一化。
- app/gateway_hunt/auth_diff.py：A/B/C 鉴权差异判定。
- app/gateway_hunt/secret_extractor.py：响应、JS、env、配置和错误内容中的 Secret 提取。
- app/gateway_hunt/inference_validator.py：模型列表解析和最小推理验证。
- app/gateway_hunt/credential_validators/：LiteLLM、OpenAI、Anthropic、Azure OpenAI、Gemini、Bedrock 验证器。
- app/gateway_hunt/profiles/base.py：Profile 接口。
- app/gateway_hunt/profiles/litellm.py：LiteLLM 路由、指纹和解析器。
- app/gateway_hunt/classifier.py：Finding 分类、严重性和 dedup key。
- app/gateway_hunt/service.py：扫描单个 GatewayAsset 的入口。
- app/api/gateway_hunt.py：资产、Secret、Observation、复查和导出 API。

后端修改：

- app/agents/prompts.py、app/api/dto.py、app/api/tasks.py、app/db/models.py、app/db/session.py
- app/agents/collector.py、app/orchestrator.py、app/main.py

前端新增/修改：

- frontend/src/litellmTaskMode.js
- frontend/src/components/task/LiteLlmAssetsPanel.vue
- frontend/src/components/task/LiteLlmSecretsPanel.vue
- frontend/src/components/task/LiteLlmObservationsPanel.vue
- frontend/src/views/CreateView.vue
- frontend/src/components/TaskEditModal.vue
- frontend/src/views/BoardView.vue
- frontend/src/taskViews.js
- frontend/src/api.js
- frontend/src/styles/operations.css

测试新增/修改：

- tests/test_litellm_task_mode.py
- tests/test_gateway_models.py
- tests/test_gateway_profile.py
- tests/test_gateway_auth_diff.py
- tests/test_gateway_secrets.py
- tests/test_gateway_validators.py
- tests/test_gateway_service.py
- tests/test_gateway_api.py
- tests/test_litellm_orchestrator.py
- tests/test_litellm_end_to_end.py
- frontend/tests/litellmTaskMode.test.js
- frontend/tests/litellmPanels.test.js

---

### Task 1: 任务类型与配置契约

Files:

- Create: tests/test_litellm_task_mode.py
- Modify: app/agents/prompts.py
- Modify: app/db/models.py
- Modify: app/db/session.py
- Modify: app/api/dto.py
- Modify: app/api/tasks.py

- [x] Step 1: 写失败测试

    def test_normalize_src_type_keeps_litellm():
        assert normalize_src_type("litellm") == "litellm"
        assert is_litellm_src("litellm") is True
        assert is_enterprise_src("litellm") is False

    def test_global_mode_defaults_to_full_checks():
        req = CreateTaskRequest(
            name="lite",
            src_type="litellm",
            target_source="fofa",
            mode_config={"scope_mode": "global"},
        )
        assert req.mode_config.validation.level == "full"
        assert req.mode_config.checks.anonymous_inference is True

    def test_targeted_mode_requires_anchor_or_manual_target():
        with pytest.raises(ValidationError):
            CreateTaskRequest(
                name="lite",
                src_type="litellm",
                target_source="manual",
                mode_config={"scope_mode": "targeted", "scope_anchors": []},
            )

- [x] Step 2: 运行失败测试

    pytest tests/test_litellm_task_mode.py -q

Expected: FAIL because litellm normalization and mode_config DTO do not exist.

- [x] Step 3: 实现最小契约

在 prompts.py 增加 is_litellm_src，normalize_src_type 明确保留 litellm，不得落入 edusrc。dto.py 增加 LiteLlmChecksDTO、LiteLlmValidationDTO、LiteLlmModeConfigDTO，extra=forbid，校验范围锚点长度、验证预算和复查周期。

CreateTaskRequest、UpdateTaskRequest、TaskResponse 增加 mode_config。服务端在 src_type=litellm 时由 checks 生成固定专项 vuln_types，忽略通用 Web 漏洞类型；未知 Profile、非法 source、超限预算返回 400。Task 增加 mode_config JSON 列，旧任务默认空对象。

- [x] Step 4: 运行通过测试

    pytest tests/test_litellm_task_mode.py -q

Expected: PASS.

- [x] Step 5: 提交

    git add tests/test_litellm_task_mode.py app/agents/prompts.py app/db/models.py app/db/session.py app/api/dto.py app/api/tasks.py
    git commit -m "功能：增加 LiteLLM 任务配置契约"

### Task 2: 专项数据模型与迁移

Files:

- Create: tests/test_gateway_models.py
- Modify: app/db/models.py
- Modify: app/db/session.py
- Modify: tests/test_db_migrations.py

- [x] Step 1: 写失败测试

    async def test_gateway_schema_is_idempotent(tmp_path):
        await init_test_database(tmp_path)
        await init_test_database(tmp_path)
        tables = await table_names(tmp_path)
        assert {"gateway_assets", "gateway_secrets", "gateway_observations"} <= tables

    async def test_observation_probe_is_unique(db):
        db.add(make_observation(asset_id="a", epoch=1, probe_id="models", auth_variant="none"))
        db.add(make_observation(asset_id="a", epoch=1, probe_id="models", auth_variant="none"))
        with pytest.raises(IntegrityError):
            await db.commit()

- [x] Step 2: 运行失败测试

    pytest tests/test_gateway_models.py tests/test_db_migrations.py -q

Expected: FAIL because the ORM classes and migrations do not exist.

- [x] Step 3: 实现模型与索引

在 models.py 实现 GatewayAsset、GatewaySecret、GatewayObservation。使用关系 Task.gateway_assets、Target.gateway_asset、GatewayAsset.secrets/observations。字段按设计文档实现，增加 origin_key、scan_state、scan_epoch、next_scan_at、validation_context、credential_group_id 和 raw evidence 引用。

在 session.py 增加 tasks.mode_config 列、三张表的唯一索引：

    CREATE UNIQUE INDEX IF NOT EXISTS ux_gateway_asset_task_origin
    ON gateway_assets(task_id, origin_key);

    CREATE UNIQUE INDEX IF NOT EXISTS ux_gateway_observation_probe
    ON gateway_observations(gateway_asset_id, scan_epoch, probe_id, auth_variant);

    CREATE UNIQUE INDEX IF NOT EXISTS ux_gateway_secret_asset_hash
    ON gateway_secrets(gateway_asset_id, secret_sha256);

补建 next_scan_at、Secret status、Observation time 索引。迁移必须可重复执行；删除 Task 时级联扩展表。

- [x] Step 4: 运行通过测试

    pytest tests/test_gateway_models.py tests/test_db_migrations.py -q

Expected: PASS.

- [x] Step 5: 提交

    git add tests/test_gateway_models.py tests/test_db_migrations.py app/db/models.py app/db/session.py
    git commit -m "数据：增加 LiteLLM 网关资产与 Secret 模型"

### Task 3: Profile、注册表、查询规划与指纹

Files:

- Create: app/gateway_hunt/__init__.py
- Create: app/gateway_hunt/schemas.py
- Create: app/gateway_hunt/registry.py
- Create: app/gateway_hunt/profiles/base.py
- Create: app/gateway_hunt/profiles/litellm.py
- Create: app/gateway_hunt/query_planner.py
- Create: app/gateway_hunt/fingerprinter.py
- Create: tests/test_gateway_profile.py

- [x] Step 1: 写失败测试

    def test_litellm_health_is_fingerprint_not_finding():
        profile = LiteLLMProfile()
        obs = HttpObservation(
            path="/health/liveliness",
            status_code=200,
            content_type="text/plain",
            body="I'm alive!",
        )
        result = profile.match_fingerprint([obs])
        assert result.status == "confirmed"
        assert result.public_only is True

    def test_same_host_different_mount_path_has_different_origin_key():
        assert origin_key("https://example.test/proxy") != origin_key(
            "https://example.test/api"
        )
        assert gateway_target_source(
            origin_key("https://example.test/proxy")
        ).startswith("gw:llm:")

- [x] Step 2: 运行失败测试

    pytest tests/test_gateway_profile.py -q

Expected: FAIL because Profile contracts and functions do not exist.

- [x] Step 3: 实现纯逻辑模块

GatewayProfile 只返回结构化 SearchSignature 和 ProbeSpec，不执行网络。LiteLLM Profile 登记：

    public probes: health_liveliness, health_liveness, health_readiness
    model probes: v1_models, models, model_info, v1_model_info
    inference probes: v1_chat_completions, chat_completions
    readonly admin probes: key_info, key_list, routes, config_list, config_callbacks

QueryPlanner.plan(scope_mode, anchors, engine, profile_id, state) 返回查询、cursor_key 和下一步状态；产品核心指纹来自 Profile，LLM 不能自由拼接。fingerprinter.py 负责默认端口、重复斜杠、尾斜杠、重定向和 mount path 归一化，并导出 gateway_target_source(origin_key)。该函数返回 gw:llm:<origin_hash8>，长度不超过 20，用于适配现有 (task_id, host, source) Target 唯一索引并保持同一挂载路径幂等；禁止随机 source。

- [x] Step 4: 运行通过测试

    pytest tests/test_gateway_profile.py -q

Expected: PASS.

- [x] Step 5: 提交

    git add app/gateway_hunt tests/test_gateway_profile.py
    git commit -m "功能：建立 LiteLLM 网关 Profile 与查询规划"

### Task 4: 鉴权差异与 Secret 提取

Files:

- Create: app/gateway_hunt/auth_diff.py
- Create: app/gateway_hunt/secret_extractor.py
- Create: tests/test_gateway_auth_diff.py
- Create: tests/test_gateway_secrets.py

- [x] Step 1: 写失败测试

    def test_auth_diff_distinguishes_anonymous_models():
        result = compare_auth_variants(
            no_auth=ResponseSample(200, "application/json", '{"data":[{"id":"gpt"}]}'),
            invalid_auth=ResponseSample(401, "application/json", '{"error":"invalid"}'),
            candidate=None,
            public_by_design=False,
        )
        assert result.kind == "anonymous_models"

    def test_extractor_keeps_plaintext_and_groups_bedrock_parts():
        artifacts = extract_secrets(
            "AWS_ACCESS_KEY_ID=AKIA_TEST\nAWS_SECRET_ACCESS_KEY=SECRET"
        )
        assert artifacts[0].value == "AKIA_TEST"
        assert artifacts[0].credential_group_id == artifacts[1].credential_group_id

- [x] Step 2: 运行失败测试

    pytest tests/test_gateway_auth_diff.py tests/test_gateway_secrets.py -q

Expected: FAIL because comparison and extraction functions do not exist.

- [x] Step 3: 实现模块

compare_auth_variants 返回 protected、anonymous_models、anonymous_inference、candidate_valid、inconclusive；比较状态码、Content-Type、JSON schema 和正文相似度；public_by_design 时返回 public_baseline。

secret_extractor.py 只产生 SecretArtifact，不调用网络、不让 LLM 生成 Secret。规则覆盖 LiteLLM Master/Virtual Key、OpenAI、Anthropic、Gemini、Azure、Bedrock 组合变量、DATABASE_URL、REDIS_URL、JWT secret 和通用 Bearer。过滤掩码、占位符、明显示例值；结果携带变量名、Provider、来源位置、上下文和组合凭据 group。

- [x] Step 4: 运行通过测试

    pytest tests/test_gateway_auth_diff.py tests/test_gateway_secrets.py -q

Expected: PASS.

- [x] Step 5: 提交

    git add app/gateway_hunt/auth_diff.py app/gateway_hunt/secret_extractor.py tests/test_gateway_auth_diff.py tests/test_gateway_secrets.py
    git commit -m "功能：增加 LiteLLM 鉴权差异与 Secret 提取"

### Task 5: Provider Validator 与最小推理

Files:

- Create: app/gateway_hunt/credential_validators/base.py
- Create: app/gateway_hunt/credential_validators/litellm.py
- Create: app/gateway_hunt/credential_validators/openai.py
- Create: app/gateway_hunt/credential_validators/anthropic.py
- Create: app/gateway_hunt/credential_validators/azure_openai.py
- Create: app/gateway_hunt/credential_validators/gemini.py
- Create: app/gateway_hunt/credential_validators/bedrock.py
- Create: app/gateway_hunt/inference_validator.py
- Create: tests/test_gateway_validators.py

- [x] Step 1: 写失败测试

    def test_inference_validator_requires_openai_shape():
        result = validate_minimal_inference(
            base_url="https://fixture.test",
            model="fixture-model",
            transport=FixtureTransport(
                chat_body='{"choices":[{"message":{"content":"ok"}}]}'
            ),
        )
        assert result.status == "valid"
        assert result.request_json["stream"] is False
        assert result.request_json["max_tokens"] == 1

    def test_http_200_error_json_is_not_valid_inference():
        result = validate_minimal_inference(
            base_url="https://fixture.test",
            model="fixture-model",
            transport=FixtureTransport(
                chat_body='{"error":{"message":"quota"}}'
            ),
        )
        assert result.status == "quota_exhausted"

- [x] Step 2: 运行失败测试

    pytest tests/test_gateway_validators.py -q

Expected: FAIL because validators and inference parser do not exist.

- [x] Step 3: 实现 Validator Registry

定义 CredentialValidator 协议：

    class CredentialValidator(Protocol):
        provider: str
        def validate(self, artifact, context) -> ValidationResult: ...

所有 Validator 使用连接 5 秒、读取 15 秒的 httpx 超时；每个凭据最多一次模型列表请求和一次最小推理。统一返回 valid、invalid、expired、quota_exhausted、permission_denied、rate_limited、network_error、unknown。Bedrock 只有组合 group 完整并有 region 才执行。推理解析拒绝只含 error 的 2xx、HTML、WAF 和空响应。

- [x] Step 4: 运行通过测试

    pytest tests/test_gateway_validators.py -q

Expected: PASS.

- [x] Step 5: 提交

    git add app/gateway_hunt/credential_validators app/gateway_hunt/inference_validator.py tests/test_gateway_validators.py
    git commit -m "功能：增加 LiteLLM Key 与最小推理验证"

### Task 6: 扫描服务、分类与 Evidence 持久化

Files:

- Create: app/gateway_hunt/classifier.py
- Create: app/gateway_hunt/service.py
- Create: tests/test_gateway_service.py
- Modify: app/raw_evidence.py（只复用既有 capture 创建入口）

- [x] Step 1: 写失败测试

    async def test_scan_asset_saves_checkpoint_and_secret(db, fixture_client):
        result = await scan_asset(asset_id="asset-1", session=db, client=fixture_client)
        asset = await db.get(GatewayAsset, "asset-1")
        assert asset.scan_state == "scheduled_recheck"
        assert asset.next_scan_at is not None
        assert result.secret_count == 1
        assert result.findings[0].vuln_type == "provider_api_key_leak"

- [x] Step 2: 运行失败测试

    pytest tests/test_gateway_service.py -q

Expected: FAIL because scan service and classifier do not exist.

- [x] Step 3: 实现扫描服务

scan_asset 固定按 fingerprinting、auth_baseline、exposure_scanning、secret_extracting、credential_validating、inference_validating、reviewing、scheduled_recheck 执行，并在每阶段保存 scan_state。先查询 Observation 唯一键，已完成 Probe 不重复发送；预算耗尽写 partial Observation 并安排下一轮。

classifier.py 只从结构化结果生成 FindingCandidate，严重性固定为：有效 Master/Provider Key 和 DSN 为严重；匿名推理、环境含真实凭据和管理面含 Secret 为高危；仅模型列表为低危；不可验证结果不生成正式 Finding。

入库复用现有 Finding dedup 和 Review 路径，完整请求/响应进入 RawEvidence；Event 只记录 ID、状态和计数。

- [x] Step 4: 运行通过测试

    pytest tests/test_gateway_service.py -q

Expected: PASS.

- [x] Step 5: 提交

    git add app/gateway_hunt/classifier.py app/gateway_hunt/service.py app/raw_evidence.py tests/test_gateway_service.py
    git commit -m "功能：实现 LiteLLM 扫描服务与结果分类"

### Task 7: Gateway API 与权限隔离

Files:

- Create: app/api/gateway_hunt.py
- Create: tests/test_gateway_api.py
- Modify: app/main.py
- Modify: app/security.py

- [x] Step 1: 写失败测试

    def test_observer_cannot_read_gateway_secrets(client, observer_headers):
        response = client.get(
            "/api/tasks/task-1/gateway/secrets",
            headers=observer_headers,
        )
        assert response.status_code == 403

    def test_readonly_can_read_plaintext_secret(client, readonly_headers):
        response = client.get(
            "/api/tasks/task-1/gateway/secrets",
            headers=readonly_headers,
        )
        assert response.status_code == 200
        assert response.json()["items"][0]["secret_value"] == "sk-fixture"

- [x] Step 2: 运行失败测试

    pytest tests/test_gateway_api.py -q

Expected: FAIL because the router and API methods do not exist.

- [x] Step 3: 实现路由

实现：

    GET  /api/tasks/{task_id}/gateway/summary
    GET  /api/tasks/{task_id}/gateway/assets
    GET  /api/tasks/{task_id}/gateway/secrets
    GET  /api/tasks/{task_id}/gateway/secrets/export?format=json|csv
    GET  /api/gateway/assets/{asset_id}
    GET  /api/gateway/assets/{asset_id}/observations
    POST /api/gateway/assets/{asset_id}/recheck
    POST /api/gateway/secrets/{secret_id}/revalidate

列表默认 limit=50、最大 200；搜索只匹配 host、URL、类型、Provider、变量名，不把 Secret 原值写入 SQL 条件。导出使用 StreamingResponse 和 Cache-Control: no-store。observer 在路由层拒绝，full/readonly 可读取原值，复查和重新验证仅 full。

- [x] Step 4: 运行通过测试

    pytest tests/test_gateway_api.py -q

Expected: PASS.

- [x] Step 5: 提交

    git add app/api/gateway_hunt.py app/main.py app/security.py tests/test_gateway_api.py
    git commit -m "接口：增加 LiteLLM 网关资产与 Secret API"

### Task 8: Collector 与 Orchestrator 接入

Files:

- Create: tests/test_litellm_orchestrator.py
- Modify: app/agents/collector.py
- Modify: app/orchestrator.py
- Modify: app/api/tasks.py

- [x] Step 1: 写失败测试

    async def test_litellm_target_uses_gateway_service(monkeypatch, runner):
        called = []
        monkeypatch.setattr(
            runner,
            "_run_worker",
            lambda *args: called.append("worker"),
        )
        monkeypatch.setattr(
            runner,
            "_run_gateway_asset",
            lambda *args: called.append("gateway"),
        )
        await runner._tick()
        assert called == ["gateway"]

覆盖 LiteLLM 候选创建 Target + GatewayAsset、跳过通用 prefilter/scorer/target_filter、到期资产原子重新入队、无 queued Target 仍保持 running。

- [x] Step 2: 运行失败测试

    pytest tests/test_litellm_orchestrator.py -q

Expected: FAIL because Collector and TaskRunner only know generic Worker.

- [x] Step 3: 接入 Collector

collector.refill 在 is_litellm_src 时委托 QueryPlanner；手动目标直接进入候选；自动结果转 GatewayCandidate。LiteLLM 不调用通用 prefilter、score、站点画像、EduSRC 标注和同款冷却，改用 Profile strength 和指纹置信度排序。使用 nested transaction 创建 Target 与 GatewayAsset，Target.source 必须由 gateway_target_source(origin_key) 生成，冲突候选回滚并继续；不得把多个 mount path 都写成 source=fofa。

- [x] Step 4: 接入 Orchestrator

在 _tick 中先调用 enqueue_due_assets。取到 LiteLLM Target 后调用 _spawn_gateway_scan，而不是 Worker。新增 _run_gateway_asset 顶层异常守卫；reclaim 支持网关 scanning。到期更新必须满足 Target status 为 done/dead/skipped、assigned_worker 为空且 next_scan_at 到期。未来 next_run_at/next_scan_at 存在时保持 running，只有用户 pause/stop 才退出。

- [x] Step 5: 运行通过测试

    pytest tests/test_litellm_orchestrator.py tests/test_task_queue.py tests/test_task_operations_api.py -q

Expected: PASS.

- [x] Step 6: 提交

    git add app/agents/collector.py app/orchestrator.py app/api/tasks.py tests/test_litellm_orchestrator.py
    git commit -m "编排：接入 LiteLLM 专项扫描与持续复查"

### Task 9: LiteLLM Reviewer 与审计事件

Files:

- Modify: app/agents/prompts.py
- Modify: app/agents/reviewer.py
- Create: tests/test_litellm_review_policy.py

- [x] Step 1: 写失败测试

    def test_litellm_reviewer_requires_structured_evidence():
        prompt = reviewer_system_prompt("litellm")
        assert "鉴权对照" in prompt
        assert "Provider 验证" in prompt
        assert "公开健康检查" in prompt
        assert "无 Key 可完成模型推理" in prompt

- [x] Step 2: 运行失败测试

    pytest tests/test_litellm_review_policy.py -q

Expected: FAIL because prompt factory falls back to EduSRC.

- [x] Step 3: 实现 Reviewer 分支

增加 LiteLLM Reviewer prompt：公开健康接口不成漏洞；匿名模型列表和匿名推理分开；Secret 必须有真实 Evidence 和 Validator 状态；请求/响应必须成对；伪 200、WAF、SPA、掩码值拒绝。reviewer_system_prompt 按 is_litellm_src 选择分支。复现只允许 Profile 生成的只读/最小推理请求。

- [x] Step 4: 运行通过测试

    pytest tests/test_litellm_review_policy.py tests/test_edusrc_prompt_policy.py tests/test_enterprise_prompt_policy.py -q

Expected: PASS.

- [x] Step 5: 提交

    git add app/agents/prompts.py app/agents/reviewer.py tests/test_litellm_review_policy.py
    git commit -m "审核：增加 LiteLLM 证据与复现策略"

### Task 10: 创建页与编辑弹窗

Files:

- Create: frontend/src/litellmTaskMode.js
- Create: frontend/tests/litellmTaskMode.test.js
- Modify: frontend/src/views/CreateView.vue
- Modify: frontend/src/components/TaskEditModal.vue

- [x] Step 1: 写失败测试

    it("builds a global LiteLLM payload with all checks", () => {
      const body = buildLiteLlmTaskPayload({
        name: "lite",
        scopeMode: "global",
      });
      expect(body.src_type).toBe("litellm");
      expect(body.mode_config.validation.level).toBe("full");
      expect(body.mode_config.checks.anonymous_inference).toBe(true);
      expect(body.vuln_types).toEqual([]);
    });

- [x] Step 2: 运行失败测试

    node --test frontend/tests/litellmTaskMode.test.js

Expected: FAIL because helper and form fields do not exist.

- [x] Step 3: 实现 helper 和表单

litellmTaskMode.js 导出 LITELLM_DEFAULT_CHECKS、buildLiteLlmTaskPayload(form)、validateLiteLlmForm(form)。创建页和编辑弹窗共用 helper。LiteLLM 选择后显示定向/全网分段控件、范围锚点、检测项复选框、复查周期和验证上限；搜索引擎、搜索 Key、内部 LLM 和并发复用现有控件。前端阻断全网无自动搜索和定向无范围/手动目标。

- [x] Step 4: 运行通过测试

    node --test frontend/tests/litellmTaskMode.test.js

Expected: PASS.

- [x] Step 5: 提交

    git add frontend/src/litellmTaskMode.js frontend/tests/litellmTaskMode.test.js frontend/src/views/CreateView.vue frontend/src/components/TaskEditModal.vue
    git commit -m "前端：增加 LiteLLM 任务创建与编辑表单"

### Task 11: API 客户端与 LiteLLM 看板

Files:

- Create: frontend/src/components/task/LiteLlmAssetsPanel.vue
- Create: frontend/src/components/task/LiteLlmSecretsPanel.vue
- Create: frontend/src/components/task/LiteLlmObservationsPanel.vue
- Create: frontend/tests/litellmPanels.test.js
- Modify: frontend/src/api.js
- Modify: frontend/src/taskViews.js
- Modify: frontend/src/views/BoardView.vue
- Modify: frontend/src/styles/operations.css

- [x] Step 1: 写失败测试

    it("requests gateway endpoints", async () => {
      await api.gatewaySecrets("task-1");
      assert.equal(
        fetchMock.mock.calls[0][0],
        "/api/tasks/task-1/gateway/secrets",
      );
    });

    it("does not expose LiteLLM tabs to observer", () => {
      expect(taskViewForRole("gateway-secrets", "observer")).toBe("board");
    });

- [x] Step 2: 运行失败测试

    node --test frontend/tests/litellmPanels.test.js

Expected: FAIL because API methods, views and panels do not exist.

- [x] Step 3: 实现 API 和面板

api.js 增加 gatewaySummary、gatewayAssets、gatewaySecrets、gatewaySecretExport、gatewayAsset、gatewayObservations、recheckGatewayAsset、revalidateGatewaySecret。BoardView 只有 task.src_type=litellm 且角色为 full/readonly 时显示网关资产、Secret、探测记录标签。Secret 面板默认显示原值，支持复制、状态筛选、重新验证、导出和加载/空/错误状态；observer 不渲染组件且不调用接口。

- [x] Step 4: 运行通过测试

    node --test frontend/tests/litellmPanels.test.js frontend/tests/operationsFoundation.test.js

Expected: PASS.

- [x] Step 5: 提交

    git add frontend/src/api.js frontend/src/taskViews.js frontend/src/views/BoardView.vue frontend/src/styles/operations.css frontend/src/components/task/LiteLlmAssetsPanel.vue frontend/src/components/task/LiteLlmSecretsPanel.vue frontend/src/components/task/LiteLlmObservationsPanel.vue frontend/tests/litellmPanels.test.js
    git commit -m "前端：增加 LiteLLM 资产与 Secret 看板"

### Task 12: Fixture、端到端验证与回归

Files:

- Create: tests/fixtures/litellm_proxy_fixture.py
- Create: tests/test_litellm_end_to_end.py
- Modify: tests/test_app_imports.py
- Modify: tests/test_task_operations_api.py
- Modify: tests/test_db_migrations.py

- [x] Step 1: 写失败集成测试

Fixture 提供正常鉴权、无 Master Key、env 暴露、SPA/WAF 全 200 四种状态。测试覆盖创建任务、Collector 入队、GatewayAsset 扫描、匿名推理 Finding、有效 Provider Key、复查重新入队、重启恢复和 observer 拒绝。

    async def test_full_litellm_flow_to_finding(app_client, litellm_fixture):
        task = await create_litellm_task(app_client, scope_mode="global")
        await start_and_drain_one_tick(task["id"])
        summary = (
            await app_client.get(
                f"/api/tasks/{task['id']}/gateway/summary"
            )
        ).json()
        assert summary["assets_confirmed"] == 1
        assert summary["anonymous_inference"] == 1

- [x] Step 2: 运行失败测试

    pytest tests/test_litellm_end_to_end.py -q

Expected: FAIL until all layers are registered and Orchestrator dispatches LiteLLM scans.

- [x] Step 3: 实现 Fixture 和回归断言

Fixture 的 /health/liveliness 返回公开 I'm alive!；受保护路由对无 Key/无效 Key 返回 401，对 fixture Key 返回合法模型和最小推理；无 Master Key 模式对模型列表和推理放行；env 返回固定测试值；SPA 模式所有路径返回相同 HTML。测试 Secret 使用 sk-fixture 等固定值，不读取真实环境变量。

补充 import smoke，确认新 router、模型和 Profile 可启动；现有 EduSRC/enterprise 任务的 mode_config={} 和 Worker 路径不变。

- [x] Step 4: 运行完整验证

    pytest -q
    npm --prefix frontend test
    npm --prefix frontend run build
    python -m compileall app

Expected: Python 测试、Node 内置测试、Vite build 和 compileall 全部 PASS。

- [x] Step 5: 检查运行日志

启动测试服务后执行创建、扫描、summary/assets/secrets 查询、停止和重启恢复。确认 TaskEvent、普通 logger 和错误摘要不出现 secret_value、Authorization 或 DSN 原文。

- [x] Step 6: 提交

    git add tests/fixtures/litellm_proxy_fixture.py tests/test_litellm_end_to_end.py tests/test_app_imports.py tests/test_task_operations_api.py tests/test_db_migrations.py
    git commit -m "测试：增加 LiteLLM 端到端 Fixture 与回归验证"

---

## 计划自检

- 规格覆盖：Task/DTO、迁移、Profile、查询游标、指纹、鉴权差异、Secret、Provider 验证、推理、扫描服务、Finding/Review、API、权限、看板、持续复查、错误退避和测试均有对应任务。
- 类型一致性：统一使用 litellm、mode_config、GatewayAsset、GatewaySecret、GatewayObservation、scan_epoch、next_scan_at 和 validation_status。
- 幂等性：Asset、Secret、Observation 唯一约束和复查条件更新分别在 Task 2、6、8 覆盖。
- 非目标：不改远端管理配置，不把健康接口单独算漏洞，不让 LiteLLM 进入通用 Worker，未扩展其他网关 Profile。
- 运行策略：每个任务先写失败测试，再实现最小行为；每个任务使用中文提交信息，最后执行 Python、前端单测和构建回归。
