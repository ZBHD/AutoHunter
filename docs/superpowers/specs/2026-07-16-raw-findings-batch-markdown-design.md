# 原始发现多选与 Markdown 批量下载设计

## 目标

在任务页“原始发现”列表增加跨页多选、批量下载 Markdown，以及可持久化的“已下载/未下载”筛选。

## 交互

- 每条 Finding 左侧显示复选框；工具栏提供“全选当前结果”“清空选择”和已选数量。
- 选择通过 Finding ID 集合保存，翻页与搜索不会丢失；清空搜索或刷新后仍能识别已选项。
- 下载弹窗支持“已选项”“当前搜索结果”“当前任务全部”三种范围；没有已选项时禁用“已选项”。
- 下载成功后只标记成功的 Finding；刷新列表后“全部/已下载/未下载”筛选立即反映结果。
- 点击行主体仍打开报告详情，点击复选框不会打开详情。

## 数据与接口

- `findings.markdown_downloaded_at` 为可空时间字段；启动时通过现有轻量迁移自动补列。
- 原始发现列表返回 `downloaded` 与 `markdown_downloaded_at`，接受 `download_status=downloaded|pending` 查询参数。
- 新增批量标记接口，接收 Finding ID 列表，仅允许当前任务的 Finding；服务端设置下载时间并返回成功 ID。

## 下载流程

前端按范围分页读取 compact Finding，再逐条读取完整 Finding，使用既有 `buildReportMd` 和 `downloadMarkdownReports` 生成独立 `.md` 文件。单个文件下载成功后记录 ID；整批完成后调用批量标记接口，失败或取消的条目保持未下载。

## 验证

- 后端 API 测试覆盖下载状态过滤、批量标记的任务隔离与返回字段。
- 前端静态契约测试覆盖多选状态、三种下载范围、状态筛选和成功回写。
- 运行前端 `npm test`、`npm run build` 与相关 Python 测试。
