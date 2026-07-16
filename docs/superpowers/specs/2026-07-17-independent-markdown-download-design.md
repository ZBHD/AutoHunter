# 独立 Markdown 下载与 AI 未采纳批量操作设计

## 目标

所有批量下载入口都输出“一条漏洞一个 `.md` 文件”，下载版报告不包含“AI 审核结论”和“EDUSRC 自动填充 JSON”；AI 未采纳列表增加同样的多选、状态筛选和批量下载能力。

## 方案

- 在 `report.js` 保留完整阅读报告 `buildReportMd`，新增下载专用 `buildDownloadReportMd`，复用同一事实数据渲染核心但省略审核结论与 EduSRC JSON。
- 复审队列使用既有 `downloadMarkdownReports` 逐条调用浏览器下载，不再拼接单个合并文件。
- 原始发现下载改用 `buildDownloadReportMd`，继续支持跨页选中和已下载标记。
- AI 未采纳列表沿用现有分页数据，新增 ID Set 选择、已下载/未下载服务端筛选、已选/当前筛选/全部范围，并复用逐条下载工具与标记接口。
- 归档接口增加 `download_status` 参数，状态仍由 `findings.markdown_downloaded_at` 持久化。

## 失败处理

每个文件成功触发下载后才记录 ID；批量标记接口只提交成功 ID。取消或单条失败不会把未成功文件标为已下载。

## 验证

- Markdown 渲染测试确认下载版不含两段排除内容。
- 前端契约测试确认三个列表均使用逐条下载工具，并覆盖 AI 未采纳多选/状态筛选。
- 后端测试覆盖归档下载状态筛选。
