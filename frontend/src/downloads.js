const INVALID_FILENAME = /[<>:"/\\|?*\u0000-\u001f：]+/g;

function filenamePart(value) {
  return String(value || "")
    .normalize("NFKC")
    .replace(INVALID_FILENAME, "-")
    .replace(/\s+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^[.-]+|[.-]+$/g, "")
    .slice(0, 96);
}

export function markdownReportFilename(finding = {}, index = 0) {
  const editedOwner = finding.review?.user_edits?.owner;
  const unit = filenamePart(finding.edu_school || finding.owner || editedOwner) || "待确认单位";
  const type = filenamePart(finding.vuln_type) || "未分类漏洞";
  const stem = `${unit}-${type}`;
  return `${stem}.md`;
}

export function reportsForDownload(scope, { all = [], filtered = [] } = {}) {
  if (scope === "all") return all;
  if (scope === "filtered") return filtered;
  throw new TypeError(`Unknown download scope: ${scope}`);
}

export function saveMarkdownFile({ filename, content }) {
  const blob = new Blob([content], { type: "text/markdown;charset=utf-8" });
  const href = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = href;
  anchor.download = filename;
  anchor.hidden = true;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(href);
}

const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export async function downloadMarkdownReports(findings, options = {}) {
  const rows = Array.isArray(findings) ? findings : [];
  const render = options.render;
  const save = options.save || saveMarkdownFile;
  const pause = options.pause || (() => wait(options.delayMs ?? 120));
  if (typeof render !== "function") throw new TypeError("render must be a function");

  let downloaded = 0;
  for (let index = 0; index < rows.length; index += 1) {
    const finding = rows[index];
    const content = await render(finding, index);
    await save({
      filename: markdownReportFilename(finding, index),
      content: String(content ?? ""),
      finding,
    });
    downloaded += 1;
    if (index < rows.length - 1) await pause();
  }
  return { downloaded };
}
