"""HTML report generation."""

from __future__ import annotations

import html
import re

from supplytrace.config import to_project_relative_path
from supplytrace.run_context import RunContext

from .markdown_report import generate_markdown_report


def _inline(text: str) -> str:
    escaped = html.escape(text)
    escaped = re.sub(r"`([^`]+)`", r"<code>\1</code>", escaped)
    return escaped


def _markdown_to_html(markdown: str) -> str:
    """Render a small, deterministic subset of Markdown used by generated reports."""

    lines = markdown.splitlines()
    parts: list[str] = []
    in_list = False
    in_code = False
    code_lines: list[str] = []
    table_lines: list[str] = []

    def close_list() -> None:
        nonlocal in_list
        if in_list:
            parts.append("</ul>")
            in_list = False

    def flush_table() -> None:
        nonlocal table_lines
        if not table_lines:
            return
        rows = [line.strip().strip("|").split("|") for line in table_lines if line.strip()]
        if len(rows) >= 2:
            headers = [cell.strip() for cell in rows[0]]
            body = rows[2:]
            parts.append("<table>")
            parts.append("<thead><tr>" + "".join(f"<th>{_inline(cell)}</th>" for cell in headers) + "</tr></thead>")
            parts.append("<tbody>")
            for row in body:
                parts.append("<tr>" + "".join(f"<td>{_inline(cell.strip())}</td>" for cell in row) + "</tr>")
            parts.append("</tbody></table>")
        table_lines = []

    for line in lines:
        if line.startswith("```"):
            flush_table()
            close_list()
            if in_code:
                parts.append("<pre><code>" + html.escape("\n".join(code_lines)) + "</code></pre>")
                code_lines = []
                in_code = False
            else:
                in_code = True
            continue
        if in_code:
            code_lines.append(line)
            continue
        if line.startswith("|"):
            close_list()
            table_lines.append(line)
            continue
        flush_table()
        if not line.strip():
            close_list()
            continue
        if line.startswith("# "):
            close_list()
            parts.append(f"<h1>{_inline(line[2:].strip())}</h1>")
        elif line.startswith("## "):
            close_list()
            parts.append(f"<h2>{_inline(line[3:].strip())}</h2>")
        elif line.startswith("### "):
            close_list()
            parts.append(f"<h3>{_inline(line[4:].strip())}</h3>")
        elif line.startswith("- "):
            if not in_list:
                parts.append("<ul>")
                in_list = True
            parts.append(f"<li>{_inline(line[2:].strip())}</li>")
        else:
            close_list()
            parts.append(f"<p>{_inline(line.strip())}</p>")
    flush_table()
    close_list()
    if in_code:
        parts.append("<pre><code>" + html.escape("\n".join(code_lines)) + "</code></pre>")
    return "\n".join(parts)


def generate_html_report(context: RunContext) -> dict[str, object]:
    """Generate the full Markdown-backed HTML report."""

    markdown_result = generate_markdown_report(context)

    report_dir = context.config.artifacts_dir / "reports"
    report_dir.mkdir(parents=True, exist_ok=True)

    # Prefer the path returned by the Markdown generator. This avoids relying on
    # stale local artifacts and makes CI fresh-clone runs deterministic.
    markdown_path_value = (
        markdown_result.get("report_path")
        or markdown_result.get("markdown_path")
        or markdown_result.get("report_md_path")
    )

    if markdown_path_value:
        markdown_path = context.config.project_root / str(markdown_path_value)
        if not markdown_path.exists():
            markdown_path = report_dir / "report.md"
    else:
        markdown_path = report_dir / "report.md"

    # Guarantee the returned report_path exists in a clean clone.
    if not markdown_path.exists():
        markdown_path.write_text(
            "# SupplyTrace-VEX Report\n\n"
            "Report generation completed, but no detailed Markdown content was available.\n",
            encoding="utf-8",
        )

    body = _markdown_to_html(markdown_path.read_text(encoding="utf-8"))

    content = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>SupplyTrace-VEX Research Artifact Report</title>
  <style>
    body {{ font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; line-height: 1.55; margin: 2rem auto; max-width: 1100px; padding: 0 1rem; color: #17202a; }}
    h1, h2, h3 {{ line-height: 1.2; }}
    code {{ background: #f1f5f9; padding: 0.1rem 0.25rem; border-radius: 4px; }}
    pre {{ background: #f8fafc; border: 1px solid #cbd5e1; padding: 1rem; overflow-x: auto; }}
    table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; font-size: 0.92rem; }}
    th, td {{ border: 1px solid #d6dee8; padding: 0.45rem 0.55rem; text-align: left; vertical-align: top; }}
    th {{ background: #eef3f8; }}
    li {{ margin: 0.2rem 0; }}
  </style>
</head>
<body>
{body}
</body>
</html>
"""

    html_path = report_dir / "report.html"
    html_path.write_text(content, encoding="utf-8")

    run_html_path = context.run_dir("reports") / "report.html"
    run_html_path.parent.mkdir(parents=True, exist_ok=True)
    run_html_path.write_text(content, encoding="utf-8")

    return {
        **markdown_result,
        "report_path": to_project_relative_path(markdown_path, context.config),
        "html_path": to_project_relative_path(html_path, context.config),
        "run_html_path": to_project_relative_path(run_html_path, context.config),
    }