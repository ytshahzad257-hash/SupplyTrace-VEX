"""Build static dependency reachability graphs and context matrices."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from supplytrace.config import ProjectConfig, to_project_relative_path
from supplytrace.context.container_context import detect_container_files
from supplytrace.context.dependency_scope import dependency_scopes
from supplytrace.context.exposure import infer_exposure
from supplytrace.run_context import RunContext, write_json
from supplytrace.sbom.generator import discover_case_dirs
from supplytrace.sbom.parsers import components_from_manifests

from .js_analyzer import JsAnalysis, analyze_js_tree
from .py_analyzer import PythonAnalysis, analyze_python_tree, map_import_to_package


REACHABILITY_FIELDS: tuple[str, ...] = (
    "case_id",
    "package_name",
    "package_version",
    "ecosystem",
    "package_manager",
    "dependency_scope",
    "direct_or_transitive",
    "declared",
    "imported",
    "called",
    "reachability_status",
    "source_files",
    "reachability_confidence",
    "evidence_reason",
    "limitation_note",
)

CONTEXT_FIELDS: tuple[str, ...] = (
    "case_id",
    "package_name",
    "runtime_dependency",
    "dev_dependency",
    "direct_dependency",
    "transitive_dependency",
    "package_reachable",
    "containerized",
    "exposed_service",
    "fixed_version_available",
    "reachability_confidence",
    "context_confidence",
    "evidence_reason",
    "limitation_note",
)


def _write_csv(path: Path, rows: list[dict[str, object]], fields: tuple[str, ...]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(fields))
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field) for field in fields})


def _project_relative(config: ProjectConfig, value: object) -> str:
    text = str(value)
    return to_project_relative_path(Path(text), config) or text.replace("\\", "/")


def _relativize_analysis_paths(config: ProjectConfig, value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _relativize_analysis_paths(config, item) for key, item in value.items()}
    if isinstance(value, list):
        return [_relativize_analysis_paths(config, item) for item in value]
    if isinstance(value, str) and (":\\" in value or value.startswith(("/", "\\"))):
        return _project_relative(config, value)
    return value


def _load_fixed_version_evidence(config: ProjectConfig) -> dict[tuple[str, str], bool]:
    path = config.artifacts_dir / "normalized" / "findings_normalized.json"
    if not path.exists():
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    evidence: dict[tuple[str, str], bool] = {}
    for finding in payload.get("findings", []) if isinstance(payload.get("findings"), list) else []:
        if not isinstance(finding, dict):
            continue
        case_id = finding.get("case_id")
        package_name = finding.get("package_name")
        if not case_id or not package_name:
            continue
        key = (str(case_id), str(package_name).lower())
        evidence[key] = evidence.get(key, False) or bool(finding.get("fixed_version"))
    return evidence


def _python_import_index(analysis: PythonAnalysis, declared_names: set[str]) -> dict[str, dict[str, object]]:
    index: dict[str, dict[str, object]] = {}
    for item in analysis.imports:
        package = map_import_to_package(item.module, declared_names)
        if package is None:
            continue
        entry = index.setdefault(package.lower(), {"source_files": set(), "called": False, "imports": []})
        entry["source_files"].add(item.source_file)
        entry["called"] = bool(entry["called"]) or item.used_in_call
        entry["imports"].append(item.to_dict())
    return index


def _js_import_index(analysis: JsAnalysis) -> dict[str, dict[str, object]]:
    index: dict[str, dict[str, object]] = {}
    for item in analysis.imports:
        if item.package.startswith("."):
            continue
        entry = index.setdefault(item.package.lower(), {"source_files": set(), "called": False, "imports": []})
        entry["source_files"].add(item.source_file)
        entry["called"] = bool(entry["called"]) or item.used_in_call
        entry["imports"].append(item.to_dict())
    return index


def _merge_import_indexes(*indexes: dict[str, dict[str, object]]) -> dict[str, dict[str, object]]:
    merged: dict[str, dict[str, object]] = {}
    for index in indexes:
        for package, evidence in index.items():
            entry = merged.setdefault(package, {"source_files": set(), "called": False, "imports": []})
            entry["source_files"].update(evidence.get("source_files", set()))
            entry["called"] = bool(entry["called"]) or bool(evidence.get("called"))
            entry["imports"].extend(evidence.get("imports", []))
    return merged


def _status_for_dependency(
    *,
    component: dict[str, object],
    import_evidence: dict[str, object] | None,
    has_dynamic_imports: bool,
    containerized: bool,
) -> tuple[str, bool, str]:
    scope = str(component.get("dependency_scope") or component.get("scope") or "unknown")
    direct_or_transitive = str(component.get("direct_or_transitive") or "unknown")
    package_manager = str(component.get("package_manager") or "unknown")

    if package_manager == "dockerfile" or scope == "container_layer" or containerized and direct_or_transitive == "container_layer":
        return (
            "unknown",
            False,
            "container-layer package observed in local fixture metadata; static source analysis cannot prove package reachability",
        )
    if scope == "development":
        return "dev_only", False, "dependency is declared in a development dependency scope"
    if direct_or_transitive == "transitive":
        if import_evidence:
            return (
                "imported_not_called",
                False,
                "transitive package name appears in source imports, but static analysis does not prove vulnerable code execution",
            )
        return (
            "transitive_only",
            False,
            "dependency is present only as a transitive dependency in local manifests or lockfiles",
        )
    if import_evidence:
        if import_evidence.get("called"):
            return "reachable", True, "dependency is statically imported and used in a call expression"
        return "imported_not_called", False, "dependency is statically imported but no call expression was observed"
    if has_dynamic_imports:
        return "unknown", False, "dynamic import or require pattern present; static analysis cannot resolve target"
    return "declared_not_used", False, "dependency is declared in local manifests but no static import was observed"


def _confidence_for_status(status: str, *, imported: bool, called: bool, dynamic_imports: bool, containerized: bool) -> tuple[str, str]:
    if dynamic_imports or status == "unknown" or containerized:
        return (
            "low",
            "static analysis cannot fully resolve dynamic imports, container package execution, or runtime configuration",
        )
    if status == "reachable" and imported and called:
        return ("medium", "static import and call evidence observed; exploitability is not inferred")
    if status in {"dev_only", "declared_not_used", "transitive_only"}:
        return ("medium", "manifest and static-source evidence support the classification, with normal static-analysis limits")
    return ("low", "static evidence is partial")


def _component_to_dict(component: Any) -> dict[str, object]:
    return {
        "name": component.name,
        "version": component.version,
        "ecosystem": component.ecosystem,
        "package_manager": component.package_manager,
        "dependency_scope": component.dependency_scope,
        "direct_or_transitive": component.direct_or_transitive,
        "source_manifest": component.source_manifest,
    }


def analyze_case(config: ProjectConfig, case_dir: Path, fixed_version_evidence: dict[tuple[str, str], bool] | None = None) -> dict[str, object]:
    """Analyze one local case and return graph, matrix, and context rows."""

    components = [_component_to_dict(component) for component in components_from_manifests(case_dir)]
    declared_names = {str(component["name"]) for component in components}
    py_analysis = analyze_python_tree(case_dir)
    js_analysis = analyze_js_tree(case_dir)
    py_index = _python_import_index(py_analysis, declared_names)
    js_index = _js_import_index(js_analysis)
    import_index = _merge_import_indexes(py_index, js_index)
    dynamic_imports = [*py_analysis.dynamic_imports, *js_analysis.dynamic_imports]
    exposure = infer_exposure(case_dir)
    container = detect_container_files(case_dir)
    scopes = dependency_scopes(case_dir)
    fixed_versions = fixed_version_evidence or {}

    matrix_rows: list[dict[str, object]] = []
    context_rows: list[dict[str, object]] = []
    graph_nodes: list[dict[str, object]] = [
        {
            "id": case_dir.name,
            "type": "project",
            "label": case_dir.name,
        }
    ]
    graph_edges: list[dict[str, object]] = []

    for component in components:
        package_name = str(component["name"])
        package_key = package_name.lower()
        scope = str(component["dependency_scope"])
        direct_or_transitive = str(component["direct_or_transitive"])
        import_evidence = import_index.get(package_key)
        status, package_reachable, reason = _status_for_dependency(
            component=component,
            import_evidence=import_evidence,
            has_dynamic_imports=bool(dynamic_imports),
            containerized=bool(container["containerized"]),
        )
        source_files = sorted(import_evidence.get("source_files", set())) if import_evidence else []
        source_files_relative = [_project_relative(config, source_file) for source_file in source_files]
        reachability_confidence, limitation_note = _confidence_for_status(
            status,
            imported=bool(import_evidence),
            called=bool(import_evidence and import_evidence.get("called")),
            dynamic_imports=bool(dynamic_imports),
            containerized=bool(container["containerized"]),
        )
        matrix_row = {
            "case_id": case_dir.name,
            "package_name": package_name,
            "package_version": component["version"],
            "ecosystem": component["ecosystem"],
            "package_manager": component["package_manager"],
            "dependency_scope": scope,
            "direct_or_transitive": direct_or_transitive,
            "declared": True,
            "imported": bool(import_evidence),
            "called": bool(import_evidence and import_evidence.get("called")),
            "reachability_status": status,
            "source_files": ";".join(source_files_relative),
            "reachability_confidence": reachability_confidence,
            "evidence_reason": reason,
            "limitation_note": limitation_note,
        }
        matrix_rows.append(matrix_row)

        scope_context = scopes.get(package_name, {})
        context_row = {
            "case_id": case_dir.name,
            "package_name": package_name,
            "runtime_dependency": bool(scope_context.get("runtime_dependency", scope in {"runtime", "optional", "peer"})),
            "dev_dependency": bool(scope_context.get("dev_dependency", scope == "development")),
            "direct_dependency": bool(scope_context.get("direct_dependency", direct_or_transitive == "direct")),
            "transitive_dependency": bool(scope_context.get("transitive_dependency", direct_or_transitive in {"transitive", "container_layer"})),
            "package_reachable": package_reachable,
            "containerized": bool(container["containerized"]),
            "exposed_service": bool(exposure["exposed_service"]),
            "fixed_version_available": bool(fixed_versions.get((case_dir.name, package_key), False)),
            "reachability_confidence": reachability_confidence,
            "context_confidence": "low" if bool(container["containerized"]) or bool(dynamic_imports) else "medium",
            "evidence_reason": reason,
            "limitation_note": limitation_note,
        }
        context_rows.append(context_row)

        node_id = f"{case_dir.name}:{package_name}"
        graph_nodes.append(
            {
                "id": node_id,
                "type": "dependency",
                "label": package_name,
                "version": component["version"],
                "ecosystem": component["ecosystem"],
                "dependency_scope": scope,
                "direct_or_transitive": direct_or_transitive,
                "reachability_status": status,
            }
        )
        graph_edges.append(
            {
                "source": case_dir.name,
                "target": node_id,
                "relationship": direct_or_transitive,
                "source_manifest": component["source_manifest"],
            }
        )
        for source_file in source_files_relative:
            source_id = f"{case_dir.name}:source:{source_file}"
            if not any(node["id"] == source_id for node in graph_nodes):
                graph_nodes.append({"id": source_id, "type": "source_file", "label": source_file})
            graph_edges.append(
                {
                    "source": source_id,
                    "target": node_id,
                    "relationship": "imports",
                }
            )

    graph = {
        "case_id": case_dir.name,
        "nodes": graph_nodes,
        "edges": graph_edges,
        "python_analysis": _relativize_analysis_paths(config, py_analysis.to_dict()),
        "javascript_analysis": _relativize_analysis_paths(config, js_analysis.to_dict()),
        "dynamic_imports": _relativize_analysis_paths(config, dynamic_imports),
        "container_context": container,
        "exposure_context": exposure,
        "analysis_limits": [
            "Static import analysis does not prove exploitability.",
            "Dynamic imports, reflection, generated code, framework dispatch, and runtime configuration may be missed.",
            "Transitive dependency reachability is represented conservatively unless directly imported by source.",
        ],
    }

    return {
        "case_id": case_dir.name,
        "matrix_rows": matrix_rows,
        "context_rows": context_rows,
        "graph": graph,
        "dependencies": [
            {
                "name": row["package_name"],
                "version": row["package_version"],
                "ecosystem": row["ecosystem"],
                "declared": row["declared"],
                "imported_by_source": row["imported"],
                "called_by_source": row["called"],
                "reachability_status": row["reachability_status"],
                "dependency_scope": row["dependency_scope"],
                "direct_or_transitive": row["direct_or_transitive"],
            }
            for row in matrix_rows
        ],
    }


def analyze_reachability(config: ProjectConfig, context: RunContext) -> dict[str, object]:
    """Generate reachability and context artifacts for all local cases."""

    output_dir = config.artifacts_dir / "reachability"
    graph_dir = output_dir / "dependency_graphs"
    output_dir.mkdir(parents=True, exist_ok=True)
    graph_dir.mkdir(parents=True, exist_ok=True)

    fixed_version_evidence = _load_fixed_version_evidence(config)
    cases: list[dict[str, object]] = []
    matrix_rows: list[dict[str, object]] = []
    context_rows: list[dict[str, object]] = []

    for case_dir in discover_case_dirs(config):
        case_result = analyze_case(config, case_dir, fixed_version_evidence)
        cases.append(
            {
                "case_id": case_result["case_id"],
                "dependencies": case_result["dependencies"],
            }
        )
        matrix_rows.extend(case_result["matrix_rows"])
        context_rows.extend(case_result["context_rows"])
        write_json(graph_dir / f"{case_dir.name}.json", case_result["graph"])

    matrix_json = output_dir / "reachability_matrix.json"
    matrix_csv = output_dir / "reachability_matrix.csv"
    context_csv = output_dir / "context_enrichment.csv"
    write_json(
        matrix_json,
        {
            "run_id": context.run_id,
            "row_count": len(matrix_rows),
            "rows": matrix_rows,
            "claim_scope": "Reachability is based on static local source and manifest analysis only.",
        },
    )
    _write_csv(matrix_csv, matrix_rows, REACHABILITY_FIELDS)
    _write_csv(context_csv, context_rows, CONTEXT_FIELDS)

    payload = {
        "run_id": context.run_id,
        "case_count": len(cases),
        "dependency_count": len(matrix_rows),
        "reachability_matrix_json": to_project_relative_path(matrix_json, config),
        "reachability_matrix_csv": to_project_relative_path(matrix_csv, config),
        "context_enrichment_csv": to_project_relative_path(context_csv, config),
        "dependency_graph_dir": to_project_relative_path(graph_dir, config),
        "cases": cases,
        "claim_scope": "Reachability evidence is limited to local static analysis and does not claim exploitability.",
    }
    write_json(output_dir / "reachability_summary.json", payload)
    write_json(context.run_dir("reachability") / "reachability.json", payload)
    return payload
