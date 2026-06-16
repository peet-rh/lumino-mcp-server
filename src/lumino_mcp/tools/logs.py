"""Log analysis tools — summarize, search, stream, detect anomalies in pod logs."""

import asyncio
import json
import logging
import re
import time
from collections import Counter
from datetime import datetime
from typing import Any, Dict, List, Optional

from ..server import mcp
from .. import client
from .. import helpers
from ..helpers.log_analysis import (
    LogStreamProcessor,
    StrategySelector,
    extract_log_patterns,
    extract_timestamp,
    assess_log_severity,
    generate_streaming_summary,
    analyze_trending_patterns,
    generate_streaming_recommendations,
    combine_analysis_results,
    generate_supplementary_insights,
    generate_hybrid_recommendations,
    generate_focused_summary,
    get_strategy_selection_reason,
    truncate_to_token_limit,
    truncate_streaming_results,
)
from ..helpers.semantic_search import (
    interpret_semantic_query,
    determine_search_strategy,
    _get_target_namespaces,
    _search_pod_logs_semantically,
    _search_events_semantically,
    _search_tekton_resources_semantically,
    rank_results_by_semantic_relevance,
    identify_common_patterns,
    generate_semantic_suggestions,
)

logger = logging.getLogger("lumino-mcp")


async def _get_pod_logs(namespace, pod_name, core_api, tail_lines=200):
    """Get pod logs using our helpers."""
    return await helpers.get_all_pod_logs(pod_name, namespace, core_api, tail_lines=tail_lines)


def _estimate_tokens(text):
    return len(text) // 3 if text else 0


@mcp.tool()
async def analyze_logs(
    log_text: str,
    context: str | None = None,
) -> str:
    """Extract error patterns and insights from log text."""
    try:
        error_patterns = helpers.extract_error_patterns(log_text)
        categories = helpers.categorize_errors(log_text, error_patterns)
        root_cause = helpers.determine_root_cause(categories, error_patterns)
        summary = {
            "total_lines": len(log_text.split("\n")),
            "error_patterns": error_patterns[:20],
            "error_categories": categories,
            "root_cause": root_cause,
        }
        return json.dumps(summary)
    except Exception as e:
        return json.dumps({"error": f"Log analysis failed: {e}"})


@mcp.tool()
async def detect_log_anomalies(
    namespace: str,
    pod_name: str | None = None,
    time_range: str = "1h",
    sensitivity: float = 0.7,
    context: str | None = None,
) -> str:
    """Detect anomalies in pod logs using pattern-based analysis.

    Analyzes error frequency, repetitive patterns, timestamp gaps, and log level distribution.
    """
    try:
        client._ensure_clients()
        core_api = client._get_client("core_v1")

        target_pods = []
        if pod_name:
            target_pods = [pod_name]
        else:
            pods_resp = await client.call(
                "core_v1", "list_namespaced_pod",
                namespace=namespace, context=context,
            )
            for pod in pods_resp.items:
                phase = pod.status.phase if pod.status else "Unknown"
                if phase != "Succeeded":
                    target_pods.append(pod.metadata.name)
            target_pods = target_pods[:10]

        time_mapping = {"1h": 3600, "6h": 21600, "24h": 86400, "7d": 604800}
        since_seconds = time_mapping.get(time_range, 3600)

        anomalies = []
        total_lines_analyzed = 0

        for pod in target_pods:
            try:
                log_content = await asyncio.to_thread(
                    core_api.read_namespaced_pod_log,
                    name=pod, namespace=namespace,
                    since_seconds=since_seconds, tail_lines=500,
                )
                if not log_content:
                    continue

                lines = log_content.strip().split("\n")
                total_lines_analyzed += len(lines)

                error_lines = [l for l in lines if re.search(r'\b(error|exception|fatal|panic|fail)\b', l, re.IGNORECASE)]
                error_rate = len(error_lines) / max(len(lines), 1)
                if error_rate > (1 - sensitivity) * 0.3:
                    anomalies.append({
                        "pod": pod,
                        "type": "high_error_rate",
                        "severity": "high" if error_rate > 0.3 else "medium",
                        "description": f"Error rate {error_rate:.1%} ({len(error_lines)}/{len(lines)} lines)",
                        "sample_errors": error_lines[:3],
                    })

                line_counts = Counter(re.sub(r'\d+', 'N', l) for l in lines)
                for pattern, count in line_counts.most_common(3):
                    if count > len(lines) * 0.2 and count > 5:
                        anomalies.append({
                            "pod": pod,
                            "type": "repetitive_pattern",
                            "severity": "medium",
                            "description": f"Pattern repeated {count} times ({count/len(lines):.0%} of logs)",
                            "pattern": pattern[:200],
                        })

                level_counts = {"ERROR": 0, "WARN": 0, "INFO": 0, "DEBUG": 0}
                for line in lines:
                    m = re.search(r'\b(ERROR|WARN|WARNING|INFO|DEBUG)\b', line, re.IGNORECASE)
                    if m:
                        lvl = m.group(1).upper()
                        if lvl == "WARNING":
                            lvl = "WARN"
                        if lvl in level_counts:
                            level_counts[lvl] += 1

                if level_counts["ERROR"] > 0 and level_counts["ERROR"] > level_counts["INFO"] * 0.5:
                    anomalies.append({
                        "pod": pod,
                        "type": "abnormal_log_level_distribution",
                        "severity": "high",
                        "description": f"High ERROR:INFO ratio — {level_counts['ERROR']} errors vs {level_counts['INFO']} info",
                        "level_distribution": level_counts,
                    })

            except Exception as e:
                logger.debug(f"Error analyzing logs for pod {pod}: {e}")
                continue

        return json.dumps({
            "namespace": namespace,
            "pods_analyzed": len(target_pods),
            "total_lines_analyzed": total_lines_analyzed,
            "anomalies": anomalies,
            "total_anomalies": len(anomalies),
            "sensitivity": sensitivity,
        })

    except Exception as e:
        return json.dumps({"error": f"Log anomaly detection failed: {e}"})


@mcp.tool()
async def smart_summarize_pod_logs(
    namespace: str,
    pod_name: str,
    detail_level: str = "auto",
    max_tokens: int = 4000,
    context: str | None = None,
) -> str:
    """Adaptive pod log analysis — auto-selects detail level based on volume.

    detail_level: "brief", "standard", "detailed", or "auto".
    """
    try:
        client._ensure_clients()
        core_api = client._get_client("core_v1")

        tail = 500 if detail_level in ("auto", "brief") else 1000
        pod_logs = await _get_pod_logs(namespace, pod_name, core_api, tail_lines=tail)

        all_text = ""
        container_summaries = {}
        for container, log_text in pod_logs.items():
            if container.startswith("_"):
                continue
            cleaned = helpers.clean_pipeline_logs(log_text)
            all_text += cleaned + "\n"

            lines = cleaned.split("\n")
            errors = helpers.extract_error_patterns(cleaned)
            patterns = extract_log_patterns(cleaned)

            container_summaries[container] = {
                "total_lines": len(lines),
                "error_count": len(errors),
                "errors": errors[:5],
                "patterns": patterns[:5] if isinstance(patterns, list) else [],
            }

        total_lines = len(all_text.split("\n"))
        if detail_level == "auto":
            if total_lines < 100:
                detail_level = "detailed"
            elif total_lines < 500:
                detail_level = "standard"
            else:
                detail_level = "brief"

        summary = {
            "pod": pod_name,
            "namespace": namespace,
            "detail_level": detail_level,
            "total_lines": total_lines,
            "containers": container_summaries,
            "overall_errors": helpers.extract_error_patterns(all_text)[:10],
        }

        if _estimate_tokens(json.dumps(summary)) > max_tokens:
            for cs in container_summaries.values():
                cs["errors"] = cs["errors"][:3]
                cs.pop("patterns", None)
            summary["overall_errors"] = summary["overall_errors"][:5]
            summary["truncated"] = True

        return json.dumps(summary)

    except Exception as e:
        return json.dumps({"error": f"Pod log summarization failed: {e}"})


@mcp.tool()
async def stream_analyze_pod_logs(
    namespace: str,
    pod_name: str,
    chunk_size: int = 500,
    max_chunks: int = 10,
    context: str | None = None,
) -> str:
    """Streaming log analysis — processes large logs in chunks with pattern detection."""
    try:
        client._ensure_clients()
        core_api = client._get_client("core_v1")

        total_lines = chunk_size * max_chunks
        pod_logs = await _get_pod_logs(namespace, pod_name, core_api, tail_lines=total_lines)

        all_text = ""
        for container, log_text in pod_logs.items():
            if not container.startswith("_"):
                all_text += helpers.clean_pipeline_logs(log_text) + "\n"

        lines = all_text.strip().split("\n")
        chunk_results = []
        all_patterns = []

        for i in range(0, len(lines), chunk_size):
            chunk = lines[i:i + chunk_size]
            chunk_text = "\n".join(chunk)

            errors = helpers.extract_error_patterns(chunk_text)
            patterns = extract_log_patterns(chunk_text)
            severity = assess_log_severity(chunk_text)

            chunk_result = {
                "chunk_index": len(chunk_results),
                "lines": len(chunk),
                "line_range": f"{i+1}-{min(i+chunk_size, len(lines))}",
                "error_count": len(errors),
                "errors": errors[:5],
                "severity": severity,
            }
            chunk_results.append(chunk_result)
            if isinstance(patterns, list):
                all_patterns.extend(patterns)

            if len(chunk_results) >= max_chunks:
                break

        trending = analyze_trending_patterns(chunk_results) if chunk_results else {}
        recommendations = generate_streaming_recommendations(chunk_results) if chunk_results else []

        return json.dumps({
            "pod": pod_name,
            "namespace": namespace,
            "total_lines": len(lines),
            "chunks_processed": len(chunk_results),
            "chunk_results": chunk_results,
            "trending_patterns": trending,
            "recommendations": recommendations[:5] if isinstance(recommendations, list) else [],
        }, default=str)

    except Exception as e:
        return json.dumps({"error": f"Streaming log analysis failed: {e}"})


@mcp.tool()
async def analyze_pod_logs_hybrid(
    namespace: str,
    pod_name: str,
    strategy: str = "auto",
    max_tokens: int = 6000,
    context: str | None = None,
) -> str:
    """Hybrid log analysis — automatically selects best strategy based on log characteristics.

    strategy: "auto", "summary", "streaming", or "hybrid".
    """
    try:
        client._ensure_clients()
        core_api = client._get_client("core_v1")

        pod_logs = await _get_pod_logs(namespace, pod_name, core_api, tail_lines=2000)

        all_text = ""
        for container, log_text in pod_logs.items():
            if not container.startswith("_"):
                all_text += helpers.clean_pipeline_logs(log_text) + "\n"

        total_lines = len(all_text.strip().split("\n"))

        if strategy == "auto":
            if total_lines < 200:
                strategy = "summary"
            elif total_lines > 1000:
                strategy = "streaming"
            else:
                strategy = "hybrid"

        result = {
            "pod": pod_name,
            "namespace": namespace,
            "strategy_used": strategy,
            "total_lines": total_lines,
            "strategy_reason": get_strategy_selection_reason(strategy),
        }

        if strategy == "summary":
            errors = helpers.extract_error_patterns(all_text)
            categories = helpers.categorize_errors(all_text, errors)
            result["summary"] = {
                "error_patterns": errors[:10],
                "error_categories": categories,
                "root_cause": helpers.determine_root_cause(categories, errors),
            }

        elif strategy == "streaming":
            lines = all_text.strip().split("\n")
            chunk_size = 500
            chunk_results = []
            for i in range(0, len(lines), chunk_size):
                chunk = "\n".join(lines[i:i + chunk_size])
                errors = helpers.extract_error_patterns(chunk)
                chunk_results.append({
                    "chunk_index": len(chunk_results),
                    "lines": min(chunk_size, len(lines) - i),
                    "error_count": len(errors),
                    "errors": errors[:3],
                })
                if len(chunk_results) >= 10:
                    break
            result["streaming_analysis"] = chunk_results

        elif strategy == "hybrid":
            errors = helpers.extract_error_patterns(all_text)
            categories = helpers.categorize_errors(all_text, errors)

            lines = all_text.strip().split("\n")
            chunk_results = []
            for i in range(0, len(lines), 500):
                chunk = "\n".join(lines[i:i + 500])
                ch_errors = helpers.extract_error_patterns(chunk)
                chunk_results.append({
                    "chunk_index": len(chunk_results),
                    "error_count": len(ch_errors),
                })
                if len(chunk_results) >= 5:
                    break

            result["combined_analysis"] = {
                "error_patterns": errors[:10],
                "error_categories": categories,
                "root_cause": helpers.determine_root_cause(categories, errors),
                "chunk_overview": chunk_results,
            }

        if _estimate_tokens(json.dumps(result)) > max_tokens:
            result["truncated"] = True

        return json.dumps(result, default=str)

    except Exception as e:
        return json.dumps({"error": f"Hybrid log analysis failed: {e}"})


@mcp.tool()
async def semantic_log_search(
    query: str,
    namespaces: list[str] | None = None,
    time_range: str = "1h",
    max_results: int = 20,
    search_scope: list[str] | None = None,
    context: str | None = None,
) -> str:
    """Search logs, events, and Tekton resources using natural language queries.

    query: natural language description like "authentication failures" or "OOM kills".
    search_scope: list of ["logs", "events", "tekton"]. Default: all three.
    """
    if search_scope is None:
        search_scope = ["logs", "events", "tekton"]

    try:
        interpretation = interpret_semantic_query(query, time_range)
        strategy = determine_search_strategy(interpretation)

        client._ensure_clients()
        core_api = client._get_client("core_v1")

        target_ns = namespaces or []
        if not target_ns:
            ns_result = await client.call("core_v1", "list_namespace", context=context)
            target_ns = [ns.metadata.name for ns in ns_result.items][:20]

        all_results = []

        if "logs" in search_scope:
            for ns in target_ns[:5]:
                try:
                    pods_resp = await client.call(
                        "core_v1", "list_namespaced_pod",
                        namespace=ns, context=context,
                    )
                    for pod in pods_resp.items[:5]:
                        try:
                            pod_logs = await _get_pod_logs(ns, pod.metadata.name, core_api, tail_lines=200)
                            for container, log_text in pod_logs.items():
                                if container.startswith("_"):
                                    continue
                                cleaned = helpers.clean_pipeline_logs(log_text)
                                query_lower = query.lower()
                                keywords = interpretation.get("keywords", query_lower.split())
                                for i, line in enumerate(cleaned.split("\n")):
                                    if any(kw in line.lower() for kw in keywords):
                                        all_results.append({
                                            "type": "log",
                                            "namespace": ns,
                                            "pod": pod.metadata.name,
                                            "container": container,
                                            "line_number": i + 1,
                                            "content": line[:500],
                                            "relevance": sum(1 for kw in keywords if kw in line.lower()) / max(len(keywords), 1),
                                        })
                        except Exception:
                            continue
                except Exception:
                    continue

        if "events" in search_scope:
            for ns in target_ns[:10]:
                try:
                    from ..helpers.events import get_namespace_events_internal
                    events_data = await get_namespace_events_internal(
                        client.call, ns, time_period=time_range, context=context,
                    )
                    keywords = interpretation.get("keywords", query.lower().split())
                    for event_str in events_data.get("events", []):
                        if any(kw in event_str.lower() for kw in keywords):
                            all_results.append({
                                "type": "event",
                                "namespace": ns,
                                "content": event_str[:500],
                                "relevance": sum(1 for kw in keywords if kw in event_str.lower()) / max(len(keywords), 1),
                            })
                except Exception:
                    continue

        if "tekton" in search_scope:
            for ns in target_ns[:10]:
                try:
                    resp = await client.call(
                        "custom", "list_namespaced_custom_object",
                        group="tekton.dev", version="v1",
                        namespace=ns, plural="pipelineruns",
                        context=context,
                    )
                    keywords = interpretation.get("keywords", query.lower().split())
                    for pr in resp.get("items", []):
                        name = pr.get("metadata", {}).get("name", "")
                        conditions = pr.get("status", {}).get("conditions", [])
                        condition_text = " ".join(c.get("message", "") for c in conditions)
                        searchable = f"{name} {condition_text}".lower()
                        if any(kw in searchable for kw in keywords):
                            all_results.append({
                                "type": "pipelinerun",
                                "namespace": ns,
                                "name": name,
                                "status": conditions[-1].get("reason", "Unknown") if conditions else "Unknown",
                                "content": condition_text[:500],
                                "relevance": sum(1 for kw in keywords if kw in searchable) / max(len(keywords), 1),
                            })
                except Exception:
                    continue

        all_results.sort(key=lambda x: x.get("relevance", 0), reverse=True)
        all_results = all_results[:max_results]

        patterns = identify_common_patterns(all_results) if all_results else []
        suggestions = generate_semantic_suggestions(query, all_results) if all_results else []

        return json.dumps({
            "query": query,
            "interpretation": interpretation,
            "search_scope": search_scope,
            "results": all_results,
            "total_results": len(all_results),
            "patterns": patterns[:5] if isinstance(patterns, list) else [],
            "suggestions": suggestions[:5] if isinstance(suggestions, list) else [],
            "namespaces_searched": len(target_ns),
        }, default=str)

    except Exception as e:
        return json.dumps({"error": f"Semantic log search failed: {e}"})
