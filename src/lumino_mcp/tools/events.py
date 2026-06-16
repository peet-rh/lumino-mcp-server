"""Event analysis tools — anomaly detection, progressive analysis, advanced analytics."""

import asyncio
import json
import logging
import statistics
from datetime import datetime
from typing import Any, Dict, List, Optional

from ..server import mcp
from .. import client
from .. import helpers
from ..helpers.events import get_namespace_events_internal
from ..helpers.event_analysis import (
    ProgressiveEventAnalyzer,
    MLPatternDetector,
    LogMetricsIntegrator,
    RunbookSuggestionEngine,
    classify_event_severity_from_string,
    classify_event_category_from_string,
    calculate_relevance_score_from_string,
    assess_overall_risk,
    generate_strategic_recommendations,
    generate_comprehensive_insights,
)

logger = logging.getLogger("lumino-mcp")


def _detect_anomalies_in_data(values, data_items, threshold=2.5):
    """Z-score anomaly detection on a list of numeric values."""
    if len(values) < 3:
        return {"anomalies_detected": False, "anomaly_details": None}

    mean = statistics.mean(values)
    std_dev = statistics.stdev(values) if len(values) > 1 else 0

    if std_dev == 0:
        return {"anomalies_detected": False, "anomaly_details": {"statistics": {"mean": mean, "std_dev": 0}}}

    anomalies = []
    for i, val in enumerate(values):
        z_score = (val - mean) / std_dev
        if abs(z_score) > threshold:
            anomalies.append({
                "value": val,
                "z_score": z_score,
                "original_data": data_items[i] if i < len(data_items) else {},
            })

    return {
        "anomalies_detected": len(anomalies) > 0,
        "anomaly_details": {
            "anomalies": anomalies,
            "statistics": {"mean": mean, "std_dev": std_dev, "count": len(values)},
        },
    }


@mcp.tool()
async def detect_anomalies(
    namespace: str,
    limit: int = 50,
    context: str | None = None,
) -> str:
    """Detect anomalies in Tekton PipelineRuns/TaskRuns using z-score statistical analysis.

    Identifies unusually long execution times (threshold: 2.5 standard deviations).
    """
    try:
        pr_resp = await client.call(
            "custom", "list_namespaced_custom_object",
            group="tekton.dev", version="v1",
            namespace=namespace, plural="pipelineruns",
            context=context,
        )

        pipeline_runs = []
        for pr in pr_resp.get("items", []):
            meta = pr.get("metadata", {})
            status = pr.get("status", {})
            conditions = status.get("conditions", [])
            start = status.get("startTime")
            completion = status.get("completionTime")

            duration_str = "unknown"
            if start and completion:
                try:
                    s = datetime.fromisoformat(start.replace("Z", "+00:00"))
                    c = datetime.fromisoformat(completion.replace("Z", "+00:00"))
                    dur = (c - s).total_seconds()
                    duration_str = f"{dur:.1f} seconds"
                except Exception:
                    pass

            pr_status = "Unknown"
            if conditions:
                last = conditions[-1]
                pr_status = last.get("reason", "Unknown") if last.get("status") == "True" else last.get("reason", "Failed")

            pipeline_runs.append({
                "name": meta.get("name", "unknown"),
                "status": pr_status,
                "started_at": start,
                "duration": duration_str,
            })

        pipeline_runs.sort(key=lambda x: x.get("started_at") or "", reverse=True)
        pipeline_runs = pipeline_runs[:limit]

        tr_resp = await client.call(
            "custom", "list_namespaced_custom_object",
            group="tekton.dev", version="v1",
            namespace=namespace, plural="taskruns",
            context=context,
        )

        all_task_runs = []
        for tr in tr_resp.get("items", []):
            meta = tr.get("metadata", {})
            status = tr.get("status", {})
            conditions = status.get("conditions", [])
            start = status.get("startTime")
            completion = status.get("completionTime")
            pr_label = meta.get("labels", {}).get("tekton.dev/pipelineRun", "")

            duration_str = "unknown"
            if start and completion:
                try:
                    s = datetime.fromisoformat(start.replace("Z", "+00:00"))
                    c = datetime.fromisoformat(completion.replace("Z", "+00:00"))
                    dur = (c - s).total_seconds()
                    duration_str = f"{dur:.1f} seconds"
                except Exception:
                    pass

            tr_status = "Unknown"
            if conditions:
                last = conditions[-1]
                tr_status = last.get("reason", "Unknown") if last.get("status") == "True" else last.get("reason", "Failed")

            all_task_runs.append({
                "name": meta.get("name", "unknown"),
                "status": tr_status,
                "duration": duration_str,
                "pipeline_run": pr_label,
            })

        pr_names = {pr["name"] for pr in pipeline_runs}

        pipeline_data = []
        for pr in pipeline_runs:
            if pr["status"] == "Succeeded" and pr["duration"] != "unknown":
                try:
                    val = pr["duration"].split()[0]
                    if val.replace(".", "", 1).isdigit():
                        pipeline_data.append({"name": pr["name"], "duration": float(val)})
                except (ValueError, IndexError):
                    continue

        task_data = []
        for tr in all_task_runs:
            if tr["pipeline_run"] not in pr_names:
                continue
            if tr["status"] == "Succeeded" and tr["duration"] != "unknown":
                try:
                    val = tr["duration"].split()[0]
                    if val.replace(".", "", 1).isdigit():
                        task_data.append({"name": tr["name"], "duration": float(val), "pipeline_run": tr["pipeline_run"]})
                except (ValueError, IndexError):
                    continue

        pr_result = _detect_anomalies_in_data([d["duration"] for d in pipeline_data], pipeline_data)
        tr_result = _detect_anomalies_in_data([d["duration"] for d in task_data], task_data)

        pipeline_anomalies = []
        if pr_result.get("anomalies_detected") and pr_result.get("anomaly_details"):
            stats = pr_result["anomaly_details"]["statistics"]
            for a in pr_result["anomaly_details"].get("anomalies", []):
                pipeline_anomalies.append({
                    "name": a.get("original_data", {}).get("name", "unknown"),
                    "reason": f"Unusually long duration (z-score: {a.get('z_score', 0):.2f})",
                    "actual_value": a.get("value"),
                    "expected_range": [stats["mean"] - 2 * stats["std_dev"], stats["mean"] + 2 * stats["std_dev"]],
                })

        task_anomalies = []
        if tr_result.get("anomalies_detected") and tr_result.get("anomaly_details"):
            stats = tr_result["anomaly_details"]["statistics"]
            for a in tr_result["anomaly_details"].get("anomalies", []):
                task_anomalies.append({
                    "name": a.get("original_data", {}).get("name", "unknown"),
                    "pipeline_run": a.get("original_data", {}).get("pipeline_run", "unknown"),
                    "reason": f"Unusually long duration (z-score: {a.get('z_score', 0):.2f})",
                    "actual_value": a.get("value"),
                    "expected_range": [stats["mean"] - 2 * stats["std_dev"], stats["mean"] + 2 * stats["std_dev"]],
                })

        return json.dumps({
            "pipeline_anomalies": pipeline_anomalies,
            "task_anomalies": task_anomalies,
        })

    except Exception as e:
        return json.dumps({"pipeline_anomalies": [], "task_anomalies": [], "error": str(e)})


@mcp.tool()
async def progressive_event_analysis(
    namespace: str,
    analysis_level: str = "overview",
    time_period: str | None = None,
    event_filters: dict | None = None,
    seed_event_id: str | None = None,
    focus_areas: list[str] | None = None,
    context: str | None = None,
) -> str:
    """Progressive event analysis with multiple detail levels and correlation detection.

    analysis_level: "overview", "detailed", "correlation", or "deep_dive".
    """
    if focus_areas is None:
        focus_areas = ["errors", "warnings", "failures"]

    try:
        events_data = await get_namespace_events_internal(
            client.call, namespace,
            time_period=time_period or "2h",
            context=context,
        )

        if not events_data.get("events"):
            return json.dumps({
                "namespace": namespace,
                "analysis_level": analysis_level,
                "message": "No events found for analysis",
                "suggestion": "Try a longer time period or different namespace",
            })

        classified_events = []
        for event_str in events_data["events"]:
            classified_events.append({
                "event_string": event_str,
                "severity": classify_event_severity_from_string(event_str),
                "category": classify_event_category_from_string(event_str),
                "relevance_score": calculate_relevance_score_from_string(event_str),
                "timestamp": datetime.now(),
                "token_estimate": len(event_str) // 4,
            })

        analyzer = ProgressiveEventAnalyzer(classified_events)

        result = {
            "namespace": namespace,
            "analysis_level": analysis_level,
            "total_events": len(classified_events),
            "time_period": time_period,
            "generated_at": datetime.now().isoformat(),
        }

        if analysis_level == "overview":
            result["overview"] = analyzer.get_overview()
        elif analysis_level == "detailed":
            result["detailed_analysis"] = analyzer.get_detailed_analysis(event_filters)
        elif analysis_level == "correlation":
            result["correlation_analysis"] = analyzer.get_correlation_analysis(seed_event_id)
        elif analysis_level == "deep_dive":
            result["overview"] = analyzer.get_overview()
            result["detailed_analysis"] = analyzer.get_detailed_analysis(event_filters)
            result["correlation_analysis"] = analyzer.get_correlation_analysis(seed_event_id)
        else:
            return json.dumps({"error": f"Unknown analysis level: {analysis_level}"})

        return json.dumps(result, default=str)

    except Exception as e:
        return json.dumps({"error": f"Progressive analysis failed: {e}"})


@mcp.tool()
async def advanced_event_analytics(
    namespace: str,
    time_period: str | None = None,
    include_ml_patterns: bool = True,
    include_runbook_suggestions: bool = True,
    analysis_depth: str = "comprehensive",
    context: str | None = None,
) -> str:
    """Advanced event analytics with pattern detection and runbook suggestions.

    analysis_depth: "basic", "comprehensive" (default), or "deep".
    """
    try:
        events_data = await get_namespace_events_internal(
            client.call, namespace,
            time_period=time_period or "2h",
            context=context,
        )

        if not events_data.get("events"):
            return json.dumps({
                "namespace": namespace,
                "analysis_type": "advanced_analytics",
                "message": "No events available for advanced analysis",
            })

        classified = []
        for event_str in events_data["events"]:
            classified.append({
                "event_string": event_str,
                "severity": classify_event_severity_from_string(event_str),
                "category": classify_event_category_from_string(event_str),
                "timestamp": datetime.now(),
                "relevance_score": calculate_relevance_score_from_string(event_str),
            })

        result = {
            "namespace": namespace,
            "analysis_type": "advanced_analytics",
            "analysis_depth": analysis_depth,
            "total_events_analyzed": len(classified),
            "time_period": time_period,
            "generated_at": datetime.now().isoformat(),
        }

        if include_ml_patterns:
            detector = MLPatternDetector(classified)
            result["ml_patterns"] = detector.detect_patterns()

        if include_runbook_suggestions:
            engine = RunbookSuggestionEngine(classified, result.get("ml_patterns", {}))
            result["runbook_suggestions"] = engine.suggest_runbooks()

        result["risk_assessment"] = assess_overall_risk(result)
        result["strategic_recommendations"] = generate_strategic_recommendations(result)

        return json.dumps(result, default=str)

    except Exception as e:
        return json.dumps({"error": f"Advanced analytics failed: {e}"})
