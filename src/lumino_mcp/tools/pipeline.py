"""Tekton pipeline tools — list, find, trace PipelineRuns and TaskRuns."""

import asyncio
import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from ..server import mcp
from .. import client
from .. import helpers
from ..helpers.resource_topology import (
    correlate_pipeline_events,
    track_artifacts,
    analyze_bottlenecks,
)

logger = logging.getLogger("lumino-mcp")


def _calc_duration(start: Optional[str], completion: Optional[str]) -> tuple:
    """Calculate duration between two ISO timestamps. Returns (str, float|None)."""
    if not start:
        return "unknown", None
    try:
        s = datetime.fromisoformat(start.replace("Z", "+00:00"))
        if completion:
            c = datetime.fromisoformat(completion.replace("Z", "+00:00"))
        else:
            c = datetime.now(s.tzinfo)
        dur = (c - s).total_seconds()
        if dur < 60:
            return f"{dur:.1f}s", dur
        elif dur < 3600:
            return f"{dur/60:.1f}m", dur
        return f"{dur/3600:.1f}h", dur
    except Exception:
        return "unknown", None


def _extract_pr_status(conditions: list) -> str:
    if conditions:
        last = conditions[-1]
        return last.get("reason", "Unknown") if last.get("status") == "True" else last.get("reason", "Failed")
    return "Unknown"


@mcp.tool()
async def list_pipelineruns(
    namespace: str,
    context: str | None = None,
) -> str:
    """List Tekton PipelineRuns in a namespace with status and timing details."""
    try:
        resp = await client.call(
            "custom", "list_namespaced_custom_object",
            group="tekton.dev", version="v1",
            namespace=namespace, plural="pipelineruns",
            context=context,
        )

        result = []
        for pr in resp.get("items", []):
            meta = pr.get("metadata", {})
            spec = pr.get("spec", {})
            status = pr.get("status", {})
            labels = meta.get("labels", {})

            pipeline_name = (
                (spec.get("pipelineRef") or {}).get("name")
                or labels.get("tekton.dev/pipeline")
                or labels.get("pipelines.tekton.dev/pipeline")
                or "unknown"
            )

            conditions = status.get("conditions", [])
            pr_status = _extract_pr_status(conditions)
            start = status.get("startTime")
            completion = status.get("completionTime")
            dur_str, dur_sec = _calc_duration(start, completion)

            result.append({
                "name": meta.get("name", "unknown"),
                "pipeline": pipeline_name,
                "status": pr_status,
                "started_at": start,
                "completed_at": completion,
                "duration": dur_str,
                "duration_seconds": dur_sec,
            })

        result.sort(key=lambda x: x.get("started_at") or "", reverse=True)
        return json.dumps({"pipeline_runs": result, "total": len(result)})

    except Exception as e:
        return json.dumps({"error": f"Failed to list PipelineRuns: {e}"})


@mcp.tool()
async def list_taskruns(
    namespace: str,
    pipeline_run: str | None = None,
    context: str | None = None,
) -> str:
    """List Tekton TaskRuns in a namespace, optionally filtered by PipelineRun."""
    try:
        resp = await client.call(
            "custom", "list_namespaced_custom_object",
            group="tekton.dev", version="v1",
            namespace=namespace, plural="taskruns",
            context=context,
        )

        result = []
        for tr in resp.get("items", []):
            meta = tr.get("metadata", {})
            spec = tr.get("spec", {})
            status = tr.get("status", {})
            labels = meta.get("labels", {})

            pr_label = labels.get("tekton.dev/pipelineRun", "")
            if pipeline_run and pr_label != pipeline_run:
                continue

            task_name = (
                (spec.get("taskRef") or {}).get("name")
                or labels.get("tekton.dev/pipelineTask")
                or labels.get("tekton.dev/task")
                or "unknown"
            )

            conditions = status.get("conditions", [])
            tr_status = _extract_pr_status(conditions)
            start = status.get("startTime")
            completion = status.get("completionTime")
            dur_str, dur_sec = _calc_duration(start, completion)

            result.append({
                "name": meta.get("name", "unknown"),
                "task": task_name,
                "pipeline_run": pr_label or None,
                "status": tr_status,
                "started_at": start,
                "completed_at": completion,
                "duration": dur_str,
                "duration_seconds": dur_sec,
            })

        result.sort(key=lambda x: x.get("started_at") or "", reverse=True)
        return json.dumps({"task_runs": result, "total": len(result)})

    except Exception as e:
        return json.dumps({"error": f"Failed to list TaskRuns: {e}"})


@mcp.tool()
async def find_pipeline(
    pattern: str,
    namespaces: list[str] | None = None,
    include_task_runs: bool = False,
    limit: int = 100,
    context: str | None = None,
) -> str:
    """Find pipelines matching a pattern across namespaces.

    pattern: substring match on pipeline or pipelinerun name.
    """
    try:
        target_ns = namespaces or []
        if not target_ns:
            ns_result = await client.call("core_v1", "list_namespace", context=context)
            pipeline_keywords = ["tenant", "pipeline", "tekton", "cicd", "build", "konflux"]
            all_ns = [ns.metadata.name for ns in ns_result.items]
            prioritized = [ns for ns in all_ns if any(kw in ns.lower() for kw in pipeline_keywords)]
            others = [ns for ns in all_ns if ns not in prioritized]
            target_ns = (prioritized + others)[:50]

        pattern_lower = pattern.lower()
        matches = []

        for ns in target_ns:
            try:
                resp = await client.call(
                    "custom", "list_namespaced_custom_object",
                    group="tekton.dev", version="v1",
                    namespace=ns, plural="pipelineruns",
                    context=context,
                )
                for pr in resp.get("items", []):
                    meta = pr.get("metadata", {})
                    name = meta.get("name", "")
                    labels = meta.get("labels", {})
                    pipeline_name = labels.get("tekton.dev/pipeline", "")

                    if pattern_lower in name.lower() or pattern_lower in pipeline_name.lower():
                        status = pr.get("status", {})
                        conditions = status.get("conditions", [])
                        start = status.get("startTime")
                        completion = status.get("completionTime")
                        dur_str, _ = _calc_duration(start, completion)

                        match = {
                            "namespace": ns,
                            "name": name,
                            "pipeline": pipeline_name or "unknown",
                            "status": _extract_pr_status(conditions),
                            "started_at": start,
                            "duration": dur_str,
                        }

                        if include_task_runs:
                            try:
                                tr_resp = await client.call(
                                    "custom", "list_namespaced_custom_object",
                                    group="tekton.dev", version="v1",
                                    namespace=ns, plural="taskruns",
                                    label_selector=f"tekton.dev/pipelineRun={name}",
                                    context=context,
                                )
                                match["task_runs"] = len(tr_resp.get("items", []))
                            except Exception:
                                match["task_runs"] = "unknown"

                        matches.append(match)

                        if len(matches) >= limit:
                            break
            except Exception:
                continue

            if len(matches) >= limit:
                break

        matches.sort(key=lambda x: x.get("started_at") or "", reverse=True)
        return json.dumps({
            "pattern": pattern,
            "matches": matches,
            "total": len(matches),
            "namespaces_searched": len(target_ns),
        })

    except Exception as e:
        return json.dumps({"error": f"Pipeline search failed: {e}"})


@mcp.tool()
async def get_tekton_pipeline_runs_status(
    namespaces: list[str] | None = None,
    limit_per_namespace: int = 20,
    context: str | None = None,
) -> str:
    """Get cluster-wide Tekton PipelineRun status summary across namespaces."""
    try:
        target_ns = namespaces or []
        if not target_ns:
            ns_result = await client.call("core_v1", "list_namespace", context=context)
            target_ns = [ns.metadata.name for ns in ns_result.items]

        summary = {"total": 0, "succeeded": 0, "failed": 0, "running": 0, "other": 0}
        ns_details = {}

        for ns in target_ns:
            try:
                resp = await client.call(
                    "custom", "list_namespaced_custom_object",
                    group="tekton.dev", version="v1",
                    namespace=ns, plural="pipelineruns",
                    limit=limit_per_namespace,
                    context=context,
                )
                items = resp.get("items", [])
                if not items:
                    continue

                ns_summary = {"total": len(items), "succeeded": 0, "failed": 0, "running": 0}
                for pr in items:
                    conditions = pr.get("status", {}).get("conditions", [])
                    status = _extract_pr_status(conditions)
                    if status == "Succeeded":
                        ns_summary["succeeded"] += 1
                        summary["succeeded"] += 1
                    elif status in ("Failed", "Error", "PipelineRunTimeout"):
                        ns_summary["failed"] += 1
                        summary["failed"] += 1
                    elif status in ("Running", "Started", "Pending"):
                        ns_summary["running"] += 1
                        summary["running"] += 1
                    else:
                        summary["other"] += 1

                summary["total"] += ns_summary["total"]
                ns_details[ns] = ns_summary

            except Exception:
                continue

        return json.dumps({
            "cluster_summary": summary,
            "namespaces": ns_details,
            "namespaces_with_pipelines": len(ns_details),
        })

    except Exception as e:
        return json.dumps({"error": f"Pipeline status check failed: {e}"})


@mcp.tool()
async def list_recent_pipeline_runs(
    limit: int = 10,
    context: str | None = None,
) -> str:
    """List recent PipelineRuns across all namespaces."""
    try:
        ns_result = await client.call("core_v1", "list_namespace", context=context)
        pipeline_keywords = ["tenant", "pipeline", "tekton", "cicd", "build", "konflux"]
        all_ns = [ns.metadata.name for ns in ns_result.items]
        prioritized = [ns for ns in all_ns if any(kw in ns.lower() for kw in pipeline_keywords)]
        others = [ns for ns in all_ns if ns not in prioritized]
        target_ns = (prioritized + others)[:30]

        all_runs = []
        for ns in target_ns:
            try:
                resp = await client.call(
                    "custom", "list_namespaced_custom_object",
                    group="tekton.dev", version="v1",
                    namespace=ns, plural="pipelineruns",
                    limit=limit,
                    context=context,
                )
                for pr in resp.get("items", []):
                    meta = pr.get("metadata", {})
                    status = pr.get("status", {})
                    conditions = status.get("conditions", [])
                    labels = meta.get("labels", {})
                    start = status.get("startTime")
                    completion = status.get("completionTime")
                    dur_str, _ = _calc_duration(start, completion)

                    all_runs.append({
                        "namespace": ns,
                        "name": meta.get("name", "unknown"),
                        "pipeline": labels.get("tekton.dev/pipeline", "unknown"),
                        "status": _extract_pr_status(conditions),
                        "started_at": start,
                        "duration": dur_str,
                    })
            except Exception:
                continue

        all_runs.sort(key=lambda x: x.get("started_at") or "", reverse=True)
        return json.dumps({
            "recent_runs": all_runs[:limit],
            "total_found": len(all_runs),
            "namespaces_searched": len(target_ns),
        })

    except Exception as e:
        return json.dumps({"error": f"Failed to list recent pipeline runs: {e}"})


@mcp.tool()
async def pipeline_tracer(
    trace_identifier: str,
    trace_type: str = "custom",
    namespaces: list[str] | None = None,
    include_artifacts: bool = True,
    start_time: str | None = None,
    end_time: str | None = None,
    context: str | None = None,
) -> str:
    """Trace a commit, PR, image, or custom identifier through pipeline flows.

    trace_type: "commit", "pr", "image", or "custom".
    """
    try:
        async def _client_call(api, method, **kwargs):
            return await client.call(api, method, context=context, **kwargs)

        pipeline_flow = await correlate_pipeline_events(
            trace_identifier=trace_identifier,
            trace_type=trace_type,
            client_call=_client_call,
            start_time=start_time,
            end_time=end_time,
            namespaces=namespaces,
            context=context,
        )

        artifacts = []
        if include_artifacts and pipeline_flow:
            artifacts = await track_artifacts(pipeline_flow)

        bottlenecks = analyze_bottlenecks(pipeline_flow) if pipeline_flow else []

        return json.dumps({
            "trace_identifier": trace_identifier,
            "trace_type": trace_type,
            "pipeline_flow": pipeline_flow,
            "artifacts": artifacts,
            "bottlenecks": bottlenecks,
            "total_pipelines_found": len(pipeline_flow),
        }, default=str)

    except Exception as e:
        return json.dumps({"error": f"Pipeline tracing failed: {e}"})
