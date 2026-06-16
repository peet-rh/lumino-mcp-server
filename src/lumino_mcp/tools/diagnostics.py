"""Diagnostic tools — namespace overview, TLS investigation, RCA report generation."""

import asyncio
import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from ..server import mcp
from .. import client
from .. import helpers
from ..helpers.events import (
    get_namespace_events_internal,
    filter_analysis_for_synthesis,
    compress_events_for_synthesis,
)
from ..helpers.failure_analysis import (
    identify_failure_context,
    analyze_pipeline_failure,
    analyze_pod_failure,
    analyze_generic_failure,
    build_failure_timeline,
    find_related_failures,
    perform_advanced_rca,
    generate_remediation_plan,
    calculate_confidence_score,
    calculate_failure_impact_score,
    assess_failure_severity,
    analyze_failure_trends,
    analyze_resource_constraints as fa_analyze_resource_constraints,
    analyze_configuration_issues,
)

logger = logging.getLogger("lumino-mcp")


@mcp.tool()
async def investigate_tls_certificate_issues(
    namespace: str | None = None,
    include_routes: bool = True,
    context: str | None = None,
) -> str:
    """Investigate TLS certificate issues — expired certs, missing secrets, misconfigured routes."""
    try:
        target_ns = [namespace] if namespace else []
        if not target_ns:
            ns_result = await client.call("core_v1", "list_namespace", context=context)
            target_ns = [ns.metadata.name for ns in ns_result.items][:20]

        cert_issues = []
        route_issues = []

        for ns in target_ns:
            try:
                secrets = await client.call(
                    "core_v1", "list_namespaced_secret",
                    namespace=ns, context=context,
                )
                for secret in secrets.items:
                    if secret.type != "kubernetes.io/tls":
                        continue

                    issues = []
                    data = secret.data or {}

                    if "tls.crt" not in data:
                        issues.append("missing tls.crt")
                    if "tls.key" not in data:
                        issues.append("missing tls.key")

                    if "tls.crt" in data and helpers._HAS_CRYPTO:
                        import base64
                        decoded = base64.b64decode(data["tls.crt"]).decode("utf-8", errors="replace")
                        parsed = helpers.parse_certificate(decoded)
                        if parsed:
                            days = parsed.get("days_remaining", 999)
                            if days <= 0:
                                issues.append(f"EXPIRED ({abs(days)} days ago)")
                            elif days <= 7:
                                issues.append(f"expires in {days} days (CRITICAL)")
                            elif days <= 30:
                                issues.append(f"expires in {days} days (WARNING)")

                    if issues:
                        cert_issues.append({
                            "namespace": ns,
                            "secret": secret.metadata.name,
                            "issues": issues,
                        })

            except Exception:
                continue

            if include_routes:
                try:
                    routes = await client.call(
                        "custom", "list_namespaced_custom_object",
                        group="route.openshift.io", version="v1",
                        namespace=ns, plural="routes",
                        context=context,
                    )
                    for route in routes.get("items", []):
                        meta = route.get("metadata", {})
                        spec = route.get("spec", {})
                        tls = spec.get("tls", {})

                        if tls and tls.get("termination"):
                            if tls["termination"] in ("edge", "reencrypt") and not tls.get("certificate"):
                                if not tls.get("externalCertificate"):
                                    route_issues.append({
                                        "namespace": ns,
                                        "route": meta.get("name", "unknown"),
                                        "issue": f"TLS termination '{tls['termination']}' but no certificate configured",
                                    })
                except Exception:
                    continue

        return json.dumps({
            "certificate_issues": cert_issues,
            "route_issues": route_issues,
            "total_cert_issues": len(cert_issues),
            "total_route_issues": len(route_issues),
            "namespaces_checked": len(target_ns),
        })

    except Exception as e:
        return json.dumps({"error": f"TLS investigation failed: {e}"})


@mcp.tool()
async def conservative_namespace_overview(
    namespace: str,
    max_pods: int = 10,
    context: str | None = None,
) -> str:
    """Quick namespace health check — pods, events, error patterns."""
    try:
        pods_resp, events_data = await asyncio.gather(
            client.call("core_v1", "list_namespaced_pod", namespace=namespace, context=context),
            get_namespace_events_internal(client.call, namespace, time_period="1h", context=context),
        )

        pod_summary = {"total": 0, "running": 0, "failed": 0, "pending": 0, "issues": []}
        for pod in pods_resp.items:
            pod_summary["total"] += 1
            phase = pod.status.phase if pod.status else "Unknown"
            if phase == "Running":
                pod_summary["running"] += 1
            elif phase == "Failed":
                pod_summary["failed"] += 1
            elif phase == "Pending":
                pod_summary["pending"] += 1

            containers = pod.status.container_statuses or []
            for cs in containers:
                if cs.restart_count and cs.restart_count > 5:
                    pod_summary["issues"].append({
                        "pod": pod.metadata.name,
                        "container": cs.name,
                        "issue": f"high restarts ({cs.restart_count})",
                    })
                waiting = cs.state.waiting if cs.state else None
                if waiting and waiting.reason == "CrashLoopBackOff":
                    pod_summary["issues"].append({
                        "pod": pod.metadata.name,
                        "container": cs.name,
                        "issue": "CrashLoopBackOff",
                    })

        client._ensure_clients()
        core_api = client._get_client("core_v1")
        error_patterns = []
        problem_pods = [p for p in pods_resp.items if (p.status.phase or "") != "Running"][:max_pods]
        for pod in problem_pods[:3]:
            try:
                pod_logs = await helpers.get_all_pod_logs(
                    pod.metadata.name, namespace, core_api, tail_lines=200,
                )
                for container, log_text in pod_logs.items():
                    cleaned = helpers.clean_pipeline_logs(log_text)
                    patterns = helpers.extract_error_patterns(cleaned)
                    if patterns:
                        error_patterns.extend(patterns[:5])
            except Exception:
                continue

        events_summary = {
            "total": events_data.get("filtered_events_count", 0),
            "sample": events_data.get("events", [])[:10],
        }

        return json.dumps({
            "namespace": namespace,
            "pod_summary": pod_summary,
            "events_summary": events_summary,
            "error_patterns": error_patterns[:15],
        })

    except Exception as e:
        return json.dumps({"error": f"Namespace overview failed: {e}"})


@mcp.tool()
async def adaptive_namespace_investigation(
    namespace: str,
    focus_areas: list[str] | None = None,
    max_token_budget: int = 12000,
    context: str | None = None,
) -> str:
    """Progressive namespace analysis — discovery, analysis, synthesis.

    focus_areas: e.g. ["errors", "performance", "security"]. Default: ["errors", "warnings"].
    """
    if focus_areas is None:
        focus_areas = ["errors", "warnings"]

    try:
        pods_resp, events_data = await asyncio.gather(
            client.call("core_v1", "list_namespaced_pod", namespace=namespace, context=context),
            get_namespace_events_internal(client.call, namespace, time_period="2h", context=context),
        )

        pod_count = len(pods_resp.items)
        problem_pods = []
        for pod in pods_resp.items:
            phase = pod.status.phase if pod.status else "Unknown"
            has_issue = False
            for cs in (pod.status.container_statuses or []):
                if (cs.restart_count or 0) > 3:
                    has_issue = True
                waiting = cs.state.waiting if cs.state else None
                if waiting and waiting.reason in ("CrashLoopBackOff", "ImagePullBackOff"):
                    has_issue = True
            if has_issue or phase in ("Failed", "Pending"):
                problem_pods.append(pod)

        compressed_events = compress_events_for_synthesis(events_data)

        client._ensure_clients()
        core_api = client._get_client("core_v1")
        pod_analyses = []
        for pod in problem_pods[:5]:
            try:
                pod_logs = await helpers.get_all_pod_logs(
                    pod.metadata.name, namespace, core_api, tail_lines=300,
                )
                all_errors = []
                for container, log_text in pod_logs.items():
                    cleaned = helpers.clean_pipeline_logs(log_text)
                    all_errors.extend(helpers.extract_error_patterns(cleaned))

                pod_analyses.append({
                    "pod": pod.metadata.name,
                    "phase": pod.status.phase,
                    "error_patterns": all_errors[:10],
                    "containers": len(pod.status.container_statuses or []),
                })
            except Exception:
                continue

        synthesis = {
            "namespace": namespace,
            "total_pods": pod_count,
            "problem_pods": len(problem_pods),
            "pods_analyzed": len(pod_analyses),
            "events_summary": compressed_events,
            "pod_analyses": pod_analyses,
            "focus_areas": focus_areas,
            "health": "healthy" if not problem_pods else ("degraded" if len(problem_pods) < 3 else "critical"),
        }

        return json.dumps(synthesis)

    except Exception as e:
        return json.dumps({"error": f"Namespace investigation failed: {e}"})


@mcp.tool()
async def automated_triage_rca_report_generator(
    failure_identifier: str,
    namespace: str | None = None,
    depth: str = "standard",
    time_window_hours: int = 4,
    context: str | None = None,
) -> str:
    """Generate automated Root Cause Analysis report for a failure.

    failure_identifier: PipelineRun name, pod name, or event ID.
    depth: "basic", "standard", or "deep".
    """
    try:
        async def _detect_ns():
            ns_result = await client.call("core_v1", "list_namespace", context=context)
            return {"tekton": [ns.metadata.name for ns in ns_result.items][:30]}

        client._ensure_clients()
        core_api = client._get_client("core_v1")
        custom_api = client._get_client("custom")

        failure_ctx = await identify_failure_context(
            failure_identifier, _detect_ns,
            custom_api, core_api, logger,
            namespace=namespace,
        )

        if not failure_ctx.get("found"):
            return json.dumps({
                "error": f"Could not find resource '{failure_identifier}' in any namespace",
                "searched_namespace": namespace,
            })

        ns = failure_ctx["namespace"]
        failure_type = failure_ctx["type"]

        async def _get_events(ns_arg):
            data = await get_namespace_events_internal(client.call, ns_arg, time_period=f"{time_window_hours}h", context=context)
            return data

        if failure_type == "pipelinerun":
            primary_analysis = {"basic_analysis": {"failed_tasks": []}, "logs_analyzed": {}}
            try:
                from ..server import analyze_failed_pipeline
                basic = json.loads(await analyze_failed_pipeline(ns, failure_identifier, context=context))
                primary_analysis["basic_analysis"] = basic
            except Exception:
                pass
        elif failure_type == "pod":
            primary_analysis = await analyze_pod_failure(
                ns, failure_identifier, depth,
                core_api, lambda n, p: helpers.get_all_pod_logs(p, n, core_api, tail_lines=200),
                lambda t: {"error_patterns": helpers.extract_error_patterns(t)},
                lambda t: {"anomalies": []},
                _get_events, logger,
            )
        else:
            primary_analysis = await analyze_generic_failure(ns, failure_identifier, depth, _get_events, logger)

        timeline = await build_failure_timeline(ns, failure_identifier, time_window_hours, _get_events, logger)

        async def _list_pipelineruns(ns_arg):
            resp = await client.call(
                "custom", "list_namespaced_custom_object",
                group="tekton.dev", version="v1",
                namespace=ns_arg, plural="pipelineruns",
                context=context,
            )
            return [{"name": pr.get("metadata", {}).get("name"), "status": "Unknown"} for pr in resp.get("items", [])]

        related = await find_related_failures(ns, failure_identifier, time_window_hours, depth, _list_pipelineruns, logger)

        root_cause = await perform_advanced_rca(primary_analysis, timeline, related, depth, helpers.categorize_errors, logger)

        resource_analysis = await fa_analyze_resource_constraints(ns, failure_identifier, core_api, logger)
        config_analysis = await analyze_configuration_issues(ns, failure_identifier, logger)

        remediation = await generate_remediation_plan(
            root_cause, primary_analysis, resource_analysis, config_analysis,
            lambda rc, tasks=None: helpers.recommend_actions(rc, tasks or []),
            logger,
        )

        confidence = calculate_confidence_score(primary_analysis, root_cause, timeline)
        impact = calculate_failure_impact_score(primary_analysis, timeline, related)
        severity = assess_failure_severity(primary_analysis, root_cause, resource_analysis, config_analysis)
        trends = analyze_failure_trends(related, timeline)

        report = {
            "report_type": "automated_triage_rca",
            "failure_identifier": failure_identifier,
            "failure_type": failure_type,
            "namespace": ns,
            "depth": depth,
            "generated_at": datetime.now().isoformat(),
            "root_cause_analysis": root_cause,
            "severity_assessment": severity,
            "impact_assessment": impact,
            "confidence_score": confidence,
            "timeline": timeline[:10],
            "related_failures": related[:5],
            "resource_analysis": resource_analysis,
            "remediation_plan": remediation,
            "failure_trends": trends,
        }

        return json.dumps(report, default=str)

    except Exception as e:
        return json.dumps({"error": f"RCA report generation failed: {e}"})
