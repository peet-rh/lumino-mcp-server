import asyncio
import json
import logging
from datetime import datetime, timezone

from mcp.server.fastmcp import FastMCP

from . import client
from . import helpers

logger = logging.getLogger("lumino-mcp")

mcp = FastMCP("lumino-mcp-server")


@mcp.tool()
async def reload_credentials(context: str | None = None) -> str:
    """Reload kubeconfig and reinitialise API clients.

    Call after `oc login` or kubeconfig changes — avoids restarting the MCP
    server. Returns the active context, cluster and user.
    """
    try:
        if context:
            client._load_config(context=context)
            client._init_clients()
        else:
            client._load_config()
            client._init_clients()
        info = client.get_current_context()
        return json.dumps({"status": "reloaded", **info})
    except Exception as e:
        return json.dumps({"error": f"Failed to reload credentials: {e}"})


@mcp.tool()
async def list_namespaces(context: str | None = None) -> str:
    """List all namespaces (projects) the current user can see.

    Returns sorted namespace names with status and labels.
    """
    try:
        result = await client.call("core_v1", "list_namespace", context=context)
        namespaces = []
        for ns in result.items:
            namespaces.append({
                "name": ns.metadata.name,
                "status": ns.status.phase if ns.status else "Unknown",
                "labels": dict(ns.metadata.labels or {}),
            })
        namespaces.sort(key=lambda n: n["name"])
        return json.dumps({"namespaces": namespaces, "total": len(namespaces)})
    except Exception as e:
        return json.dumps({"error": f"Failed to list namespaces: {e}"})


@mcp.tool()
async def search_resources_by_labels(
    label_selectors: list[dict],
    resource_types: list[str] | None = None,
    namespaces: list[str] | None = None,
    include_spec: bool = False,
    include_status: bool = True,
    context: str | None = None,
) -> str:
    """Search for Kubernetes resources across namespaces by label selector.

    Beats `oc get` by querying multiple resource types across multiple
    namespaces in one call.

    label_selectors: list of {key, value, operator} where operator is one of
        equals, exists, not_equals, in, not_in.
    resource_types: e.g. ["pods", "deployments", "pipelineruns"]. Defaults to
        pods + deployments.
    """
    try:
        selector = helpers.build_label_selector(label_selectors)
        if not selector:
            return json.dumps({"error": "No valid label selectors provided"})

        types = resource_types or ["pods", "deployments"]
        target_ns = namespaces or []

        if not target_ns:
            ns_result = await client.call("core_v1", "list_namespace", context=context)
            target_ns = [ns.metadata.name for ns in ns_result.items]

        results: dict[str, list] = {}
        for rtype in types:
            api_info = helpers.get_resource_api_info(rtype)
            if not api_info:
                results[rtype] = [{"error": f"Unsupported resource type: {rtype}"}]
                continue

            items: list[dict] = []
            if api_info["api"] == "custom":
                for ns in target_ns:
                    try:
                        resp = await client.call(
                            "custom", "list_namespaced_custom_object",
                            group=api_info["group"], version=api_info["version"],
                            namespace=ns, plural=api_info["plural"],
                            label_selector=selector, context=context,
                        )
                        for r in resp.get("items", []):
                            items.append(helpers.extract_resource_info(r, include_spec, include_status))
                    except Exception:
                        pass
            elif api_info.get("namespaced", True):
                for ns in target_ns:
                    try:
                        resp = await client.call(
                            api_info["api"], api_info["method"],
                            namespace=ns, label_selector=selector, context=context,
                        )
                        for r in resp.items:
                            items.append(helpers.extract_resource_info(r.to_dict(), include_spec, include_status))
                    except Exception:
                        pass
            else:
                try:
                    resp = await client.call(
                        api_info["api"], api_info["method"],
                        label_selector=selector, context=context,
                    )
                    for r in resp.items:
                        items.append(helpers.extract_resource_info(r.to_dict(), include_spec, include_status))
                except Exception:
                    pass

            results[rtype] = items

        total = sum(len(v) for v in results.values())
        return json.dumps({"selector": selector, "results": results, "total_matches": total})
    except Exception as e:
        return json.dumps({"error": f"Label search failed: {e}"})


@mcp.tool()
async def smart_get_namespace_events(
    namespace: str,
    time_period: str = "1h",
    max_tokens: int = 8000,
    severity_filter: str | None = None,
    context: str | None = None,
) -> str:
    """Get namespace events with adaptive token management and severity classification.

    Beats `oc get events` by classifying severity, categorising event types,
    and intelligently sampling to stay within a token budget.

    severity_filter: optional — CRITICAL, HIGH, MEDIUM, LOW.
    """
    try:
        td = helpers.parse_time_period(time_period)
        cutoff = datetime.now(tz=timezone.utc) - td

        result = await client.call(
            "core_v1", "list_namespaced_event",
            namespace=namespace, context=context,
        )

        events: list[str] = []
        for ev in result.items:
            ts = ev.last_timestamp or ev.event_time or ev.metadata.creation_timestamp
            if ts and ts.replace(tzinfo=timezone.utc) < cutoff:
                continue

            obj = ev.involved_object
            obj_ref = f"{obj.kind}/{obj.name}" if obj else "unknown"
            event_str = (
                f"[{ev.type}] {ev.reason}: {ev.message} "
                f"(Object: {obj_ref}, Count: {ev.count or 1}, "
                f"Time: {ts.isoformat() if ts else 'unknown'})"
            )
            events.append(event_str)

        if severity_filter:
            events = [e for e in events if helpers.classify_event_severity(e) == severity_filter.upper()]

        sampled = helpers.smart_sample_events(events, max_tokens)
        summary = helpers.generate_events_summary(sampled)
        insights = helpers.generate_events_insights(sampled)

        display_events = []
        for ev in sampled:
            display_events.append({
                "event": ev["event"],
                "severity": ev["severity"],
                "category": ev["category"],
            })

        return json.dumps({
            "namespace": namespace,
            "time_period": time_period,
            "summary": summary,
            "insights": insights,
            "events": display_events,
            "total_in_period": len(events),
            "sampled": len(sampled),
        })
    except Exception as e:
        return json.dumps({"error": f"Event retrieval failed: {e}"})


@mcp.tool()
async def check_resource_constraints(
    namespace: str,
    context: str | None = None,
) -> str:
    """Check resource constraints in a namespace — quotas, OOM kills, CrashLoopBackOff, restarts.

    Beats `oc get` by aggregating quota utilisation, pod health, and
    container-level restart/OOM data into one structured response.
    """
    try:
        pods_resp, quotas_resp = await asyncio.gather(
            client.call("core_v1", "list_namespaced_pod", namespace=namespace, context=context),
            client.call("core_v1", "list_namespaced_resource_quota", namespace=namespace, context=context),
        )

        quota_info = []
        for q in quotas_resp.items:
            hard = q.status.hard or {}
            used = q.status.used or {}
            quota_detail = {"name": q.metadata.name, "resources": {}}
            for resource, limit_val in hard.items():
                used_val = used.get(resource, "0")
                quota_detail["resources"][resource] = {
                    "used": used_val, "limit": limit_val,
                    "utilization_pct": helpers.calculate_utilization(str(used_val), str(limit_val)),
                }
            quota_info.append(quota_detail)

        pod_issues: list[dict] = []
        total_pods = 0
        running = 0
        problem_pods = 0

        for pod in pods_resp.items:
            total_pods += 1
            phase = pod.status.phase if pod.status else "Unknown"
            if phase == "Running":
                running += 1

            has_issue = False
            containers = pod.status.container_statuses or []
            for cs in containers:
                restart_count = cs.restart_count or 0
                waiting = cs.state.waiting if cs.state else None
                terminated = cs.state.terminated if cs.state else None

                issues: list[str] = []
                if waiting and waiting.reason == "CrashLoopBackOff":
                    issues.append("CrashLoopBackOff")
                if terminated and terminated.reason == "OOMKilled":
                    issues.append("OOMKilled")
                if restart_count > 5:
                    issues.append(f"high_restarts ({restart_count})")

                if issues:
                    has_issue = True
                    pod_issues.append({
                        "pod": pod.metadata.name,
                        "container": cs.name,
                        "issues": issues,
                        "restart_count": restart_count,
                        "phase": phase,
                    })

            if has_issue:
                problem_pods += 1

        high_util = [
            {"quota": q["name"], "resource": r, **v}
            for q in quota_info
            for r, v in q["resources"].items()
            if v["utilization_pct"] > 80
        ]

        return json.dumps({
            "namespace": namespace,
            "pod_summary": {
                "total": total_pods, "running": running, "problem_pods": problem_pods,
            },
            "pod_issues": pod_issues,
            "quotas": quota_info,
            "high_utilization_alerts": high_util,
        })
    except Exception as e:
        return json.dumps({"error": f"Resource check failed: {e}"})


@mcp.tool()
async def get_pipelinerun_logs(
    namespace: str,
    pipeline_run: str,
    max_log_lines: int = 200,
    context: str | None = None,
) -> str:
    """Fetch logs from all pods in a Tekton PipelineRun.

    Beats `tkn pr logs` by collecting all task pod logs with adaptive
    tail-line management and error pattern extraction.
    """
    try:
        client._ensure_clients()
        core_api = client._get_client("core_v1")
        custom_api = client._get_client("custom")

        pods_resp = await asyncio.to_thread(
            core_api.list_namespaced_pod,
            namespace=namespace,
            label_selector=f"tekton.dev/pipelineRun={pipeline_run}",
        )

        if not pods_resp.items:
            return json.dumps({"error": f"No pods found for PipelineRun {pipeline_run}"})

        lines_per_pod = max(50, max_log_lines // max(len(pods_resp.items), 1))
        all_logs: dict[str, dict] = {}
        all_errors: list[str] = []

        for pod in pods_resp.items:
            pod_name = pod.metadata.name
            task_name = (pod.metadata.labels or {}).get("tekton.dev/pipelineTask", "unknown")
            pod_logs = await helpers.get_all_pod_logs(
                pod_name, namespace, core_api, tail_lines=lines_per_pod,
            )
            cleaned = {}
            for container, log_text in pod_logs.items():
                cleaned_text = helpers.clean_pipeline_logs(log_text)
                cleaned[container] = cleaned_text
                all_errors.extend(helpers.extract_error_patterns(cleaned_text))

            all_logs[task_name] = {"pod": pod_name, "containers": cleaned}

        return json.dumps({
            "pipeline_run": pipeline_run,
            "namespace": namespace,
            "task_count": len(all_logs),
            "logs": all_logs,
            "error_patterns": all_errors[:20],
            "lines_per_pod": lines_per_pod,
        })
    except Exception as e:
        return json.dumps({"error": f"Log retrieval failed: {e}"})


@mcp.tool()
async def analyze_failed_pipeline(
    namespace: str,
    pipeline_run: str,
    context: str | None = None,
) -> str:
    """Analyse a failed Tekton PipelineRun — aggregates status, task details,
    pod logs, error patterns, root cause analysis, and recommendations.

    This is the most valuable tool: one call replaces a multi-step manual
    investigation with `oc`, `tkn`, and log reading.
    """
    try:
        client._ensure_clients()
        core_api = client._get_client("core_v1")
        custom_api = client._get_client("custom")

        pr_details = await helpers.get_pipeline_details(namespace, pipeline_run, custom_api)
        if "error" in pr_details:
            return json.dumps(pr_details)

        failed_tasks = [t for t in pr_details.get("task_runs", [])
                        if t.get("status") in ("Failed", "Error", "TaskRunTimeout")]

        task_details = []
        all_logs_text = ""
        all_errors: list[str] = []

        for task in (failed_tasks or pr_details.get("task_runs", [])[:3]):
            td = await helpers.get_task_details(namespace, task["name"], custom_api)
            task_details.append(td)

            pod_name = td.get("pod", "")
            if pod_name and pod_name != "unknown":
                pod_logs = await helpers.get_all_pod_logs(pod_name, namespace, core_api, tail_lines=100)
                for container, log_text in pod_logs.items():
                    if container.startswith("_"):
                        continue
                    cleaned = helpers.clean_pipeline_logs(log_text)
                    all_logs_text += cleaned + "\n"
                    all_errors.extend(helpers.extract_error_patterns(cleaned))

        error_categories = helpers.categorize_errors(all_logs_text, all_errors)
        root_cause = helpers.determine_root_cause(error_categories, all_errors)
        recommendations = helpers.recommend_actions(root_cause, failed_tasks)

        return json.dumps({
            "pipeline_run": pr_details,
            "failed_tasks": [t["name"] for t in failed_tasks],
            "task_details": task_details,
            "error_patterns": all_errors[:15],
            "error_categories": error_categories,
            "root_cause_analysis": root_cause,
            "recommendations": recommendations,
        })
    except Exception as e:
        return json.dumps({"error": f"Pipeline analysis failed: {e}"})


@mcp.tool()
async def check_cluster_certificate_health(
    namespaces: list[str] | None = None,
    warning_days: int = 30,
    critical_days: int = 7,
    context: str | None = None,
) -> str:
    """Scan TLS certificates across namespaces for expiry.

    Beats manual checking by scanning all kubernetes.io/tls secrets,
    parsing certificates, and generating an expiry timeline with
    severity classification.
    """
    if not helpers._HAS_CRYPTO:
        return json.dumps({"error": "cryptography library not installed — cannot parse certificates"})

    try:
        target_ns = namespaces
        if not target_ns:
            ns_result = await client.call("core_v1", "list_namespace", context=context)
            target_ns = [ns.metadata.name for ns in ns_result.items]

        certs: list[dict] = []
        for ns in target_ns:
            try:
                secrets = await client.call(
                    "core_v1", "list_namespaced_secret",
                    namespace=ns, context=context,
                )
                for secret in secrets.items:
                    if secret.type != "kubernetes.io/tls":
                        continue
                    cert_data = (secret.data or {}).get("tls.crt")
                    if not cert_data:
                        continue

                    import base64
                    decoded = base64.b64decode(cert_data).decode("utf-8", errors="replace")
                    parsed = helpers.parse_certificate(decoded)
                    if not parsed:
                        continue

                    status = helpers.categorize_certificate_status(
                        parsed["days_remaining"], warning_days, critical_days,
                    )
                    certs.append({
                        "namespace": ns,
                        "secret": secret.metadata.name,
                        "status": status,
                        **parsed,
                    })
            except Exception:
                pass

        certs.sort(key=lambda c: c.get("days_remaining", 9999))

        summary = {
            "total_certs": len(certs),
            "expired": sum(1 for c in certs if c["status"] == "expired"),
            "critical": sum(1 for c in certs if c["status"] == "critical"),
            "warning": sum(1 for c in certs if c["status"] == "warning"),
            "healthy": sum(1 for c in certs if c["status"] == "healthy"),
        }

        return json.dumps({
            "summary": summary,
            "certificates": certs,
            "thresholds": {"warning_days": warning_days, "critical_days": critical_days},
        })
    except Exception as e:
        return json.dumps({"error": f"Certificate check failed: {e}"})


@mcp.tool()
async def get_openshift_cluster_operator_status(
    context: str | None = None,
) -> str:
    """Get status of all OpenShift ClusterOperators with condition analysis.

    Aggregates operator health, degraded/progressing/available conditions,
    and version info into one structured view.
    """
    try:
        result = await client.call(
            "custom", "list_cluster_custom_object",
            group="config.openshift.io", version="v1",
            plural="clusteroperators", context=context,
        )

        operators = []
        degraded_list: list[str] = []
        progressing_list: list[str] = []

        for op in result.get("items", []):
            name = op.get("metadata", {}).get("name", "unknown")
            status = op.get("status", {})
            conditions = status.get("conditions", [])

            analysis = helpers.analyze_operator_conditions(conditions)

            versions = []
            for v in status.get("versions", []):
                versions.append({"name": v.get("name", ""), "version": v.get("version", "")})

            if analysis["degraded"]:
                degraded_list.append(name)
            if analysis["progressing"]:
                progressing_list.append(name)

            operators.append({
                "name": name,
                "available": analysis["available"],
                "progressing": analysis["progressing"],
                "degraded": analysis["degraded"],
                "versions": versions,
                "critical_conditions": analysis["critical_conditions"],
                "warning_conditions": analysis["warning_conditions"],
            })

        operators.sort(key=lambda o: (not o["degraded"], not o["progressing"], o["name"]))

        health = "healthy"
        if degraded_list:
            health = "degraded"
        elif progressing_list:
            health = "progressing"

        return json.dumps({
            "cluster_health": health,
            "total_operators": len(operators),
            "degraded": degraded_list,
            "progressing": progressing_list,
            "operators": operators,
        })
    except Exception as e:
        return json.dumps({"error": f"Cluster operator check failed: {e}"})


@mcp.tool()
async def get_machine_config_pool_status(
    context: str | None = None,
) -> str:
    """Get MachineConfigPool status with update progress and issue detection.

    Shows pool health, update progress, degraded nodes, and actionable issues
    for each MCP (master, worker, etc).
    """
    try:
        result = await client.call(
            "custom", "list_cluster_custom_object",
            group="machineconfiguration.openshift.io", version="v1",
            plural="machineconfigpools", context=context,
        )

        pools = []
        all_issues: list[dict] = []

        for pool in result.get("items", []):
            analysis = helpers.analyze_mcp_status(pool)
            issues = helpers.detect_pool_issues(analysis)
            all_issues.extend(issues)
            pools.append({**analysis, "issues": issues})

        overall = "healthy"
        if any(p["status"] == "degraded" for p in pools):
            overall = "degraded"
        elif any(p["status"] == "updating" for p in pools):
            overall = "updating"

        return json.dumps({
            "overall_status": overall,
            "pools": pools,
            "issues": all_issues,
            "total_pools": len(pools),
        })
    except Exception as e:
        return json.dumps({"error": f"MCP status check failed: {e}"})


# Import tool modules — registration happens at import time via @mcp.tool()
# This MUST be at the bottom to avoid circular imports (tools import mcp from here)
from . import tools  # noqa: E402, F401
