"""Resource topology helper module — pipeline correlation, topology mapping, operator analysis.

Ported from upstream lumino-mcp-server helpers/resource_topology.py.
Functions that overlap with existing helpers/__init__.py are not re-exported.
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

logger = logging.getLogger("lumino-mcp")


async def get_multi_cluster_clients(client_call) -> Dict[str, Dict[str, Any]]:
    """Get clients for multiple clusters. Currently returns current cluster only."""
    return {"current": {"client_call": client_call}}


async def correlate_pipeline_events(
    trace_identifier: str,
    trace_type: str,
    client_call,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    namespaces: Optional[List[str]] = None,
    max_namespaces: int = 50,
    tekton_namespaces: Optional[List[str]] = None,
    context: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Correlate pipeline runs across clusters using labels, annotations, and artifact references."""
    pipeline_flow = []

    target_namespaces = namespaces or []
    if not target_namespaces:
        try:
            ns_result = await client_call("core_v1", "list_namespace", context=context)
            all_ns = [ns.metadata.name for ns in ns_result.items]

            if tekton_namespaces:
                tekton_set = set(tekton_namespaces)
                prioritized = [ns for ns in all_ns if ns in tekton_set]
                others = [ns for ns in all_ns if ns not in tekton_set]
                target_namespaces = (prioritized + others)[:max_namespaces]
            else:
                pipeline_keywords = ["tenant", "pipeline", "tekton", "cicd", "ci-cd", "build", "konflux"]
                prioritized = [ns for ns in all_ns if any(kw in ns.lower() for kw in pipeline_keywords)]
                others = [ns for ns in all_ns if ns not in prioritized]
                target_namespaces = (prioritized + others)[:max_namespaces]
        except Exception as e:
            logger.warning(f"Failed to list namespaces: {e}")
            return []

    async def query_namespace(namespace: str) -> List[Dict[str, Any]]:
        results = []
        try:
            prs = await client_call(
                "custom", "list_namespaced_custom_object",
                group="tekton.dev", version="v1beta1",
                namespace=namespace, plural="pipelineruns",
                context=context,
            )
            for pr in prs.get("items", []):
                if matches_trace_identifier(pr, trace_identifier, trace_type):
                    info = {
                        "cluster": "current",
                        "namespace": namespace,
                        "pipeline_name": pr.get("metadata", {}).get("name", "unknown"),
                        "pipeline_run_name": pr.get("metadata", {}).get("name", "unknown"),
                        "status": get_pipeline_status(pr),
                        "start_time": pr.get("status", {}).get("startTime"),
                        "completion_time": pr.get("status", {}).get("completionTime"),
                        "tasks": extract_task_info(pr),
                        "labels": pr.get("metadata", {}).get("labels", {}),
                        "annotations": pr.get("metadata", {}).get("annotations", {}),
                    }
                    if in_time_range(info, start_time, end_time):
                        results.append(info)
        except Exception:
            pass
        return results

    tasks = [asyncio.create_task(query_namespace(ns)) for ns in target_namespaces]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for result in results:
        if isinstance(result, list):
            pipeline_flow.extend(result)

    return pipeline_flow


def matches_trace_identifier(pipeline_run: Dict[str, Any], trace_identifier: str, trace_type: str) -> bool:
    """Check if a pipeline run matches the trace identifier."""
    metadata = pipeline_run.get("metadata", {})
    labels = metadata.get("labels", {})
    annotations = metadata.get("annotations", {})

    if trace_type == "commit":
        commit_keys = ["git.commit", "tekton.dev/git-commit", "pipelinesascode.tekton.dev/sha"]
        for key in commit_keys:
            if labels.get(key, "").startswith(trace_identifier) or annotations.get(key, "").startswith(trace_identifier):
                return True
        return any(trace_identifier in str(v) for v in labels.values()) or \
               any(trace_identifier in str(v) for v in annotations.values())

    elif trace_type == "pr":
        pr_keys = [
            "pac.test.appstudio.openshift.io/pull-request",
            "pipelinesascode.tekton.dev/pull-request",
            "pull-request", "pr",
        ]
        for key in pr_keys:
            if labels.get(key) == trace_identifier or annotations.get(key) == trace_identifier:
                return True
        for key in ["pipelinesascode.tekton.dev/pull-request", "build.appstudio.openshift.io/pull_request_number"]:
            if annotations.get(key) == trace_identifier:
                return True
        return False

    elif trace_type == "image":
        return any(trace_identifier in str(v) for v in labels.values()) or \
               any(trace_identifier in str(v) for v in annotations.values())

    elif trace_type == "custom":
        name = metadata.get("name", "")
        return trace_identifier in name or \
               any(trace_identifier in str(v) for v in labels.values()) or \
               any(trace_identifier in str(v) for v in annotations.values())

    return False


def get_pipeline_status(pipeline_run: Dict[str, Any]) -> str:
    """Extract pipeline status from PipelineRun."""
    conditions = pipeline_run.get("status", {}).get("conditions", [])
    if conditions:
        latest = conditions[-1]
        return latest.get("reason", "Unknown") if latest.get("status") == "True" else latest.get("reason", "Failed")
    return "Unknown"


def extract_task_info(pipeline_run: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extract task information from PipelineRun status."""
    tasks = []
    task_runs = pipeline_run.get("status", {}).get("taskRuns", {})
    for name, status in task_runs.items():
        conditions = status.get("status", {}).get("conditions", [{}])
        tasks.append({
            "name": name,
            "status": conditions[-1].get("reason", "Unknown"),
            "start_time": status.get("status", {}).get("startTime"),
            "completion_time": status.get("status", {}).get("completionTime"),
        })
    return tasks


def in_time_range(pipeline_info: Dict[str, Any], start_time: Optional[str], end_time: Optional[str]) -> bool:
    """Check if pipeline execution falls within the specified time range."""
    if not start_time and not end_time:
        return True
    ps = pipeline_info.get("start_time")
    if not ps:
        return True
    try:
        pdt = datetime.fromisoformat(ps.replace("Z", "+00:00"))
        if start_time and pdt < datetime.fromisoformat(start_time.replace("Z", "+00:00")):
            return False
        if end_time and pdt > datetime.fromisoformat(end_time.replace("Z", "+00:00")):
            return False
        return True
    except Exception:
        return True


async def track_artifacts(pipeline_flow: List[Dict[str, Any]], include_artifacts: bool = True) -> List[Dict[str, Any]]:
    """Track artifacts through container registries and pipeline results."""
    if not include_artifacts:
        return []
    artifacts = []
    seen = set()
    for pipeline in pipeline_flow:
        for artifact in extract_pipeline_artifacts(pipeline):
            aid = artifact.get("artifact_id", "")
            if aid and aid not in seen:
                artifacts.append(artifact)
                seen.add(aid)
    return artifacts


def extract_pipeline_artifacts(pipeline: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extract artifact information from pipeline metadata."""
    artifacts = []
    labels = pipeline.get("labels", {})
    annotations = pipeline.get("annotations", {})

    potential_images = []
    for key, value in labels.items():
        if any(kw in key.lower() for kw in ["image", "container", "artifact"]):
            potential_images.append(value)
    for key, value in annotations.items():
        if any(kw in key.lower() for kw in ["image", "container", "artifact"]):
            potential_images.append(value)

    for image in potential_images:
        if image and ":" in image:
            artifacts.append({
                "artifact_id": image,
                "type": "container_image",
                "registry": image.split("/")[0] if "/" in image else "unknown",
                "propagation_path": [{
                    "cluster": pipeline.get("cluster", "unknown"),
                    "namespace": pipeline.get("namespace", "unknown"),
                    "pipeline": pipeline.get("pipeline_name", "unknown"),
                    "timestamp": pipeline.get("start_time", ""),
                }],
            })
    return artifacts


def analyze_bottlenecks(pipeline_flow: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Analyze pipeline flow for bottlenecks and performance issues."""
    bottlenecks = []
    for pipeline in pipeline_flow:
        st = pipeline.get("start_time")
        ct = pipeline.get("completion_time")
        if st and ct:
            try:
                start_dt = datetime.fromisoformat(st.replace("Z", "+00:00"))
                end_dt = datetime.fromisoformat(ct.replace("Z", "+00:00"))
                duration = (end_dt - start_dt).total_seconds()
                if duration > 1800:
                    bottlenecks.append({
                        "location": f"{pipeline.get('cluster', '')}/{pipeline.get('namespace', '')}/{pipeline.get('pipeline_name', '')}",
                        "type": "long_duration",
                        "duration": duration,
                        "description": f"Pipeline execution took {duration/60:.1f} minutes",
                    })
                for task in pipeline.get("tasks", []):
                    ts = task.get("start_time")
                    te = task.get("completion_time")
                    if ts and te:
                        try:
                            td = (datetime.fromisoformat(te.replace("Z", "+00:00")) - datetime.fromisoformat(ts.replace("Z", "+00:00"))).total_seconds()
                            if td > 900:
                                bottlenecks.append({
                                    "location": f"{pipeline.get('cluster', '')}/{pipeline.get('namespace', '')}/{task['name']}",
                                    "type": "slow_task",
                                    "duration": td,
                                    "description": f"Task '{task['name']}' took {td/60:.1f} minutes",
                                })
                        except Exception:
                            continue
            except Exception:
                continue

    if len(pipeline_flow) > 1:
        failed = [p for p in pipeline_flow if p.get("status", "").lower() in ("failed", "error")]
        if len(failed) / len(pipeline_flow) > 0.3:
            bottlenecks.append({
                "location": "cross_cluster",
                "type": "high_failure_rate",
                "description": f"High failure rate: {len(failed)}/{len(pipeline_flow)} pipelines failed",
            })

    return bottlenecks


def analyze_operator_dependencies(operators: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Analyze operator dependencies and relationships."""
    operator_deps = {
        "authentication": ["oauth-openshift", "openshift-apiserver"],
        "console": ["authentication", "oauth-openshift"],
        "monitoring": ["prometheus-operator"],
        "ingress": ["dns"],
        "image-registry": ["storage"],
        "openshift-apiserver": ["etcd", "kube-apiserver-operator"],
        "openshift-controller-manager": ["openshift-apiserver"],
        "machine-api": ["cluster-autoscaler-operator"],
    }

    operator_names = {op.get("name", "") for op in operators}
    dependencies = []
    for operator in operators:
        name = operator.get("name", "")
        deps = [d for d in operator_deps.get(name, []) if d in operator_names]
        if deps:
            dep_status = "healthy"
            for dep in deps:
                dep_op = next((op for op in operators if op.get("name") == dep), None)
                if dep_op:
                    for cond in dep_op.get("conditions", []):
                        if cond.get("type") in ("Degraded", "Available") and cond.get("status") != "True":
                            dep_status = "unhealthy"
                            break
            dependencies.append({"operator": name, "depends_on": deps, "dependency_status": dep_status})
    return dependencies


def identify_critical_issues(operators: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Identify critical issues requiring immediate attention."""
    issues = []
    for op in operators:
        name = op.get("name", "")
        analysis = op.get("conditions_analysis", {})
        critical = analysis.get("critical_conditions", [])
        warning = analysis.get("warning_conditions", [])

        if critical:
            for cond in critical:
                issues.append({
                    "operator": name, "severity": "critical",
                    "issue": cond.get("message", "Operator is degraded"),
                    "impact": f"Operator {name} failure may affect cluster functionality",
                    "recommended_action": f"Investigate and resolve {name} operator issues immediately",
                })
        elif warning:
            for cond in warning:
                issues.append({
                    "operator": name, "severity": "warning",
                    "issue": cond.get("message", "Operator is not available"),
                    "impact": f"Operator {name} availability issues may affect functionality",
                    "recommended_action": f"Monitor and investigate {name} operator availability",
                })
    return issues


def generate_node_id(cluster: str, namespace: str, resource_type: str, name: str) -> str:
    return f"{cluster}:{namespace}:{resource_type}:{name}"


def calculate_dependency_weight(source_type: str, target_type: str, relationship: str) -> float:
    weights = {
        ("deployment", "service"): 0.9, ("deployment", "configmap"): 0.7,
        ("deployment", "secret"): 0.8, ("deployment", "persistentvolumeclaim"): 0.6,
        ("service", "pod"): 0.9, ("pipelinerun", "pipeline"): 0.9,
        ("taskrun", "task"): 0.8, ("pod", "node"): 0.5,
        ("pod", "persistentvolumeclaim"): 0.6,
    }
    return weights.get((source_type.lower(), target_type.lower()), 0.5)


def convert_to_graphviz(nodes: List[Dict[str, Any]], edges: List[Dict[str, Any]]) -> str:
    """Convert topology to Graphviz DOT format."""
    dot = ["digraph topology {", "  rankdir=LR;", "  node [shape=box];"]
    for node in nodes:
        label = f"{node.get('namespace', 'default')}\\n{node.get('name', 'unknown')}\\n({node.get('type', 'unknown')})"
        dot.append(f'  "{node["id"]}" [label="{label}"];')
    for edge in edges:
        dot.append(f'  "{edge["source"]}" -> "{edge["target"]}" [label="{edge.get("relationship", "")}"];')
    dot.append("}")
    return "\n".join(dot)


def convert_to_mermaid(nodes: List[Dict[str, Any]], edges: List[Dict[str, Any]]) -> str:
    """Convert topology to Mermaid diagram format."""
    lines = ["graph LR"]
    for node in nodes:
        nid = node["id"].replace(":", "_").replace("/", "_")
        label = f"{node.get('name', 'unknown')}<br/>({node.get('type', 'unknown')})"
        lines.append(f'  {nid}["{label}"]')
    for edge in edges:
        sid = edge["source"].replace(":", "_").replace("/", "_")
        tid = edge["target"].replace(":", "_").replace("/", "_")
        lines.append(f'  {sid} -->|{edge.get("relationship", "")}| {tid}')
    return "\n".join(lines)


def handle_resource_fetch_error(e: Exception, resource_type: str, namespace: str, skip_on_permission_denied: bool, logger_inst) -> Dict[str, Any]:
    """Handle errors during resource fetching with permission-aware logic."""
    from kubernetes.client.rest import ApiException

    result = {"success": False, "permission_denied": False, "error_message": str(e)}
    if isinstance(e, ApiException):
        if e.status == 403:
            result["permission_denied"] = True
        elif e.status == 404:
            logger_inst.debug(f"Resource type {resource_type} not found in {namespace}")
        else:
            logger_inst.warning(f"API error fetching {resource_type} in {namespace}: {e.status}")
    return result
