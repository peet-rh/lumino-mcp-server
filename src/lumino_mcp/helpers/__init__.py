import asyncio
import base64
import json
import logging
import re
from collections import Counter
from datetime import datetime, timedelta, timezone

logger = logging.getLogger("lumino-mcp")

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.x509.oid import NameOID, ExtensionOID
    _HAS_CRYPTO = True
except ImportError:
    _HAS_CRYPTO = False


# ---- Time parsing ----

def parse_time_period(time_period: str) -> timedelta:
    match = re.match(r'^(\d+)([smhd])$', time_period.lower())
    if not match:
        raise ValueError(f"Invalid time period: {time_period} (expected e.g. '1h', '30m', '2d')")
    value, unit = int(match.group(1)), match.group(2)
    return {"s": timedelta(seconds=value), "m": timedelta(minutes=value),
            "h": timedelta(hours=value), "d": timedelta(days=value)}[unit]


# ---- Event classification keywords ----

SEVERITY_KEYWORDS = {
    "CRITICAL": ["oom", "killed", "crash", "panic", "fatal", "critical",
                 "emergency", "disaster", "outage", "down", "unavailable"],
    "HIGH": ["error", "failed", "failure", "exception", "timeout",
             "unreachable", "denied", "refused", "invalid"],
    "MEDIUM": ["warning", "warn", "retry", "slow", "degraded",
               "pending", "waiting", "delayed"],
    "LOW": ["info", "created", "started", "completed", "successful",
            "ready", "healthy", "normal"],
}

CATEGORY_KEYWORDS = {
    "FAILURE": ["failed", "failure", "error", "crash", "panic", "exception",
                "abort", "terminated", "killed", "died", "backoff"],
    "IMAGE": ["imagepull", "pullimage", "errimagepull", "imagepullbackoff",
              "pull image", "pulling image", "image pull", "registry"],
    "STORAGE": ["volume", "disk", "storage", "mount", "pvc", "pv",
                "filesystem", "unmount", "failedmount", "failedattach"],
    "NETWORKING": ["network", "dns", "connection", "unreachable",
                   "endpoint", "route", "ingress", "addedinterface"],
    "RESOURCE": ["memory", "cpu", "oom", "oomkilled", "quota exceeded",
                 "resource quota", "limitrange", "evicted"],
    "SCHEDULING": ["scheduled", "unschedulable", "failedscheduling", "preempted",
                   "affinity", "taint", "toleration", "nodeaffinity"],
    "CONFIGURATION": ["configmap", "secret", "createcontainerconfigerror",
                      "invalidargument", "envvar"],
    "SECURITY": ["forbidden", "unauthorized", "accessdenied", "permission denied",
                 "securitycontext", "podsecurity", "scc violation"],
    "SCALING": ["scaled", "scaling", "replicas", "horizontalpodautoscaler",
                "hpa", "scaleup", "scaledown"],
    "LIFECYCLE": ["created", "started", "stopped", "deleted", "killing",
                  "prestop", "poststart", "liveness", "readiness"],
    "HEALTH": ["healthy", "unhealthy", "probe", "livenessprobe", "readinessprobe",
               "startupprobe", "health check"],
}


# ---- Duration / token utilities ----

def calculate_duration(start_time, end_time) -> str:
    if not start_time:
        return "unknown"
    if not end_time:
        return "unknown"
    try:
        if isinstance(start_time, str):
            start = datetime.fromisoformat(start_time.replace("Z", "+00:00"))
        else:
            start = start_time
        if isinstance(end_time, str):
            end = datetime.fromisoformat(end_time.replace("Z", "+00:00"))
        else:
            end = end_time
            if start.tzinfo and not end.tzinfo:
                end = end.replace(tzinfo=timezone.utc)

        secs = (end - start).total_seconds()
        if secs < 60:
            return f"{secs:.1f}s"
        if secs < 3600:
            return f"{secs / 60:.1f}m"
        if secs < 86400:
            return f"{secs / 3600:.1f}h"
        return f"{int(secs // 86400)}d {(secs % 86400) / 3600:.1f}h"
    except Exception:
        return "unknown"


def estimate_tokens(text: str) -> int:
    return len(text) // 3


# ---- Error pattern extraction ----

_ERROR_PATTERNS = [
    "Error:", "Exception:", "Failed:", "fatal:", "panic:",
    "cannot", "unable to", "failed to", "error", "invalid",
    "No such file", "Permission denied", "Out of memory",
    "Connection refused", "timed out",
    "OOMKilled", "CrashLoopBackOff", "ImagePullBackOff", "ErrImagePull",
    "CreateContainerConfigError", "CreateContainerError",
    "FailedMount", "FailedAttachVolume", "FailedScheduling",
    "Unschedulable", "BackOff", "Evicted",
    "container killed", "container exited", "restart count",
    "liveness probe failed", "readiness probe failed",
    "dial tcp", "no route to host", "connection reset",
    "quota exceeded", "limit exceeded", "insufficient",
]


def extract_error_patterns(log_text: str) -> list[str]:
    if not log_text:
        return []
    lines = []
    for line in log_text.split("\n"):
        line = line.strip()
        if len(line) > 10 and any(p.lower() in line.lower() for p in _ERROR_PATTERNS):
            lines.append(line[:200])
    return lines[:15]


def categorize_errors(log_text: str, error_patterns: list[str]) -> dict[str, int]:
    categories = {
        "oom": ["oomkilled", "oom killed", "out of memory", "memory limit exceeded"],
        "crash": ["crashloopbackoff", "crash loop", "container crashed", "backoff restarting"],
        "image": ["imagepullbackoff", "errimagepull", "image pull", "pull image", "registry"],
        "scheduling": ["unschedulable", "failedscheduling", "insufficient", "node affinity"],
        "storage": ["failedmount", "volume mount", "pvc", "persistent volume", "mount failed"],
        "config": ["createcontainerconfigerror", "configmap", "secret not found", "missing key"],
        "resource_limits": ["memory limit", "cpu limit", "resource quota", "evicted"],
        "network": ["timeout", "connection refused", "connection reset", "unreachable", "dial tcp"],
        "permissions": ["access denied", "permission denied", "forbidden", "unauthorized", "rbac"],
        "dependency": ["not found", "missing dependency", "version mismatch", "incompatible"],
    }
    combined = (log_text + " " + " ".join(error_patterns)).lower()
    return {cat: sum(combined.count(t) for t in terms)
            for cat, terms in categories.items()
            if sum(combined.count(t) for t in terms) > 0}


# ---- Root cause analysis ----

_CATEGORY_DESCRIPTIONS = {
    "resource_limits": "Resource constraints (CPU, memory, or storage limits exceeded)",
    "network": "Network connectivity or DNS resolution issues",
    "permissions": "Permission denied or access control issues",
    "config": "Configuration errors or missing settings",
    "dependency": "External dependency or service unavailability",
    "image": "Container image pull or registry issues",
    "storage": "Volume mount or storage access problems",
    "crash": "Container crash loop or restart issues",
    "oom": "Out of memory — container killed by OOM",
    "scheduling": "Pod scheduling failures — insufficient resources or affinity",
}


def determine_root_cause(error_categories: dict, error_patterns: list[str]) -> dict:
    if not error_categories:
        return {"category": "unknown", "confidence": 0.1,
                "description": "Insufficient data for root cause determination",
                "evidence": error_patterns[:3]}
    top = max(error_categories.items(), key=lambda x: x[1])
    return {
        "category": top[0],
        "confidence": min(0.9, top[1] / 10.0),
        "description": _CATEGORY_DESCRIPTIONS.get(top[0], f"Issues related to {top[0]}"),
        "evidence": error_patterns[:3],
    }


def recommend_actions(root_cause: dict, failed_tasks: list[dict] | None = None) -> list[str]:
    cat = root_cause.get("category", "").lower()
    recs = {
        "oom": ["Increase memory limits for the affected container",
                "Check for memory leaks in the build process",
                "Consider splitting large tasks into smaller steps"],
        "crash": ["Check container logs for crash reason before restart",
                  "Verify container entrypoint and command",
                  "Review liveness/readiness probe configurations"],
        "image": ["Verify the container image exists in the registry",
                  "Check image pull secrets are configured correctly",
                  "Verify registry credentials are valid and not expired"],
        "scheduling": ["Check node resources — ensure sufficient CPU/memory",
                       "Review node selectors and affinity rules",
                       "Check for taints preventing scheduling"],
        "storage": ["Check PVC status and bound PV availability",
                    "Verify storage class exists",
                    "Check if the storage provisioner is healthy"],
        "config": ["Verify referenced ConfigMaps exist and have required keys",
                   "Check Secrets are available and properly referenced"],
        "resource_limits": ["Check resource quotas in the namespace",
                            "Consider increasing CPU/memory limits"],
        "network": ["Verify network policies allow necessary connections",
                    "Check external dependencies are accessible",
                    "Review DNS configuration"],
        "permissions": ["Review RBAC for service accounts",
                        "Check ClusterRoles and RoleBindings",
                        "Verify SA tokens are mounted correctly"],
        "dependency": ["Check image versions in TaskRuns",
                       "Verify external dependencies are available"],
    }
    actions = recs.get(cat, [
        "Review complete logs of failed tasks",
        "Check recent changes to pipeline definitions",
        "Compare with previous successful runs",
    ])
    if failed_tasks:
        names = [t.get("task_name", "unknown") for t in failed_tasks]
        actions.append(f"Focus investigation on failed tasks: {', '.join(names)}")
    return actions


# ---- Event classification ----

def _extract_event_content(event_str: str) -> str:
    if " (Object:" in event_str:
        return event_str.split(" (Object:")[0]
    return event_str


def classify_event_severity(event_str: str) -> str:
    text = _extract_event_content(event_str).lower()
    for severity, keywords in SEVERITY_KEYWORDS.items():
        if any(kw in text for kw in keywords):
            return severity
    return "LOW"


def classify_event_category(event_str: str) -> str:
    text = _extract_event_content(event_str).lower()
    for category, keywords in CATEGORY_KEYWORDS.items():
        if any(kw in text for kw in keywords):
            return category
    return "OTHER"


def estimate_event_tokens(event_str: str) -> int:
    return max(len(event_str) // 4 + 10, 5)


def extract_timestamp_from_event(event_str: str) -> datetime:
    match = re.search(
        r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)",
        event_str,
    )
    if match:
        try:
            ts = match.group(1)
            return datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except ValueError:
            pass
    return datetime.now(tz=timezone.utc)


def smart_sample_events(events: list[str], max_tokens: int) -> list[dict]:
    classified = []
    for ev in events:
        classified.append({
            "event": ev,
            "severity": classify_event_severity(ev),
            "category": classify_event_category(ev),
            "timestamp": extract_timestamp_from_event(ev),
            "tokens": estimate_event_tokens(ev),
        })
    weight = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    classified.sort(key=lambda e: weight.get(e["severity"], 0), reverse=True)

    budget = int(max_tokens * 0.8)
    selected, used = [], 0
    for evt in classified:
        if used + evt["tokens"] <= budget:
            selected.append(evt)
            used += evt["tokens"]
    return selected


def generate_events_summary(classified_events: list[dict]) -> dict:
    if not classified_events:
        return {"total_events": 0, "message": "No events found"}

    severity_counts = Counter(e["severity"] for e in classified_events)
    category_counts = Counter(e["category"] for e in classified_events)
    timestamps = [e["timestamp"] for e in classified_events]
    span = max(timestamps) - min(timestamps) if len(timestamps) > 1 else None
    rate = len(classified_events) / max(span.total_seconds() / 3600, 0.1) if span else 0

    return {
        "total_events": len(classified_events),
        "severity_breakdown": dict(severity_counts),
        "category_breakdown": dict(category_counts),
        "time_span": str(span) if span else "N/A",
        "event_rate_per_hour": round(rate, 2),
        "critical_events": severity_counts.get("CRITICAL", 0),
        "high_events": severity_counts.get("HIGH", 0),
    }


def generate_events_insights(classified_events: list[dict]) -> list[str]:
    if not classified_events:
        return []
    insights = []
    total = len(classified_events)
    critical = sum(1 for e in classified_events if e["severity"] == "CRITICAL")
    high = sum(1 for e in classified_events if e["severity"] == "HIGH")

    if critical > 0:
        insights.append(f"{critical} critical events requiring immediate attention")
    if high > total * 0.3:
        insights.append(f"High severity events: {high / total:.0%} of total")

    top_cat = Counter(e["category"] for e in classified_events).most_common(1)
    if top_cat and top_cat[0][1] > total * 0.4:
        insights.append(f"{top_cat[0][0]} category dominates with {top_cat[0][1]} events")

    timestamps = [e["timestamp"] for e in classified_events]
    if len(timestamps) > 1:
        span = max(timestamps) - min(timestamps)
        if span.total_seconds() < 3600:
            insights.append("Events clustered in short time window — potential incident burst")

    combined = " ".join(_extract_event_content(e.get("event", "")) for e in classified_events).lower()
    if "oom" in combined:
        insights.append("Memory-related issues detected — check resource limits")
    if "imagepull" in combined:
        insights.append("Image pull issues — verify registry connectivity")
    if "timeout" in combined:
        insights.append("Timeout patterns — investigate network latency")

    return insights


# ---- OpenShift: ClusterOperator conditions ----

def analyze_operator_conditions(conditions: list[dict]) -> dict:
    summary = {
        "available": False, "progressing": False, "degraded": False,
        "critical_conditions": [], "warning_conditions": [], "healthy_conditions": [],
    }
    for cond in conditions:
        ctype = cond.get("type", "")
        status = cond.get("status", "Unknown")
        message = cond.get("message", "")
        reason = cond.get("reason", "")

        if ctype == "Available":
            summary["available"] = status == "True"
        elif ctype == "Progressing":
            summary["progressing"] = status == "True"
        elif ctype == "Degraded":
            summary["degraded"] = status == "True"

        entry = {"type": ctype, "message": message, "reason": reason}
        if status == "True" and ctype in ("Degraded", "Failed"):
            summary["critical_conditions"].append(entry)
        elif status == "Unknown" or (status == "False" and ctype == "Available"):
            summary["warning_conditions"].append(entry)
        else:
            summary["healthy_conditions"].append({"type": ctype, "status": status})

    return summary


# ---- OpenShift: MachineConfigPool ----

def analyze_mcp_status(pool: dict) -> dict:
    try:
        meta = pool.get("metadata", {})
        spec = pool.get("spec", {})
        status = pool.get("status", {})
        name = meta.get("name", "unknown")
        total = status.get("machineCount", 0)
        ready = status.get("readyMachineCount", 0)
        updated = status.get("updatedMachineCount", 0)
        degraded = status.get("degradedMachineCount", 0)

        if degraded > 0:
            health = "degraded"
        elif total != ready:
            health = "updating"
        elif total == ready == updated:
            health = "ready"
        else:
            health = "unknown"

        return {
            "name": name,
            "status": health,
            "machine_count": total,
            "ready": ready,
            "updated": updated,
            "degraded": degraded,
            "progress_pct": round((updated / total) * 100, 1) if total else 0,
            "paused": spec.get("paused", False),
            "max_unavailable": spec.get("maxUnavailable", "1"),
            "conditions": status.get("conditions", []),
        }
    except Exception as e:
        return {"name": pool.get("metadata", {}).get("name", "unknown"),
                "status": "error", "error": str(e)}


def detect_pool_issues(pool_analysis: dict) -> list[dict]:
    issues = []
    name = pool_analysis.get("name", "unknown")
    status = pool_analysis.get("status", "unknown")
    degraded = pool_analysis.get("degraded", 0)

    if status == "degraded":
        issues.append({
            "pool": name, "type": "degraded",
            "description": f"{degraded} degraded machine(s)",
            "severity": "high" if degraded > 1 else "medium",
            "remediation": "Check individual node status and machine config application logs",
        })

    if pool_analysis.get("progress_pct", 100) < 100 and status == "updating":
        issues.append({
            "pool": name, "type": "update_in_progress",
            "description": f"Update: {pool_analysis['progress_pct']}% complete",
            "severity": "low",
            "remediation": "Monitor update progress, check for stuck nodes",
        })

    for cond in pool_analysis.get("conditions", []):
        ct, cs = cond.get("type", ""), cond.get("status", "")
        if ct in ("NodeDegraded", "RenderDegraded") and cs == "True":
            issues.append({
                "pool": name, "type": ct.lower(),
                "description": cond.get("message", ""),
                "severity": "high",
                "remediation": f"Investigate: {cond.get('reason', '')}",
            })

    return issues


# ---- Label selector building ----

def build_label_selector(label_selectors: list[dict]) -> str:
    parts = []
    for sel in label_selectors:
        key = sel.get("key", "")
        value = sel.get("value", "")
        op = sel.get("operator", "equals")
        if not key:
            continue
        if op == "equals":
            parts.append(f"{key}={value}" if value else key)
        elif op == "exists":
            parts.append(key)
        elif op == "not_equals" and value:
            parts.append(f"{key}!={value}")
        elif op == "in" and value:
            vals = ",".join(v.strip() for v in value.split(","))
            parts.append(f"{key} in ({vals})")
        elif op == "not_in" and value:
            vals = ",".join(v.strip() for v in value.split(","))
            parts.append(f"{key} notin ({vals})")
    return ",".join(parts)


# ---- Resource API mapping ----

_RESOURCE_MAP = {
    "pods": {"api": "core_v1", "method": "list_namespaced_pod", "namespaced": True},
    "services": {"api": "core_v1", "method": "list_namespaced_service", "namespaced": True},
    "configmaps": {"api": "core_v1", "method": "list_namespaced_config_map", "namespaced": True},
    "secrets": {"api": "core_v1", "method": "list_namespaced_secret", "namespaced": True},
    "persistentvolumeclaims": {"api": "core_v1", "method": "list_namespaced_persistent_volume_claim", "namespaced": True},
    "nodes": {"api": "core_v1", "method": "list_node", "namespaced": False},
    "deployments": {"api": "apps_v1", "method": "list_namespaced_deployment", "namespaced": True},
    "daemonsets": {"api": "apps_v1", "method": "list_namespaced_daemon_set", "namespaced": True},
    "statefulsets": {"api": "apps_v1", "method": "list_namespaced_stateful_set", "namespaced": True},
    "jobs": {"api": "batch_v1", "method": "list_namespaced_job", "namespaced": True},
    "routes": {"api": "custom", "group": "route.openshift.io", "version": "v1", "plural": "routes", "namespaced": True},
    "pipelineruns": {"api": "custom", "group": "tekton.dev", "version": "v1", "plural": "pipelineruns", "namespaced": True},
    "taskruns": {"api": "custom", "group": "tekton.dev", "version": "v1", "plural": "taskruns", "namespaced": True},
}


def get_resource_api_info(resource_type: str) -> dict | None:
    return _RESOURCE_MAP.get(resource_type.lower())


def extract_resource_info(resource: dict, include_spec: bool, include_status: bool) -> dict:
    meta = resource.get("metadata", {})
    info: dict = {
        "kind": resource.get("kind", "Unknown"),
        "metadata": {
            "name": meta.get("name", ""),
            "namespace": meta.get("namespace", ""),
            "labels": meta.get("labels", {}),
            "creation_timestamp": meta.get("creationTimestamp", ""),
        },
    }
    if include_spec:
        info["spec"] = resource.get("spec", {})
    if include_status:
        status = resource.get("status", {})
        info["status"] = {k: v for k, v in {
            "phase": status.get("phase", ""),
            "conditions": status.get("conditions", []),
            "ready_replicas": status.get("readyReplicas"),
            "available_replicas": status.get("availableReplicas"),
        }.items() if v is not None}
    return info


# ---- Resource quota utilization ----

def calculate_utilization(used: str, limit: str) -> float:
    try:
        def _parse(val: str) -> float:
            if val.endswith("m"):
                return float(val[:-1]) / 1000.0
            units = {"Ki": 2**10, "Mi": 2**20, "Gi": 2**30, "Ti": 2**40,
                      "K": 1e3, "M": 1e6, "G": 1e9, "k": 1e3}
            for suffix, mult in units.items():
                if val.endswith(suffix):
                    return float(val[:-len(suffix)]) * mult
            return float(val)
        u, l = _parse(used), _parse(limit)
        return round((u / l) * 100, 1) if l > 0 else 0.0
    except Exception:
        return 0.0


# ---- Pipeline helpers (async) ----

async def get_pipeline_details(namespace: str, pipeline_run: str, custom_api) -> dict:
    from kubernetes.client.rest import ApiException
    try:
        pr = await asyncio.to_thread(
            custom_api.get_namespaced_custom_object,
            group="tekton.dev", version="v1", namespace=namespace,
            plural="pipelineruns", name=pipeline_run,
        )
        meta = pr.get("metadata", {})
        spec = pr.get("spec", {})
        status = pr.get("status", {})
        cond = (status.get("conditions") or [{}])[0]

        pipeline_name = "unknown"
        ref = spec.get("pipelineRef", {})
        if ref and ref.get("name"):
            pipeline_name = ref["name"]
        if pipeline_name == "unknown":
            labels = meta.get("labels", {})
            pipeline_name = (labels.get("tekton.dev/pipeline")
                             or labels.get("pipelines.tekton.dev/pipeline") or "unknown")

        trs = await asyncio.to_thread(
            custom_api.list_namespaced_custom_object,
            group="tekton.dev", version="v1", namespace=namespace,
            plural="taskruns",
            label_selector=f"tekton.dev/pipelineRun={pipeline_run}",
        )
        task_runs = []
        for tr in trs.get("items", []):
            tr_meta = tr.get("metadata", {})
            tr_status = tr.get("status", {})
            tr_cond = (tr_status.get("conditions") or [{}])[0]
            task_runs.append({
                "name": tr_meta.get("name", ""),
                "task": tr.get("spec", {}).get("taskRef", {}).get("name", "unknown"),
                "status": tr_cond.get("reason", "Unknown"),
                "message": tr_cond.get("message", ""),
            })

        return {
            "name": pipeline_run,
            "pipeline": pipeline_name,
            "status": cond.get("reason", "Unknown"),
            "message": cond.get("message", ""),
            "started_at": status.get("startTime", "unknown"),
            "completed_at": status.get("completionTime", "unknown"),
            "duration": calculate_duration(status.get("startTime"), status.get("completionTime")),
            "task_runs": task_runs,
        }
    except ApiException as e:
        return {"error": f"PipelineRun not found: {e.reason}"}


async def get_task_details(namespace: str, task_run: str, custom_api) -> dict:
    from kubernetes.client.rest import ApiException
    try:
        tr = await asyncio.to_thread(
            custom_api.get_namespaced_custom_object,
            group="tekton.dev", version="v1", namespace=namespace,
            plural="taskruns", name=task_run,
        )
        status = tr.get("status", {})
        cond = (status.get("conditions") or [{}])[0]
        steps = []
        for s in status.get("steps", []):
            term = s.get("terminated", {})
            steps.append({
                "name": s.get("name", "unknown"),
                "exit_code": term.get("exitCode") if term else None,
                "reason": term.get("reason") if term else s.get("waiting", {}).get("reason"),
            })
        return {
            "name": task_run,
            "task": tr.get("spec", {}).get("taskRef", {}).get("name", "unknown"),
            "status": cond.get("reason", "Unknown"),
            "message": cond.get("message", ""),
            "pod": status.get("podName", "unknown"),
            "steps": steps,
            "started_at": status.get("startTime", "unknown"),
            "completed_at": status.get("completionTime", "unknown"),
            "duration": calculate_duration(status.get("startTime"), status.get("completionTime")),
        }
    except ApiException as e:
        return {"error": str(e), "name": task_run, "pod": "unknown", "steps": []}


# ---- Pod log helpers (async) ----

async def get_all_pod_logs(pod_name: str, namespace: str, core_api,
                           tail_lines: int | None = None,
                           timestamps: bool = True,
                           previous: bool = False) -> dict[str, str]:
    try:
        pod = await asyncio.to_thread(core_api.read_namespaced_pod,
                                      name=pod_name, namespace=namespace)
        if not pod.spec.containers:
            return {"_error": "No containers"}
        result = {}
        for c in pod.spec.containers:
            params: dict = {"name": pod_name, "namespace": namespace,
                            "container": c.name, "timestamps": timestamps, "previous": previous}
            if tail_lines:
                params["tail_lines"] = tail_lines
            try:
                logs = await asyncio.to_thread(core_api.read_namespaced_pod_log, **params)
                result[c.name] = logs
            except Exception as e:
                result[c.name] = f"Error: {e}"
        return result or {"_error": "No logs"}
    except Exception as e:
        return {"_error": f"Pod error: {e}"}


def clean_pipeline_logs(raw_logs: str) -> str:
    if not raw_logs or not raw_logs.strip():
        return raw_logs
    lines = []
    for line in raw_logs.strip().split("\n"):
        line = re.sub(r'[│┌└├┤┐┘┬┴┼─═║]', '', line).strip()
        if not line:
            continue
        line = re.sub(r'\x1b\[[0-9;]*m', '', line)
        line = line.replace('\\\\"', '"').replace('\\n', '\n').replace('\\/', '/')
        lines.append(line)
    return "\n".join(lines)


# ---- Certificate parsing ----

def parse_certificate(cert_data: str) -> dict | None:
    if not _HAS_CRYPTO:
        return None
    try:
        cert_bytes = cert_data.encode("utf-8") if cert_data.startswith("-----BEGIN") else base64.b64decode(cert_data)
        cert = x509.load_pem_x509_certificate(cert_bytes, default_backend())
        subject_cn = issuer_cn = None
        try:
            subject_cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        except (IndexError, AttributeError):
            pass
        try:
            issuer_cn = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        except (IndexError, AttributeError):
            pass
        san_list: list[str] = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san_list = [name.value for name in san_ext.value]
        except x509.ExtensionNotFound:
            pass
        now = datetime.utcnow()
        days_remaining = (cert.not_valid_after_utc - now.replace(tzinfo=timezone.utc)).days
        return {
            "subject_cn": subject_cn, "issuer_cn": issuer_cn,
            "not_before": cert.not_valid_before_utc.isoformat(),
            "not_after": cert.not_valid_after_utc.isoformat(),
            "days_remaining": days_remaining,
            "serial_number": str(cert.serial_number),
            "signature_algorithm": cert.signature_algorithm_oid._name,
            "san": san_list,
        }
    except Exception:
        return None


def categorize_certificate_status(days_remaining: int, warning_threshold: int, critical_threshold: int) -> str:
    if days_remaining < 0:
        return "expired"
    if days_remaining <= critical_threshold:
        return "critical"
    if days_remaining <= warning_threshold:
        return "warning"
    return "healthy"
