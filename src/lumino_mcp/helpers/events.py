"""Internal event helper functions extracted from upstream server-mcp.py."""

import asyncio
import json
import logging
import re
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Union

from . import parse_time_period

logger = logging.getLogger("lumino-mcp")


async def get_namespace_events_internal(
    client_call,
    namespace: str,
    last_n_events: Optional[int] = None,
    time_period: Optional[str] = None,
    max_fetch_limit: int = 5000,
    context: Optional[str] = None,
) -> Dict[str, Any]:
    """Fetch K8s events from a namespace with optional filtering and pagination.

    Args:
        client_call: async callable matching client.call(api, method, **kwargs)
        namespace: Kubernetes namespace
        last_n_events: Limit to last N events
        time_period: e.g. '1h', '30m', '2d'
        max_fetch_limit: Max events per page
        context: Optional cluster context
    """
    from kubernetes.client.rest import ApiException

    output: Dict[str, Any] = {
        "namespace": namespace,
        "events": [],
        "errors": [],
        "applied_filters": {},
    }

    try:
        cutoff_time = None
        if time_period is not None:
            try:
                time_delta = parse_time_period(time_period)
                cutoff_time = datetime.now() - time_delta
                output["applied_filters"]["time_period"] = time_period
                output["applied_filters"]["cutoff_time"] = cutoff_time.isoformat()
            except Exception as e:
                output["errors"].append(f"Error parsing time period: {e}")

        all_events = []
        continue_token = None
        page_count = 0
        MAX_PAGES = 20

        while page_count < MAX_PAGES:
            try:
                kwargs: Dict[str, Any] = {
                    "namespace": namespace,
                    "watch": False,
                    "limit": max_fetch_limit,
                }
                if context:
                    kwargs["context"] = context
                if continue_token:
                    kwargs["_continue"] = continue_token

                event_list_response = await client_call(
                    "core_v1", "list_namespaced_event", **kwargs
                )

                page_count += 1
                all_events.extend(event_list_response.items)
                continue_token = event_list_response.metadata._continue

                if not continue_token:
                    break
                if last_n_events and len(all_events) >= last_n_events * 2:
                    break
                if cutoff_time and event_list_response.items:

                    def _get_event_time(event):
                        ts = event.last_timestamp or event.first_timestamp
                        if ts is None:
                            return datetime.max
                        return ts.replace(tzinfo=None) if ts.tzinfo else ts

                    oldest = min(event_list_response.items, key=_get_event_time)
                    if _get_event_time(oldest) < cutoff_time:
                        break

            except ApiException as e:
                if e.status == 410:
                    break
                raise

        if page_count >= MAX_PAGES and continue_token:
            output["errors"].append(
                f"Event fetching limited to {len(all_events)} events due to volume."
            )

        original_count = len(all_events)

        def _comparable_ts(event):
            ts = event.last_timestamp or event.first_timestamp
            if ts is None:
                return datetime.min.replace(tzinfo=None)
            return ts.replace(tzinfo=None) if ts.tzinfo else ts

        events = sorted(all_events, key=_comparable_ts, reverse=True)

        if cutoff_time is not None:
            events = [e for e in events if _comparable_ts(e) >= cutoff_time]

        if last_n_events is not None and len(events) > last_n_events:
            events = events[:last_n_events]
            output["applied_filters"]["last_n_events"] = last_n_events

        events_list: List[str] = []
        for event in events:
            try:
                timestamp = event.last_timestamp or event.first_timestamp or "Unknown"
                event_str = f"[{timestamp}] {event.type}: {event.reason} - {event.message}"
                if event.involved_object:
                    event_str += f" (Object: {event.involved_object.kind}/{event.involved_object.name})"
                events_list.append(event_str)
            except Exception as e:
                output["errors"].append(f"Error formatting event: {e}")

        output["events"] = events_list
        output["original_events_count"] = original_count
        output["filtered_events_count"] = len(events_list)
        output["pagination_info"] = {
            "pages_fetched": page_count,
            "hit_page_limit": page_count >= MAX_PAGES and continue_token is not None,
        }
        return output

    except Exception as e:
        return {
            "namespace": namespace,
            "events": [],
            "errors": [f"Failed to fetch events: {e}"],
            "applied_filters": {},
        }


def filter_analysis_for_synthesis(
    pod_analysis: Dict[str, Any], focus_areas: List[str]
) -> Dict[str, Any]:
    """Filter pod analysis results to essential data for synthesis, preventing token overflow."""
    try:
        filtered = {
            "summary": pod_analysis.get("summary", {}),
            "metadata": {
                "total_log_lines": pod_analysis.get("metadata", {})
                .get("processing_metrics", {})
                .get("total_log_lines", 0),
                "patterns_extracted": pod_analysis.get("metadata", {})
                .get("processing_metrics", {})
                .get("patterns_extracted", 0),
                "processing_time_seconds": pod_analysis.get("metadata", {})
                .get("processing_metrics", {})
                .get("processing_time_seconds", 0),
            },
        }

        if "patterns" in pod_analysis:
            filtered["patterns"] = {}
            for area in focus_areas:
                if area in pod_analysis["patterns"] and pod_analysis["patterns"][area]:
                    filtered["patterns"][area] = pod_analysis["patterns"][area][:3]

        if "representative_samples" in pod_analysis:
            filtered["representative_samples"] = {}
            for area in focus_areas:
                if area in pod_analysis["representative_samples"]:
                    filtered["representative_samples"][area] = pod_analysis[
                        "representative_samples"
                    ][area][:2]

        return filtered

    except Exception:
        return {
            "summary": pod_analysis.get(
                "summary", "Analysis available but filtered due to size"
            ),
            "metadata": {"filtered": True, "reason": "token_overflow_prevention"},
        }


def compress_events_for_synthesis(events_result: Dict[str, Any]) -> Dict[str, Any]:
    """Compress event analysis results to essential information for synthesis."""
    try:
        if not events_result or "error" in events_result:
            return events_result

        compressed = {
            "namespace": events_result.get("namespace"),
            "strategy_used": events_result.get("strategy_used"),
            "total_events": events_result.get("total_events", 0),
            "processed_events": events_result.get("processed_events", 0),
        }

        if "events" in events_result and events_result["events"]:
            sorted_events = sorted(
                events_result["events"],
                key=lambda e: (
                    e.get("severity") == "CRITICAL",
                    e.get("relevance_score", 0),
                ),
                reverse=True,
            )
            compressed["critical_events"] = sorted_events[:5]

        if "summary" in events_result:
            compressed["summary"] = events_result["summary"]
        if "insights" in events_result:
            compressed["insights"] = events_result["insights"][:3]
        if "recommendations" in events_result:
            compressed["recommendations"] = events_result["recommendations"][:3]

        return compressed

    except Exception:
        return {
            "compressed": True,
            "total_events": events_result.get("total_events", 0),
        }


async def quick_volume_estimate(
    client_call, namespace: str, pod_name: str, context: Optional[str] = None
) -> int:
    """Quick estimate of log volume by sampling the last 5 minutes."""
    try:
        from .. import client as _client

        _client._ensure_clients()
        core_api = _client._get_client("core_v1")

        log_content = await asyncio.to_thread(
            core_api.read_namespaced_pod_log,
            name=pod_name,
            namespace=namespace,
            since_seconds=300,
            tail_lines=1000,
        )

        if log_content:
            sample_lines = len(log_content.split("\n"))
            estimated_total = sample_lines * (24 * 60 / 5)
            return int(estimated_total)

    except Exception:
        pass

    return 10000


def handle_api_exception(
    e, tool_name: str, strategy: str, namespace: str, label_selector: str, results_dict: Dict[str, str]
) -> None:
    """Handle Kubernetes API exceptions consistently."""
    from kubernetes.client.rest import ApiException

    strategy_lower = strategy.lower()

    if isinstance(e, ApiException):
        if e.status == 404:
            results_dict[f"info_{strategy_lower}_404"] = (
                f"Namespace '{namespace}' or pods with label '{label_selector}' not found"
            )
        elif e.status == 403:
            results_dict[f"error_{strategy_lower}_403"] = (
                f"Insufficient permissions for namespace '{namespace}'. "
                f"Required: pods/list, pods/log permissions"
            )
        elif e.status == 401:
            results_dict[f"error_{strategy_lower}_401"] = (
                "Authentication failed. Check kubeconfig and credentials"
            )
        else:
            results_dict[f"error_{strategy_lower}_api"] = f"API error {e.status}: {e.reason}"


def get_logs_with_k8s_client(
    k8s_core_api,
    pod_names: List[str],
    namespace: str,
    container_name: str,
    target_logs_dict: Dict[str, str],
    log_params: Dict[str, Any],
) -> bool:
    """Fetch logs for a list of pod names with flexible time and line filtering."""
    at_least_one_log_fetched = False

    for pod_name in pod_names:
        try:
            log_kwargs: Dict[str, Any] = {
                "name": pod_name,
                "namespace": namespace,
                "container": container_name,
                "timestamps": log_params.get("timestamps", True),
                "follow": log_params.get("follow", False),
                "previous": log_params.get("previous", False),
            }

            if log_params.get("since_time"):
                log_kwargs["since"] = log_params["since_time"]
            elif log_params.get("since_seconds"):
                log_kwargs["since_seconds"] = log_params["since_seconds"]
            elif log_params.get("tail_lines"):
                log_kwargs["tail_lines"] = log_params["tail_lines"]

            log_kwargs = {k: v for k, v in log_kwargs.items() if v is not None}
            log_content = k8s_core_api.read_namespaced_pod_log(**log_kwargs)

            if log_content:
                target_logs_dict[pod_name] = log_content
                at_least_one_log_fetched = True
            else:
                target_logs_dict[pod_name] = (
                    "INFO: No logs available for the specified time period/criteria"
                )

        except Exception as e:
            target_logs_dict[pod_name] = f"ERROR: {e}"

    return at_least_one_log_fetched


def filter_logs_by_time_range(logs: str, until_time: datetime) -> str:
    """Filter log lines to only include entries before until_time."""
    if not logs:
        return logs

    filtered_lines = []
    for line in logs.split("\n"):
        ts_match = re.match(
            r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})", line
        )
        if ts_match:
            try:
                line_time = datetime.fromisoformat(ts_match.group(1))
                if line_time <= until_time:
                    filtered_lines.append(line)
            except Exception:
                filtered_lines.append(line)
        else:
            filtered_lines.append(line)

    return "\n".join(filtered_lines)


def clean_etcd_logs(raw_logs: str) -> str:
    """Clean etcd logs by removing escape characters and formatting JSON entries."""
    if not raw_logs or raw_logs.strip() == "":
        return raw_logs

    try:
        lines = raw_logs.strip().split("\n")
        cleaned_lines = []

        for line in lines:
            line = line.strip()
            if not line:
                continue

            if line.startswith(("ERROR:", "INFO:")):
                cleaned_lines.append(line)
                continue

            try:
                ts_match = re.match(
                    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z)\s+(.*)$", line
                )

                if ts_match:
                    k8s_ts = ts_match.group(1)
                    json_part = ts_match.group(2)
                    json_part = json_part.replace('\\\\"', '"')
                    json_part = json_part.replace("\\n", "\n")
                    json_part = json_part.replace("\\/", "/")

                    try:
                        obj = json.loads(json_part)
                        level = obj.get("level", "unknown")
                        etcd_ts = obj.get("ts", "")
                        caller = obj.get("caller", "")
                        msg = obj.get("msg", "")

                        parts = []
                        ts_use = etcd_ts if etcd_ts else k8s_ts
                        if ts_use:
                            parts.append(f"[{ts_use}]")
                        if level:
                            parts.append(f"[{level.upper()}]")
                        if caller:
                            parts.append(f"[{caller}]")
                        if msg:
                            parts.append(msg)

                        for key, value in obj.items():
                            if key not in ("level", "ts", "caller", "msg") and value is not None:
                                parts.append(f"{key}={value}" if isinstance(value, (str, int, float, bool)) else f"{key}={json.dumps(value)}")

                        cleaned_lines.append(" ".join(parts))
                    except json.JSONDecodeError:
                        cleaned_lines.append(f"[{k8s_ts}] {json_part}")
                else:
                    cleaned_lines.append(line)

            except Exception:
                cleaned_lines.append(f"[UNPARSED] {line}")

        result = "\n".join(cleaned_lines)
        result = re.sub(r"\n\s*\n", "\n", result)
        return result.strip()

    except Exception:
        return raw_logs
