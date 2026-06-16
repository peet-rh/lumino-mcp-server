"""Prometheus query helpers extracted from upstream server-mcp.py."""

import csv
import io
import logging
import os
import re
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger("lumino-mcp")

try:
    import aiohttp
    _HAS_AIOHTTP = True
except ImportError:
    _HAS_AIOHTTP = False

_prometheus_endpoint_cache: Dict[str, str] = {}


def _is_running_in_cluster() -> bool:
    return os.path.exists("/var/run/secrets/kubernetes.io/serviceaccount/token")


async def get_k8s_bearer_token() -> Optional[str]:
    """Get bearer token for Prometheus auth from K8s config, SA token, or env."""
    try:
        from kubernetes.client import Configuration
        k8s_config = Configuration.get_default_copy()
        if k8s_config.api_key and k8s_config.api_key.get("authorization"):
            auth_header = k8s_config.api_key["authorization"]
            if auth_header.startswith("Bearer "):
                return auth_header[7:]
    except Exception:
        pass

    sa_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
    try:
        if os.path.exists(sa_path):
            with open(sa_path) as f:
                token = f.read().strip()
                if token:
                    return token
    except Exception:
        pass

    token = os.getenv("PROMETHEUS_TOKEN") or os.getenv("OPENSHIFT_TOKEN") or os.getenv("OC_TOKEN")
    if token:
        return token

    return None


async def discover_prometheus_via_routes(client_call) -> Optional[str]:
    """Discover Prometheus endpoint via OpenShift Routes."""
    try:
        routes = await client_call(
            "custom", "list_namespaced_custom_object",
            group="route.openshift.io", version="v1",
            namespace="openshift-monitoring", plural="routes",
        )

        preferred_routes = ["prometheus-k8s", "thanos-querier"]
        route_items = routes.get("items", [])
        route_map = {r.get("metadata", {}).get("name"): r for r in route_items}

        for route_name in preferred_routes:
            if route_name in route_map:
                route = route_map[route_name]
                spec = route.get("spec", {})
                host = spec.get("host")
                if host:
                    tls = spec.get("tls")
                    protocol = "https" if tls else "http"
                    endpoint = f"{protocol}://{host}"
                    logger.info(f"Discovered Prometheus via route '{route_name}': {endpoint}")
                    return endpoint

        for route in route_items:
            name = route.get("metadata", {}).get("name", "")
            if "prometheus" in name.lower():
                host = route.get("spec", {}).get("host")
                if host:
                    tls = route.get("spec", {}).get("tls")
                    protocol = "https" if tls else "http"
                    return f"{protocol}://{host}"

    except Exception as e:
        logger.debug(f"Error discovering Prometheus via routes: {e}")

    return None


async def discover_prometheus_via_operator_crd(client_call) -> Optional[str]:
    """Discover Prometheus via Prometheus Operator CRDs."""
    try:
        prometheus_resources = await client_call(
            "custom", "list_cluster_custom_object",
            group="monitoring.coreos.com", version="v1", plural="prometheuses",
        )

        for prom in prometheus_resources.get("items", []):
            metadata = prom.get("metadata", {})
            name = metadata.get("name")
            namespace = metadata.get("namespace")
            if not name or not namespace:
                continue

            service_name = f"prometheus-{name}"
            try:
                service = await client_call(
                    "core_v1", "read_namespaced_service",
                    name=service_name, namespace=namespace,
                )
                ports = service.spec.ports or []
                port = 9090
                for p in ports:
                    if p.name in ["web", "http", "prometheus"] or p.port == 9090:
                        port = p.port
                        break
                endpoint = f"http://{service_name}.{namespace}.svc.cluster.local:{port}"
                logger.info(f"Discovered Prometheus via Operator CRD: {endpoint}")
                return endpoint
            except Exception:
                continue

    except Exception as e:
        logger.debug(f"Error discovering Prometheus via Operator CRD: {e}")

    return None


async def discover_prometheus_via_services(client_call) -> Optional[str]:
    """Discover Prometheus by searching for services with prometheus-related names."""
    monitoring_namespaces = [
        "openshift-monitoring", "monitoring", "prometheus",
        "kube-prometheus", "observability",
    ]

    excluded_suffixes = [
        "-alertmanager", "-pushgateway", "-node-exporter",
        "-kube-state-metrics", "-headless", "-operated",
    ]

    try:
        for namespace in monitoring_namespaces:
            try:
                services = await client_call(
                    "core_v1", "list_namespaced_service", namespace=namespace,
                )

                priority_names = ["prometheus-server", "prometheus-k8s", "prometheus"]
                for priority_name in priority_names:
                    for service in services.items:
                        if service.metadata.name == priority_name:
                            ports = service.spec.ports or []
                            port = 9090
                            for p in ports:
                                if p.port in [9090, 80, 443] or (p.name and p.name in ["web", "http", "https"]):
                                    port = p.port
                                    break
                            endpoint = f"http://{priority_name}.{namespace}.svc.cluster.local:{port}"
                            logger.info(f"Discovered Prometheus service (priority match): {endpoint}")
                            return endpoint

                for service in services.items:
                    name = service.metadata.name
                    if "prometheus" in name.lower():
                        if any(name.lower().endswith(suffix) for suffix in excluded_suffixes):
                            continue
                        ports = service.spec.ports or []
                        port = 9090
                        for p in ports:
                            if p.port in [9090, 80, 443] or (p.name and p.name in ["web", "http", "https"]):
                                port = p.port
                                break
                        endpoint = f"http://{name}.{namespace}.svc.cluster.local:{port}"
                        logger.info(f"Discovered Prometheus service: {endpoint}")
                        return endpoint

            except Exception:
                continue

        label_selectors = [
            "app=prometheus",
            "app.kubernetes.io/name=prometheus",
            "app.kubernetes.io/component=prometheus",
        ]
        for label_selector in label_selectors:
            try:
                services = await client_call(
                    "core_v1", "list_service_for_all_namespaces",
                    label_selector=label_selector,
                )
                if services.items:
                    service = services.items[0]
                    name = service.metadata.name
                    ns = service.metadata.namespace
                    ports = service.spec.ports or []
                    port = 9090
                    for p in ports:
                        if p.port == 9090 or (p.name and p.name in ["web", "http"]):
                            port = p.port
                            break
                    endpoint = f"http://{name}.{ns}.svc.cluster.local:{port}"
                    logger.info(f"Discovered Prometheus via label selector '{label_selector}': {endpoint}")
                    return endpoint
            except Exception:
                continue

    except Exception as e:
        logger.warning(f"Error discovering Prometheus via services: {e}")

    return None


async def discover_prometheus_endpoint(client_call, cluster_override: Optional[str] = None) -> Optional[str]:
    """Discover Prometheus endpoint using multiple strategies."""
    env_url = os.getenv("PROMETHEUS_URL")
    if env_url:
        logger.info(f"Using Prometheus from PROMETHEUS_URL: {env_url}")
        return env_url

    cache_key = cluster_override or "default"
    if cache_key in _prometheus_endpoint_cache:
        return _prometheus_endpoint_cache[cache_key]

    if _is_running_in_cluster():
        discovery_methods = [
            ("Service Discovery", discover_prometheus_via_services),
            ("Prometheus Operator CRD", discover_prometheus_via_operator_crd),
            ("OpenShift Routes", discover_prometheus_via_routes),
        ]
    else:
        discovery_methods = [
            ("OpenShift Routes", discover_prometheus_via_routes),
            ("Prometheus Operator CRD", discover_prometheus_via_operator_crd),
            ("Service Discovery", discover_prometheus_via_services),
        ]

    for method_name, discovery_func in discovery_methods:
        try:
            endpoint = await discovery_func(client_call)
            if endpoint:
                _prometheus_endpoint_cache[cache_key] = endpoint
                return endpoint
        except Exception as e:
            logger.warning(f"Discovery method '{method_name}' failed: {e}")

    logger.error("Could not discover Prometheus endpoint via any method")
    return None


def parse_time_parameter(time_param: str) -> str:
    """Parse time parameter to Unix timestamp for Prometheus API."""
    try:
        if time_param.isdigit():
            return time_param
        if "T" in time_param:
            dt = datetime.fromisoformat(time_param.replace("Z", "+00:00"))
            return str(int(dt.timestamp()))
        for fmt in ["%Y-%m-%d %H:%M:%S", "%Y-%m-%d"]:
            try:
                dt = datetime.strptime(time_param, fmt)
                return str(int(dt.timestamp()))
            except ValueError:
                continue
        return time_param
    except Exception:
        return time_param


async def execute_prometheus_query_internal(
    client_call, query: str, timeout: int = 30
) -> Dict[str, Any]:
    """Execute a Prometheus instant query and return results."""
    if not _HAS_AIOHTTP:
        return {"success": False, "data": [], "error": "aiohttp not installed"}

    try:
        prometheus_url = await discover_prometheus_endpoint(client_call)
        if not prometheus_url:
            return {"success": False, "data": [], "error": "Could not discover Prometheus endpoint"}

        auth_token = await get_k8s_bearer_token()
        api_path = "/api/v1/query"
        params = {"query": query, "timeout": f"{timeout}s"}
        query_url = f"{prometheus_url}{api_path}"

        headers = {"Accept": "application/json", "User-Agent": "LUMINO-MCP/1.0"}
        if auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"

        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout + 10)) as session:
            async with session.get(query_url, params=params, headers=headers, ssl=False) as response:
                if response.status == 200:
                    data = await response.json()
                    raw_results = data.get("data", {}).get("result", [])
                    return {"success": True, "data": raw_results, "error": None}
                else:
                    error_text = await response.text()
                    return {"success": False, "data": [], "error": f"HTTP {response.status}: {error_text}"}

    except Exception as e:
        return {"success": False, "data": [], "error": str(e)}


async def process_prometheus_results(
    response_data: Dict[str, Any],
    format_type: str,
    namespace_filter: Optional[str],
    limit: Optional[int],
    original_query: str,
    query_type: str,
) -> Dict[str, Any]:
    """Process and format Prometheus query results."""
    try:
        result_data = response_data.get("data", {})
        result_type = result_data.get("resultType", "")
        raw_results = result_data.get("result", [])

        if namespace_filter:
            try:
                pattern = re.compile(namespace_filter)
                raw_results = [
                    r for r in raw_results
                    if pattern.search(r.get("metric", {}).get("namespace", ""))
                ]
            except re.error:
                pass

        if limit and len(raw_results) > limit:
            raw_results = raw_results[:limit]

        MAX_SERIES = 500
        if len(raw_results) > MAX_SERIES:
            raw_results = raw_results[:MAX_SERIES]

        if format_type == "table":
            formatted_data = format_as_table(raw_results, result_type)
        elif format_type == "csv":
            formatted_data = format_as_csv(raw_results, result_type)
        else:
            formatted_data = format_as_json(raw_results, result_type)

        summary = generate_result_summary(raw_results, result_type, original_query)
        suggestions = generate_related_query_suggestions(original_query, raw_results)

        return {
            "result_count": len(raw_results),
            "result_type": result_type,
            "data": formatted_data,
            "summary": summary,
            "suggestions": suggestions,
            "errors": [],
            "metadata": {
                "namespace_filter": namespace_filter,
                "limit": limit,
                "format": format_type,
                "query_type": query_type,
            },
        }

    except Exception as e:
        return {
            "result_count": 0,
            "result_type": "unknown",
            "data": [],
            "summary": "Error processing results",
            "suggestions": ["Check query syntax", "Try simpler query"],
            "errors": [str(e)],
        }


def format_as_table(results: List[Dict], result_type: str) -> str:
    """Format results as a human-readable table."""
    if not results:
        return "No data returned"

    try:
        if result_type == "vector":
            headers = ["Metric"] + list(results[0].get("metric", {}).keys()) + ["Value"]
            rows = []
            for result in results:
                metric = result.get("metric", {})
                value = result.get("value", ["", ""])[1] if result.get("value") else "N/A"
                metric_name = metric.get("__name__", "")
                row = [metric_name] + [metric.get(key, "") for key in headers[1:-1]] + [value]
                rows.append(row)

        elif result_type == "matrix":
            headers = ["Metric", "Namespace", "Values (timestamp:value)"]
            rows = []
            for result in results:
                metric = result.get("metric", {})
                values = result.get("values", [])
                metric_name = metric.get("__name__", "")
                namespace = metric.get("namespace", "")
                value_pairs = [f"{ts}:{val}" for ts, val in values[:5]]
                if len(values) > 5:
                    value_pairs.append(f"... ({len(values) - 5} more)")
                rows.append([metric_name, namespace, ", ".join(value_pairs)])
        else:
            return f"Unsupported result type for table format: {result_type}"

        if not rows:
            return "No data to display"

        col_widths = [
            max(len(str(header)), max(len(str(row[i])) for row in rows))
            for i, header in enumerate(headers)
        ]

        table_lines = []
        header_line = " | ".join(h.ljust(col_widths[i]) for i, h in enumerate(headers))
        table_lines.append(header_line)
        table_lines.append("-" * len(header_line))
        for row in rows:
            table_lines.append(" | ".join(str(row[i]).ljust(col_widths[i]) for i in range(len(headers))))

        return "\n".join(table_lines)

    except Exception as e:
        return f"Error formatting table: {e}"


def format_as_csv(results: List[Dict], result_type: str) -> str:
    """Format results as CSV."""
    if not results:
        return "No data returned"

    try:
        output = io.StringIO()

        if result_type == "vector":
            fieldnames = ["metric_name"] + list(results[0].get("metric", {}).keys()) + ["value", "timestamp"]
            writer = csv.DictWriter(output, fieldnames=fieldnames)
            writer.writeheader()
            for result in results:
                metric = result.get("metric", {})
                value_data = result.get("value", ["", ""])
                row = {
                    "metric_name": metric.get("__name__", ""),
                    "value": value_data[1] if len(value_data) > 1 else "",
                    "timestamp": value_data[0] if len(value_data) > 0 else "",
                }
                row.update({k: v for k, v in metric.items() if k != "__name__"})
                writer.writerow(row)

        elif result_type == "matrix":
            fieldnames = ["metric_name", "namespace", "timestamp", "value"]
            if results:
                extra_labels = set()
                for result in results:
                    extra_labels.update(
                        k for k in result.get("metric", {}).keys()
                        if k not in ("__name__", "namespace")
                    )
                fieldnames.extend(sorted(extra_labels))

            writer = csv.DictWriter(output, fieldnames=fieldnames)
            writer.writeheader()
            for result in results:
                metric = result.get("metric", {})
                base_row = {
                    "metric_name": metric.get("__name__", ""),
                    "namespace": metric.get("namespace", ""),
                }
                base_row.update({k: v for k, v in metric.items() if k not in ("__name__", "namespace")})
                for timestamp, value in result.get("values", []):
                    row = base_row.copy()
                    row.update({"timestamp": timestamp, "value": value})
                    writer.writerow(row)

        return output.getvalue()

    except Exception as e:
        return f"Error formatting CSV: {e}"


def format_as_json(results: List[Dict], result_type: str) -> List[Dict]:
    """Format results as structured JSON with stats and downsampling."""
    try:
        formatted = []
        for result in results:
            metric = result.get("metric", {})

            if result_type == "vector":
                value_data = result.get("value", [])
                formatted.append({
                    "metric": metric,
                    "value": value_data[1] if len(value_data) > 1 else None,
                    "timestamp": value_data[0] if len(value_data) > 0 else None,
                    "formatted_value": format_metric_value(
                        metric.get("__name__", ""),
                        value_data[1] if len(value_data) > 1 else None,
                    ),
                })

            elif result_type == "matrix":
                values = result.get("values", [])
                total_count = len(values)

                numeric_values = []
                for v in values:
                    try:
                        numeric_values.append(float(v[1]))
                    except (ValueError, TypeError, IndexError):
                        pass

                stats = {}
                if numeric_values:
                    sorted_vals = sorted(numeric_values)
                    stats = {
                        "min": round(min(numeric_values), 4),
                        "max": round(max(numeric_values), 4),
                        "avg": round(sum(numeric_values) / len(numeric_values), 4),
                        "latest": round(numeric_values[-1], 4),
                        "first": round(numeric_values[0], 4),
                        "p50": round(sorted_vals[len(sorted_vals) // 2], 4),
                        "p95": round(
                            sorted_vals[int(len(sorted_vals) * 0.95)], 4
                        ) if len(sorted_vals) > 1 else round(sorted_vals[0], 4),
                    }

                MAX_DP = 50
                if total_count > MAX_DP:
                    step = total_count / MAX_DP
                    sampled = [values[int(i * step)] for i in range(MAX_DP)]
                else:
                    sampled = values

                formatted.append({
                    "metric": metric,
                    "statistics": stats,
                    "values": sampled,
                    "value_count": total_count,
                    "sampled_count": len(sampled),
                    "downsampled": total_count > MAX_DP,
                    "time_range": {
                        "start": values[0][0] if values else None,
                        "end": values[-1][0] if values else None,
                    },
                })
            else:
                formatted.append(result)

        return formatted

    except Exception as e:
        return [{"error": f"Error formatting results: {e}"}]


def format_metric_value(metric_name: str, value: Optional[str]) -> str:
    """Format metric value with appropriate units."""
    if value is None:
        return "N/A"
    try:
        v = float(value)
        if "cpu" in metric_name.lower():
            return f"{v:.3f} CPU seconds" if "seconds" in metric_name.lower() else f"{v:.3f} CPU cores"
        elif "memory" in metric_name.lower() or "bytes" in metric_name.lower():
            if v >= 1024**3:
                return f"{v / (1024**3):.2f} GB"
            elif v >= 1024**2:
                return f"{v / (1024**2):.2f} MB"
            elif v >= 1024:
                return f"{v / 1024:.2f} KB"
            return f"{v:.0f} bytes"
        elif "percent" in metric_name.lower():
            return f"{v:.1f}%"
        return f"{v:.3f}"
    except (ValueError, TypeError):
        return str(value)


def generate_result_summary(results: List[Dict], result_type: str, query: str) -> str:
    """Generate human-readable summary of query results."""
    if not results:
        return f"No data returned for query: {query}"
    try:
        parts = [f"Found {len(results)} metric series"]
        namespaces = {r.get("metric", {}).get("namespace") for r in results if r.get("metric", {}).get("namespace")}
        if namespaces:
            ns_list = ", ".join(sorted(list(namespaces))[:5])
            suffix = f" and {len(namespaces) - 5} more" if len(namespaces) > 5 else ""
            parts.append(f"across {len(namespaces)} namespaces: {ns_list}{suffix}")
        metric_names = {r.get("metric", {}).get("__name__") for r in results if r.get("metric", {}).get("__name__")}
        if metric_names:
            m_list = ", ".join(sorted(list(metric_names))[:3])
            suffix = f" and {len(metric_names) - 3} more" if len(metric_names) > 3 else ""
            parts.append(f"Metric types: {m_list}{suffix}")
        return ". ".join(parts) + "."
    except Exception:
        return f"Query returned {len(results)} results"


def generate_query_suggestions(query: str, error_message: str) -> List[str]:
    """Generate helpful suggestions based on query and error."""
    suggestions = []
    if "parse error" in error_message.lower():
        suggestions.extend([
            "Check PromQL syntax - ensure proper use of operators and functions",
            "Verify metric names and label selectors are correctly formatted",
            'Example: up{job="node-exporter"} or rate(http_requests_total[5m])',
        ])
    if "unknown metric" in error_message.lower() or "not found" in error_message.lower():
        suggestions.extend([
            "Check if the metric name is spelled correctly",
            'Try querying available metrics with: {__name__=~".*"}',
            "Verify the metric is actually being scraped by Prometheus",
        ])
    if "timeout" in error_message.lower():
        suggestions.extend([
            "Try a shorter time range for range queries",
            "Use more specific label selectors to reduce data volume",
        ])
    if "rate(" in query and "[" not in query:
        suggestions.append("rate() function requires a time range: rate(metric[5m])")
    if not suggestions:
        suggestions.extend([
            "Check Prometheus documentation for correct PromQL syntax",
            "Try a simpler query first to test connectivity",
        ])
    return suggestions


def generate_related_query_suggestions(original_query: str, results: List[Dict]) -> List[str]:
    """Generate suggestions for related queries based on results."""
    suggestions = []
    if not results:
        suggestions.extend([
            "Try expanding the time range if using a range query",
            'Check if the metric exists: {__name__=~".*metric_name.*"}',
        ])
        return suggestions

    try:
        metric_names = {r.get("metric", {}).get("__name__") for r in results if r.get("metric", {}).get("__name__")}
        namespaces = {r.get("metric", {}).get("namespace") for r in results if r.get("metric", {}).get("namespace")}

        if metric_names:
            example = list(metric_names)[0]
            if "cpu" in example:
                suggestions.append("Related memory usage: sum(container_memory_working_set_bytes) by (namespace)")
            elif "memory" in example:
                suggestions.append("Related CPU usage: sum(rate(container_cpu_usage_seconds_total[5m])) by (namespace)")
            if "rate(" not in original_query and "_total" in example:
                suggestions.append(f"Rate calculation: rate({example}[5m])")

        if namespaces and len(namespaces) > 1:
            suggestions.append(f'Filter by namespace: {{namespace="{list(namespaces)[0]}"}}')
        if "topk(" not in original_query:
            suggestions.append(f"Top 10 results: topk(10, {original_query})")

    except Exception:
        pass

    return suggestions[:5]
