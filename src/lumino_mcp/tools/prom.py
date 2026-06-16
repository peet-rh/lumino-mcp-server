"""Prometheus query tool for Lumino MCP server."""

import asyncio
import json
import logging
import time
from typing import Optional

from ..server import mcp
from .. import client
from ..helpers.prometheus import (
    _HAS_AIOHTTP,
    discover_prometheus_endpoint,
    get_k8s_bearer_token,
    parse_time_parameter,
    process_prometheus_results,
    generate_query_suggestions,
)

if _HAS_AIOHTTP:
    import aiohttp

logger = logging.getLogger("lumino-mcp")


def _error_response(
    error_type: str,
    message: str,
    query: str,
    execution_time: float,
    suggestions: list[str],
    errors: list[str],
) -> str:
    return json.dumps({
        "status": "error",
        "error_type": error_type,
        "message": message,
        "query_executed": query,
        "execution_time": execution_time,
        "result_count": 0,
        "data": [],
        "suggestions": suggestions,
        "errors": errors,
    })


@mcp.tool()
async def prometheus_query(
    query: str,
    query_type: str = "instant",
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    step: str = "300s",
    cluster: Optional[str] = None,
    format: str = "json",
    namespace_filter: Optional[str] = None,
    limit: Optional[int] = None,
    timeout: int = 30,
    context: str | None = None,
) -> str:
    """Execute PromQL queries against Prometheus for cluster metrics.

    Supports instant and range queries with automatic endpoint discovery
    and authentication.

    Args:
        query: PromQL query string.
        query_type: "instant" or "range" (default: "instant").
        start_time: Start for range queries (ISO 8601 or Unix timestamp).
        end_time: End for range queries (ISO 8601 or Unix timestamp).
        step: Step interval for range queries (default: "300s").
        cluster: Cluster domain override.
        format: "json", "table", or "csv" (default: "json").
        namespace_filter: Regex to filter by namespace.
        limit: Max results to return.
        timeout: Query timeout in seconds (default: 30).
        context: Kubernetes context override.
    """
    start_execution_time = time.time()
    tool_name = "prometheus_query"

    if not _HAS_AIOHTTP:
        return json.dumps({
            "error": "aiohttp is not installed — required for Prometheus queries",
        })

    try:
        # Validate query
        if not query or not query.strip():
            return _error_response(
                "invalid_query",
                "Query parameter is required and cannot be empty",
                "",
                0,
                ["Provide a valid PromQL query", 'Example: up{job="node-exporter"}'],
                ["Empty query provided"],
            )

        # Validate query type
        if query_type not in ("instant", "range"):
            return _error_response(
                "invalid_query_type",
                f"Invalid query_type '{query_type}'. Must be 'instant' or 'range'",
                query,
                0,
                [
                    "Use query_type='instant' for current values",
                    "Use query_type='range' for time series",
                ],
                [f"Invalid query_type: {query_type}"],
            )

        # Validate range query parameters
        if query_type == "range" and (not start_time or not end_time):
            return _error_response(
                "missing_time_range",
                "Range queries require both start_time and end_time parameters",
                query,
                0,
                [
                    "Provide start_time and end_time for range queries",
                    "Use ISO 8601 format: '2024-01-01T00:00:00Z'",
                    "Or Unix timestamps: '1704067200'",
                ],
                ["Missing time range parameters for range query"],
            )

        # Get bearer token (optional — vanilla K8s may not need one)
        auth_token = await get_k8s_bearer_token()
        if not auth_token:
            logger.info(
                f"[{tool_name}] No bearer token available — will attempt "
                "unauthenticated request"
            )

        # Discover Prometheus endpoint
        async def _client_call(api, method, **kwargs):
            return await client.call(api, method, context=context, **kwargs)

        prometheus_url = await discover_prometheus_endpoint(
            _client_call, cluster_override=cluster,
        )
        if not prometheus_url:
            return _error_response(
                "endpoint_discovery_failed",
                "Could not discover Prometheus endpoint",
                query,
                0,
                [
                    "Check if Prometheus is deployed (openshift-monitoring, "
                    "monitoring, or prometheus namespace)",
                    "Verify Prometheus Operator CRDs are installed if using "
                    "Prometheus Operator",
                    "Ensure OpenShift Routes are accessible if on OpenShift",
                    "Try setting PROMETHEUS_URL environment variable",
                ],
                ["Prometheus endpoint not found"],
            )

        logger.info(f"[{tool_name}] Using Prometheus endpoint: {prometheus_url}")

        # Build query URL and parameters
        if query_type == "instant":
            api_path = "/api/v1/query"
            params: dict = {"query": query}
            if timeout:
                params["timeout"] = f"{timeout}s"
        else:
            api_path = "/api/v1/query_range"
            params = {
                "query": query,
                "start": parse_time_parameter(start_time),
                "end": parse_time_parameter(end_time),
                "step": step,
            }
            if timeout:
                params["timeout"] = f"{timeout}s"

        query_url = f"{prometheus_url}{api_path}"
        headers = {
            "Accept": "application/json",
            "User-Agent": "LUMINO-MCP/1.0",
        }
        if auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"

        logger.info(f"[{tool_name}] Executing query against: {query_url}")

        # Execute Prometheus query
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=timeout + 10),
        ) as session:
            async with session.get(
                query_url, params=params, headers=headers, ssl=False,
            ) as response:
                execution_time = round(
                    (time.time() - start_execution_time) * 1000, 2,
                )

                if response.status == 200:
                    response_data = await response.json()
                    logger.info(
                        f"[{tool_name}] Query executed successfully "
                        f"in {execution_time}ms"
                    )

                    processed = await process_prometheus_results(
                        response_data,
                        format,
                        namespace_filter,
                        limit,
                        query,
                        query_type,
                    )

                    processed.update({
                        "status": "success",
                        "query_executed": query,
                        "execution_time": execution_time,
                        "prometheus_endpoint": prometheus_url,
                        "query_type": query_type,
                        "parameters": params,
                    })

                    return json.dumps(processed)

                elif response.status == 400:
                    error_text = await response.text()
                    logger.warning(
                        f"[{tool_name}] Bad request (400): {error_text}"
                    )
                    suggestions = generate_query_suggestions(query, error_text)
                    return _error_response(
                        "invalid_query",
                        f"PromQL query error: {error_text}",
                        query,
                        execution_time,
                        suggestions,
                        [error_text],
                    )

                elif response.status == 401:
                    logger.error(
                        f"[{tool_name}] Authentication failed (401)"
                    )
                    return _error_response(
                        "authentication_failed",
                        "Authentication failed - invalid or expired token",
                        query,
                        execution_time,
                        [
                            "Refresh your Kubernetes credentials (kubeconfig "
                            "or ServiceAccount)",
                            "Check if token has expired",
                            "Set PROMETHEUS_TOKEN environment variable with "
                            "a valid token",
                            "Verify cluster access permissions",
                        ],
                        ["Authentication failed"],
                    )

                elif response.status == 403:
                    logger.error(
                        f"[{tool_name}] Access forbidden (403)"
                    )
                    return _error_response(
                        "permission_denied",
                        "Access denied - insufficient permissions",
                        query,
                        execution_time,
                        [
                            "Check RBAC permissions for metrics access",
                            "Verify cluster-monitoring-view role binding",
                            "Contact cluster administrator for monitoring "
                            "access",
                        ],
                        ["Permission denied"],
                    )

                else:
                    error_text = await response.text()
                    logger.error(
                        f"[{tool_name}] HTTP error {response.status}: "
                        f"{error_text}"
                    )
                    return _error_response(
                        "http_error",
                        f"HTTP {response.status}: {error_text}",
                        query,
                        execution_time,
                        [
                            "Check Prometheus service availability",
                            "Verify cluster connectivity",
                            "Try again in a few minutes",
                        ],
                        [f"HTTP {response.status}: {error_text}"],
                    )

    except asyncio.TimeoutError:
        execution_time = round(
            (time.time() - start_execution_time) * 1000, 2,
        )
        logger.error(f"[{tool_name}] Query timeout after {timeout}s")
        return _error_response(
            "timeout",
            f"Query timed out after {timeout} seconds",
            query,
            execution_time,
            [
                "Try a simpler query with shorter time range",
                "Increase timeout parameter",
                "Use more specific label selectors to reduce data",
            ],
            [f"Timeout after {timeout}s"],
        )

    except Exception as e:
        execution_time = round(
            (time.time() - start_execution_time) * 1000, 2,
        )
        error_msg = f"Unexpected error during query execution: {e}"
        logger.error(f"[{tool_name}] {error_msg}", exc_info=True)
        return _error_response(
            "unexpected_error",
            error_msg,
            query,
            execution_time,
            [
                "Check system logs for details",
                "Verify cluster connectivity",
                "Try a simpler query first",
            ],
            [str(e)],
        )
