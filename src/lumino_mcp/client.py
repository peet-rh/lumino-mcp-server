import asyncio
import logging

from kubernetes import client, config

logger = logging.getLogger("lumino-mcp")

_core_v1: client.CoreV1Api | None = None
_apps_v1: client.AppsV1Api | None = None
_custom: client.CustomObjectsApi | None = None
_batch_v1: client.BatchV1Api | None = None


def _load_config(context: str | None = None):
    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config(context=context)


def _init_clients():
    global _core_v1, _apps_v1, _custom, _batch_v1
    _core_v1 = client.CoreV1Api()
    _apps_v1 = client.AppsV1Api()
    _custom = client.CustomObjectsApi()
    _batch_v1 = client.BatchV1Api()


def _ensure_clients():
    if _core_v1 is None:
        _load_config()
        _init_clients()


def _get_client(api: str):
    _ensure_clients()
    clients = {
        "core_v1": _core_v1,
        "apps_v1": _apps_v1,
        "custom": _custom,
        "batch_v1": _batch_v1,
    }
    c = clients.get(api)
    if c is None:
        raise ValueError(f"Unknown API client: {api!r} (valid: {list(clients)})")
    return c


def reload() -> dict:
    _load_config()
    _init_clients()
    return get_current_context()


def get_current_context() -> dict:
    try:
        contexts, active = config.list_kube_config_contexts()
        return {
            "context": active.get("name", "unknown"),
            "cluster": active.get("context", {}).get("cluster", "unknown"),
            "user": active.get("context", {}).get("user", "unknown"),
        }
    except Exception:
        return {"context": "in-cluster", "cluster": "in-cluster", "user": "serviceaccount"}


async def call(api: str, method: str, *args, context: str | None = None, **kwargs):
    def _do():
        if context:
            _load_config(context=context)
            _init_clients()
        c = _get_client(api)
        fn = getattr(c, method)
        return fn(*args, **kwargs)
    return await asyncio.to_thread(_do)
