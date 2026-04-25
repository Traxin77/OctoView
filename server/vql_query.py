#!/usr/bin/env python3
"""
vql_query.py — Multi-mode Velociraptor gRPC helper.

Modes (CLI):
  query    <config> <vql>
  collect  <config> <client_id> <artifact_name> [params_json]
  status   <config> <client_id> <flow_id>
  results  <config> <client_id> <flow_id>
  artifacts <config> <keyword>

Library use:
  Each helper accepts an optional `stub` kwarg so callers (e.g. agent.py) can
  reuse one gRPC channel across many calls instead of paying per-call cold
  start. When `stub` is None the helper opens its own single-shot channel.
"""

import sys
import json
from contextlib import contextmanager


def get_stub_and_channel(config_path):
    import pyvelociraptor
    from pyvelociraptor import api_pb2_grpc
    import grpc

    config = pyvelociraptor.LoadConfigFile(config_path)
    creds  = grpc.ssl_channel_credentials(
        root_certificates=config["ca_certificate"].encode("utf8"),
        private_key=config["client_private_key"].encode("utf8"),
        certificate_chain=config["client_cert"].encode("utf8"),
    )
    options = (
        ("grpc.ssl_target_name_override", "VelociraptorServer"),
        ("grpc.max_receive_message_length", 50 * 1024 * 1024),  # 50MB
        ("grpc.max_send_message_length",    50 * 1024 * 1024),  # 50MB
    )
    channel = grpc.secure_channel(config["api_connection_string"], creds, options)
    stub    = api_pb2_grpc.APIStub(channel)
    return stub, channel


@contextmanager
def _stub_ctx(config_path, stub):
    """Yield (stub, keep_open). If caller supplied a stub, reuse it and do
    nothing on exit; otherwise open a fresh channel and close it afterwards."""
    if stub is not None:
        yield stub
        return
    s, ch = get_stub_and_channel(config_path)
    try:
        with ch:
            yield s
    finally:
        pass


def run_vql(config_path, vql, stub=None):
    from pyvelociraptor import api_pb2
    with _stub_ctx(config_path, stub) as s:
        request = api_pb2.VQLCollectorArgs(
            max_wait=1,
            max_row=10000,
            Query=[api_pb2.VQLRequest(Name="query", VQL=vql)],
        )
        rows = []
        for response in s.Query(request):
            if response.Response:
                rows.extend(json.loads(response.Response))
        return rows


def collect_artifact(config_path, client_id, artifact_name, params=None, stub=None):
    params = params or {}

    # Build env dict for artifact parameters
    if params:
        param_str  = ", ".join([f"{k}='{v}'" for k, v in params.items()])
        env_clause = f", env=dict({param_str})"
    else:
        env_clause = ""

    vql = (
        f"LET result <= collect_client("
        f"client_id='{client_id}', "
        f"artifacts=['{artifact_name}']"
        f"{env_clause}) "
        f"SELECT result.flow_id AS flow_id FROM scope()"
    )

    rows = run_vql(config_path, vql, stub=stub)
    if not rows or not rows[0].get("flow_id"):
        raise Exception(f"collect_client returned no flow_id for {artifact_name}")
    return rows[0]["flow_id"]


def get_flow_status(config_path, client_id, flow_id, stub=None):
    vql  = (
        f"SELECT session_id, state, status FROM flows(client_id='{client_id}') "
        f"WHERE session_id='{flow_id}' LIMIT 1"
    )
    rows = run_vql(config_path, vql, stub=stub)
    if not rows:
        return {"state": "UNKNOWN", "error": ""}
    return {
        "state": str(rows[0].get("state", "UNKNOWN")),
        "error": str(rows[0].get("status", "")),
    }


def get_flow_results(config_path, client_id, flow_id, stub=None):
    # flow_results() needs an `artifact=` naming the exact source (e.g.
    # "Windows.System.Amcache/InventoryApplicationFile"). Without it,
    # multi-source artifacts silently return nothing even though rows exist.
    # Enumerate sources from flows().artifacts_with_results and union them;
    # fall back to the bare query when that list is empty.
    with _stub_ctx(config_path, stub) as s:
        meta = run_vql(
            config_path,
            f"SELECT artifacts_with_results FROM flows(client_id='{client_id}') "
            f"WHERE session_id='{flow_id}' LIMIT 1",
            stub=s,
        )
        sources = []
        if meta and isinstance(meta[0].get("artifacts_with_results"), list):
            sources = [a for a in meta[0]["artifacts_with_results"] if a]

        if not sources:
            return run_vql(
                config_path,
                f"SELECT * FROM flow_results(client_id='{client_id}', flow_id='{flow_id}')",
                stub=s,
            )

        rows = []
        for src in sources:
            safe = src.replace("'", "")
            part = run_vql(
                config_path,
                f"SELECT * FROM flow_results(client_id='{client_id}', "
                f"flow_id='{flow_id}', artifact='{safe}')",
                stub=s,
            )
            if part:
                rows.extend(part)
        return rows


def search_artifacts(config_path, keyword, stub=None):
    """Server-side regex fallback — only used when the local cache is missing."""
    vql = (
        f"SELECT name, description FROM artifact_definitions() "
        f"WHERE name =~ '{keyword}' OR description =~ '{keyword}' "
        f"ORDER BY name LIMIT 30"
    )
    return run_vql(config_path, vql, stub=stub)


def list_artifacts(config_path, stub=None):
    """Full catalog — used by index.js refreshArtifacts() to build the cache."""
    vql = "SELECT name, description FROM artifact_definitions() ORDER BY name"
    return run_vql(config_path, vql, stub=stub)


def main():
    if len(sys.argv) < 3:
        print(json.dumps({"error": "Usage: vql_query.py <mode> <config> [args...]"}))
        sys.exit(1)

    mode        = sys.argv[1]
    config_path = sys.argv[2]

    try:
        if mode == "query":
            rows = run_vql(config_path, sys.argv[3])
            print(json.dumps(rows))

        elif mode == "collect":
            client_id     = sys.argv[3]
            artifact_name = sys.argv[4]
            params        = json.loads(sys.argv[5]) if len(sys.argv) > 5 else {}
            flow_id       = collect_artifact(config_path, client_id, artifact_name, params)
            print(json.dumps({"flow_id": flow_id, "client_id": client_id}))

        elif mode == "status":
            result = get_flow_status(config_path, sys.argv[3], sys.argv[4])
            print(json.dumps(result))

        elif mode == "results":
            rows = get_flow_results(config_path, sys.argv[3], sys.argv[4])
            print(json.dumps(rows))

        elif mode == "artifacts":
            keyword = sys.argv[3] if len(sys.argv) > 3 else ""
            if keyword:
                rows = search_artifacts(config_path, keyword)
            else:
                rows = list_artifacts(config_path)
            print(json.dumps(rows))

        else:
            print(json.dumps({"error": f"Unknown mode: {mode}"}))
            sys.exit(1)

    except Exception as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)


if __name__ == "__main__":
    main()
