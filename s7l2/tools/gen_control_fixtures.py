#!/usr/bin/env python3
# SPDX-FileCopyrightText: Oleksiy Lukin and S7 contributors
# SPDX-License-Identifier: GPL-3.0-or-later

"""Conformance script for the S7 control protocol, version 1.

Writes s7runtime/tests/fixtures/control_v1.json: a conversation with one node
(requests in order, from an anonymous peer or the authorized Studio) and,
for each response, its type and the members it must have with their JSON
types. It covers every message of S7_Control_Protocol_MVP.md, their errors,
and idempotent repeats. The configuration digests (RFC 8785 JCS, SHA-256)
and the base64url chunk are computed here, independently of the C++ code.

Usage: tools/gen_control_fixtures.py [output.json]
"""
import base64
import hashlib
import json
import sys
from pathlib import Path

NODE = "11111111-2222-3333-4444-555555555555"
STREAM = "5d4c3b2a-1f0e-4d9c-8b7a-6f5e4d3c2b1a"


def jcs(value):
    """RFC 8785 for the values used here (strings, integers, objects, arrays)."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def configuration(value, project_revision):
    diagram = {
        "document_kind": "s7.diagram",
        # A Constant pins no rate of its own: the diagram's dt seeds it, or a
        # real node refuses the graph (doc/S7_Sample_Rate_Model.md).
        "dt": 1,
        "runtime_nodes": [{"node_uuid": NODE, "name": "fixture-node", "endpoint": "wss://127.0.0.1:9002"}],
        "schema": {"name": "fixture", "elements": [{"id": "c", "type": "Constant", "params": {"value": value}, "node": NODE}],
                   "connections": []},
    }
    bundle = {"project_revision": project_revision, "diagram": diagram}
    bundle["configuration_digest"] = "sha256:" + hashlib.sha256(jcs(bundle).encode()).hexdigest()
    return bundle


def request(type_, request_id, **fields):
    return {"type": type_, "request_id": request_id, "protocol_version": 1, **fields}


ENVELOPE = {"type": "string", "request_id": "string", "protocol_version": "integer"}


def fields(**members):
    return {**ENVELOPE, **members}


ERROR = fields(code="string", message="string", details="object")


def error(code):
    return {"type": "ERROR", "fields": ERROR, "equals": {"code": code}}


def steps():
    first = configuration(4, "fixture:1")
    second = configuration(5, "fixture:2")
    second_text = json.dumps(second)
    deployment_1 = {"deployment_id": "fixture-deployment", "revision": 1, "base_revision": 0, "configuration": first}
    node_info = fields(**{
        "node": "object", "node.node_uuid": "string", "node.node_name": "string", "node.runtime_version": "string",
        "node.protocol_version": "integer", "node.certificate": "object",
        "platform": "object", "platform.os_family": "string", "platform.architecture": "string",
        "network": "object", "network.listen_url": "string", "network.control_path": "string", "network.data_path": "string",
        "libraries": "array", "state": "object", "state.mode": "string", "state.execution": "string",
        "control_limits": "object", "control_limits.max_configuration_bytes": "integer",
        "control_limits.max_chunk_bytes": "integer", "control_limits.max_transfer_bytes": "integer",
        "data_protocol": "object", "data_protocol.packet_versions": "array", "data_protocol.extensions": "array",
        "clock_domains": "array", "clock_domains[0].id": "string", "clock_domains[0].kind": "string",
        "clock_domains[0].continuous_across_restart": "boolean",
        "clock_sync": "object", "clock_sync.synchronized": "boolean", "clock_sync.max_error_ns": "integer",
        "clock_sync.estimated_error_ns": "integer", "clock_sync.source": "string", "clock_sync.max_error_bound_ns": "integer",
        "clock_sync.usable": "boolean",
    })
    deployments = fields(state="string", execution="string", active_revision="integer", active_deployment="object|null",
                         prepared_deployments="array", history="array")
    prepare_result = fields(deployment_id="string", revision="integer", configuration_digest="string", prepare_status="string",
                            prepare_token="string|null", prepared_at="string|null", expires_at="string|null",
                            incompatibilities="array", reservations="object")
    commit_result = fields(deployment_id="string", revision="integer", committed="boolean", state="string",
                           configuration_digest="string", execution="string", activate_at_ns="integer|null")
    stream_status = fields(**{
        "streams": "array", "streams[0].stream_id": "string", "streams[0].role": "string", "streams[0].data_type": "string",
        "streams[0].state": "string", "streams[0].fault": "string", "streams[0].next_sequence": "integer",
        "streams[0].packets": "integer", "streams[0].elements": "integer", "streams[0].replayed": "integer",
        "streams[0].lost_resumes": "integer", "streams[0].duplicates_discarded": "integer", "streams[0].malformed": "integer",
        "streams[0].unauthorized": "integer", "streams[0].send_log_depth": "integer", "streams[0].buffered_elements": "integer",
        "streams[0].blocked_ms_total": "integer", "streams[0].recent_faults": "array",
        "streams[0].recent_faults[0].code": "string", "streams[0].recent_faults[0].detail": "string",
        "streams[0].recent_faults[0].at": "string",
        "streams[0].latency": "object", "streams[0].latency.samples": "integer", "streams[0].latency.min_ns": "integer",
        "streams[0].latency.mean_ns": "integer", "streams[0].latency.p50_ns": "integer", "streams[0].latency.p99_ns": "integer",
        "streams[0].latency.max_ns": "integer", "streams[0].latency.last_ns": "integer", "streams[0].latency.late": "integer",
    })
    return [
        {"name": "hello", "peer": "anonymous", "request": request("HELLO", "hello-1"),
         "response": {"type": "HELLO_OK", "fields": fields(node_uuid="string", node_name="string", status="string"),
                      "equals": {"request_id": "hello-1", "node_uuid": NODE}}},
        {"name": "node_info", "peer": "anonymous", "request": request("GET_NODE_INFO", "info-1"),
         "response": {"type": "NODE_INFO", "fields": node_info,
                      "equals": {"data_protocol.packet_versions": [1], "data_protocol.extensions": ["0x0002", "0x8001"],
                                 "clock_sync.usable": True, "clock_domains[1].id": "utc"}}},
        {"name": "peer_announce", "peer": "anonymous",
         "request": request("PEER_ANNOUNCE", "announce-1", self={"endpoint": "wss://127.0.0.1:9003", "node_uuid": "33333333-4444-5555-6666-777777777777"}),
         "response": {"type": "PEER_ANNOUNCE_OK", "fields": fields(accepted="boolean")}},
        {"name": "peers", "peer": "anonymous", "request": request("GET_PEERS", "peers-1"),
         "response": {"type": "PEERS", "fields": fields(**{"peers": "array", "peers[0].endpoint": "string",
                                                           "peers[0].node_uuid": "string|null", "peers[0].trust_state": "string",
                                                           "peers[0].reachability": "string"})}},
        {"name": "list_idle", "peer": "anonymous", "request": request("LIST_DEPLOYMENTS", "list-1"),
         "response": {"type": "DEPLOYMENTS", "fields": deployments, "equals": {"active_revision": 0, "active_deployment": None}}},
        {"name": "configuration_none", "peer": "anonymous", "request": request("GET_NETWORK_CONFIGURATION", "config-1"),
         "response": error("REVISION_NOT_FOUND")},
        {"name": "prepare_unauthorized", "peer": "anonymous", "request": request("PREPARE_DEPLOYMENT", "prepare-0", deployment=deployment_1),
         "response": error("UNAUTHORIZED")},
        {"name": "prepare", "peer": "studio", "request": request("PREPARE_DEPLOYMENT", "prepare-1", deployment=deployment_1),
         "response": {"type": "PREPARE_DEPLOYMENT_RESULT", "fields": prepare_result,
                      "equals": {"prepare_status": "READY", "configuration_digest": first["configuration_digest"]}},
         "capture": {"token": "prepare_token"}},
        {"name": "prepare_repeated", "peer": "studio", "request": request("PREPARE_DEPLOYMENT", "prepare-2", deployment=deployment_1),
         "response": {"type": "PREPARE_DEPLOYMENT_RESULT", "fields": prepare_result, "equals": {"prepare_token": "${token}"}}},
        {"name": "prepare_tampered", "peer": "studio",
         "request": request("PREPARE_DEPLOYMENT", "prepare-3",
                            deployment={**deployment_1, "configuration": {**first, "project_revision": "tampered"}}),
         "response": error("INVALID_REQUEST")},
        {"name": "commit_activation_too_far", "peer": "studio",
         "request": request("COMMIT_DEPLOYMENT", "commit-0", deployment_id="fixture-deployment", revision=1, prepare_token="${token}",
                            activate_at_ns=4611686018427387904),
         "response": error("INVALID_REQUEST"), "note": "activate_at_ns more than 60 s ahead"},
        {"name": "commit", "peer": "studio",
         "request": request("COMMIT_DEPLOYMENT", "commit-1", deployment_id="fixture-deployment", revision=1, prepare_token="${token}"),
         "response": {"type": "COMMIT_DEPLOYMENT_RESULT", "fields": commit_result,
                      "equals": {"committed": True, "state": "active", "activate_at_ns": None}}},
        {"name": "commit_repeated", "peer": "studio",
         "request": request("COMMIT_DEPLOYMENT", "commit-2", deployment_id="fixture-deployment", revision=1, prepare_token="${token}"),
         "response": {"type": "COMMIT_DEPLOYMENT_RESULT", "fields": commit_result, "equals": {"committed": True}}},
        {"name": "commit_bad_token", "peer": "studio",
         "request": request("COMMIT_DEPLOYMENT", "commit-3", deployment_id="fixture-deployment", revision=1, prepare_token="0" * 64),
         "response": error("PREPARE_TOKEN_INVALID")},
        {"name": "list_active", "peer": "anonymous", "request": request("LIST_DEPLOYMENTS", "list-2"),
         "response": {"type": "DEPLOYMENTS", "fields": {**deployments, "active_deployment.deployment_id": "string",
                                                         "active_deployment.revision": "integer",
                                                         "active_deployment.configuration_digest": "string",
                                                         "active_deployment.committed_at": "string", "active_deployment.restored": "boolean",
                                                         "history[0].deployment_id": "string", "history[0].revision": "integer",
                                                         "history[0].outcome": "string"},
                      "equals": {"active_revision": 1}}},
        {"name": "configuration", "peer": "anonymous", "request": request("GET_NETWORK_CONFIGURATION", "config-2"),
         "response": {"type": "NETWORK_CONFIGURATION",
                      "fields": fields(node_uuid="string", deployment_id="string", revision="integer", project_revision="string",
                                       configuration_digest="string", committed_at="string", diagram="object", node_schema="object"),
                      "equals": {"revision": 1, "project_revision": "fixture:1", "configuration_digest": first["configuration_digest"]}}},
        {"name": "begin_transfer", "peer": "studio",
         "request": request("BEGIN_CONFIGURATION_TRANSFER", "begin-1", transfer_id="fixture-transfer", total_bytes=len(second_text.encode()),
                            configuration_digest=second["configuration_digest"]),
         "response": {"type": "CONFIGURATION_TRANSFER_STARTED", "fields": fields(transfer_id="string", max_chunk_bytes="integer")}},
        {"name": "chunk", "peer": "studio",
         "request": request("CONFIGURATION_CHUNK", "chunk-1", transfer_id="fixture-transfer", index=0, offset=0,
                            data=base64.urlsafe_b64encode(second_text.encode()).decode().rstrip("=")),
         "response": {"type": "CONFIGURATION_CHUNK_ACCEPTED", "fields": fields(transfer_id="string", index="integer", received_bytes="integer"),
                      "equals": {"received_bytes": len(second_text.encode())}}},
        {"name": "chunk_out_of_order", "peer": "studio",
         "request": request("CONFIGURATION_CHUNK", "chunk-2", transfer_id="fixture-transfer", index=2, offset=0, data="AA"),
         "response": error("TRANSFER_INVALID")},
        {"name": "end_transfer", "peer": "studio",
         "request": request("END_CONFIGURATION_TRANSFER", "end-1", transfer_id="fixture-transfer"),
         "response": {"type": "CONFIGURATION_TRANSFER_COMPLETE", "fields": fields(transfer_id="string", configuration_digest="string",
                                                                                  total_bytes="integer"),
                      "equals": {"configuration_digest": second["configuration_digest"]}}},
        {"name": "prepare_from_transfer", "peer": "studio",
         "request": request("PREPARE_DEPLOYMENT", "prepare-4", deployment={"deployment_id": "fixture-deployment", "revision": 2, "base_revision": 1,
                                                                          "configuration_transfer_id": "fixture-transfer"}),
         "response": {"type": "PREPARE_DEPLOYMENT_RESULT", "fields": prepare_result, "equals": {"prepare_status": "READY"}},
         "capture": {"token2": "prepare_token"}},
        {"name": "abort", "peer": "studio",
         "request": request("ABORT_DEPLOYMENT", "abort-1", deployment_id="fixture-deployment", revision=2, prepare_token="${token2}"),
         "response": {"type": "ABORT_DEPLOYMENT_RESULT", "fields": fields(deployment_id="string", revision="integer", aborted="boolean", state="string"),
                      "equals": {"aborted": True}}},
        {"name": "abort_repeated", "peer": "studio",
         "request": request("ABORT_DEPLOYMENT", "abort-2", deployment_id="fixture-deployment", revision=2, prepare_token="${token2}"),
         "response": {"type": "ABORT_DEPLOYMENT_RESULT", "fields": fields(aborted="boolean"), "equals": {"aborted": True}}},
        {"name": "prepare_too_large", "peer": "studio",
         "request": request("PREPARE_DEPLOYMENT", "prepare-5", deployment={**deployment_1, "revision": 3, "base_revision": 1,
                                                                          "configuration": configuration("x" * 2048, "fixture:large")}),
         "response": error("CONFIGURATION_TOO_LARGE"),
         "note": "the fixture node is configured with max_configuration_bytes = 2048"},
        {"name": "stream_status", "peer": "anonymous", "request": request("GET_STREAM_STATUS", "streams-1"),
         "response": {"type": "STREAM_STATUS", "fields": stream_status,
                      "equals": {"streams[0].stream_id": STREAM, "streams[0].fault": "UNDERRUN", "streams[0].state": "faulted"}},
         "note": "the fixture node has one consumer stream that faulted with UNDERRUN"},
        {"name": "recover_unauthorized", "peer": "anonymous", "request": request("RECOVER_STREAM", "recover-0", stream_id=STREAM),
         "response": error("UNAUTHORIZED")},
        {"name": "recover", "peer": "studio", "request": request("RECOVER_STREAM", "recover-1", stream_id=STREAM),
         "response": {"type": "RECOVER_STREAM_RESULT", "fields": fields(stream_id="string", recovered="boolean"), "equals": {"recovered": True}}},
        {"name": "recover_repeated", "peer": "studio", "request": request("RECOVER_STREAM", "recover-2", stream_id=STREAM),
         "response": {"type": "RECOVER_STREAM_RESULT", "fields": fields(stream_id="string", recovered="boolean"), "equals": {"recovered": True}}},
        {"name": "status_after_recovery", "peer": "anonymous", "request": request("GET_STREAM_STATUS", "streams-2"),
         "response": {"type": "STREAM_STATUS", "fields": stream_status,
                      "equals": {"streams[0].fault": "NONE", "streams[0].recent_faults[0].code": "UNDERRUN"}}},
        {"name": "unsupported_type", "peer": "anonymous", "request": request("SHUTDOWN", "x-1"), "response": error("UNSUPPORTED_MESSAGE_TYPE")},
        {"name": "missing_request_id", "peer": "anonymous", "request": {"type": "HELLO", "protocol_version": 1},
         "response": error("INVALID_REQUEST")},
        {"name": "unsupported_version", "peer": "anonymous", "request": {"type": "HELLO", "request_id": "v-1", "protocol_version": 2},
         "response": error("UNSUPPORTED_PROTOCOL_VERSION")},
    ]


def main():
    out_path = Path(sys.argv[1] if len(sys.argv) > 1 else
                    Path(__file__).resolve().parent.parent / "s7runtime/tests/fixtures/control_v1.json")
    fixtures = {
        "format": "S7 control protocol v1 conformance script (S7_Control_Protocol_MVP.md)",
        "generator": "tools/gen_control_fixtures.py",
        "node": {"node_uuid": NODE, "node_name": "fixture-node", "listen_url": "wss://127.0.0.1:9002",
                 "max_configuration_bytes": 2048,
                 "clock": "synchronized (NODE_INFO.clock_sync.usable)",
                 "stream": {"stream_id": STREAM, "role": "consumer", "data_type": "F64", "fault": "UNDERRUN"}},
        "peers": {"anonymous": "no TLS client certificate",
                  "studio": "the authorized Studio's verified certificate (s7runtime/examples/certs/s7_studio.cert.pem)"},
        "types": "Each response member, by path (a.b, a[0].b), has one of the JSON types string, integer, boolean, object, "
                 "array, null; 'x|y' allows either. 'equals' gives exact values. '${name}' in a request is a value "
                 "captured from an earlier response ('capture': {name: member}). Other members may be present.",
        "steps": steps(),
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(fixtures, indent=2) + "\n")
    print(f"wrote {out_path}")


if __name__ == "__main__":
    main()
