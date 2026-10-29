# SPDX-FileCopyrightText: Oleksiy Lukin and S7 contributors
# SPDX-License-Identifier: GPL-3.0-or-later

"""S7 control protocol v1, node side (doc/S7_Control_Protocol_MVP.md).

Mirrors the C++ reference (s7runtime/src/control_plane_mvp.cpp): the same
messages, errors, idempotency rules, limits and persistence. Mutations are
authorized from the TLS session only, never from JSON fields.
"""
import base64
import binascii
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import diagram as diagrams
from . import wire
from .clock import Clock, utc_now_ns
from .graph import SchemaError
from .jcs import MAX_SAFE_INTEGER, configuration_digest, dumps, loads
from .tls import ControlPeer

PROTOCOL_VERSION = 1
MAX_CHUNK_BYTES = 1024 * 1024
MAX_TRANSFER_BYTES = 256 * 1024 * 1024
MAX_TRANSFERS = 4
MAX_HISTORY = 64
MAX_ACTIVATION_DELAY_NS = 60_000_000_000
PREPARE_TTL_S = 300
DEPLOYMENT_FILE = "deployment.json"
PEERS_FILE = "peers.json"

MUTATIONS = (
    "PREPARE_DEPLOYMENT",
    "COMMIT_DEPLOYMENT",
    "ABORT_DEPLOYMENT",
    "RECOVER_STREAM",
    "BEGIN_CONFIGURATION_TRANSFER",
    "CONFIGURATION_CHUNK",
    "END_CONFIGURATION_TRANSFER",
)


def iso8601(seconds_from_now: float = 0) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + seconds_from_now))


def error(request_id: str, code: str, message: str, details: dict | None = None) -> dict:
    return {
        "type": "ERROR",
        "request_id": request_id,
        "protocol_version": PROTOCOL_VERSION,
        "code": code,
        "message": message,
        "details": details or {},
    }


def is_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def read_revision(obj: dict, key: str, allow_zero: bool) -> int | None:
    value = obj.get(key)
    if not is_int(value) or value < 0 or value > MAX_SAFE_INTEGER or (value == 0 and not allow_zero):
        return None
    return value


def tokens_equal(left: str, right: str) -> bool:
    return hmac.compare_digest(left.encode(), right.encode())


def decode_base64url(text: str) -> bytes | None:
    if "=" in text or len(text) % 4 == 1:
        return None
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError):
        return None


def write_atomically(path: Path, text: str) -> None:
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(text, encoding="utf-8")
    os.replace(temporary, path)


@dataclass
class Authorization:
    """The one Studio allowed to change this node (node configuration "control")."""

    studio_key_purpose_oid: str = ""
    studio_certificate_sha256: str = ""

    def configured(self) -> bool:
        return bool(self.studio_key_purpose_oid and self.studio_certificate_sha256)


@dataclass
class Descriptor:
    node_uuid: str
    node_name: str
    instance_id: str
    started_at: str
    listen_url: str
    os_family: str
    architecture: str
    runtime_version: str
    element_types: list[str]
    certificate: dict = field(default_factory=dict)  # common_name, fingerprint_sha256 of the node's own certificate
    hardware_capabilities: list[str] = field(default_factory=list)

    @property
    def target_triple(self) -> str:
        return f"{self.architecture}-{self.os_family}"

    def libraries(self) -> list[dict]:
        return [
            {
                "library_id": "runtime-registry",
                "kind": "builtin",
                "version": "0.1.0",
                "target_triple": self.target_triple,
                "origin": "registry",
                "status": "",
                "elements": list(self.element_types),
            }
        ]


@dataclass
class Prepared:
    deployment_id: str
    revision: int
    base_revision: int
    project_revision: str
    configuration_digest: str
    prepare_token: str
    prepared_at: str
    expires_at: str
    expires: float  # time.monotonic()
    staged: object
    configuration: dict
    node_schema: dict


@dataclass
class Active:
    deployment_id: str
    revision: int
    project_revision: str
    configuration_digest: str
    committed_at: str
    prepare_token: str
    configuration: dict
    node_schema: dict
    restored: bool = False
    activate_at_ns: int | None = None


@dataclass
class Transfer:
    total_bytes: int
    configuration_digest: str
    expires: float
    data: bytearray = field(default_factory=bytearray)
    chunks: list[tuple[int, int]] = field(default_factory=list)  # (offset, length)
    configuration: dict | None = None


class ControlPlane:
    def __init__(
        self,
        descriptor: Descriptor,
        host,
        clock: Clock,
        *,
        state_dir: Path | None = None,
        authorization: Authorization | None = None,
        max_configuration_bytes: int = 1024 * 1024,
        max_chunk_bytes: int = MAX_CHUNK_BYTES,
        max_transfer_bytes: int = 64 * 1024 * 1024,
        prepare_ttl_s: float = PREPARE_TTL_S,
        streams=None,
        data=None,
        log=print,
    ):
        self.descriptor = descriptor
        self.data = data  # transport.DataEndpoint: checks the data peers of a deployment
        self.streams = streams  # transport.StreamTable of the node's data streams, if it has a data plane
        self.host = host  # DeploymentHost: stage(), activate(), execution_state(), timing()
        self.clock = clock
        self.state_dir = state_dir
        self.authorization = authorization or Authorization()
        self.max_configuration_bytes = max_configuration_bytes
        self.max_chunk_bytes = min(max_chunk_bytes, MAX_CHUNK_BYTES)
        self.max_transfer_bytes = min(max_transfer_bytes, MAX_TRANSFER_BYTES)
        self.prepare_ttl_s = prepare_ttl_s
        self.log = log
        self.active: Active | None = None
        self.prepared: dict[tuple[str, int], Prepared] = {}
        self.transfers: dict[str, Transfer] = {}
        self.history: list[dict] = []
        self.peers: dict[str, dict] = {}
        self._load_peers()

    # ---- dispatch -------------------------------------------------------------

    def handle_json(self, peer: ControlPeer, text: str) -> str:
        try:
            request = loads(text)
        except (ValueError, RecursionError) as ex:
            return dumps(error("", "INVALID_REQUEST", f"Request is not valid JSON: {ex}"))
        if not isinstance(request, dict):
            return dumps(error("", "INVALID_REQUEST", "Request must be a JSON object."))
        try:
            return dumps(self.handle(peer, request))
        except Exception as ex:  # a handler bug must not drop the connection
            self.log(f"control.internal_error {type(ex).__name__}: {ex}")
            request_id = request.get("request_id") if isinstance(request.get("request_id"), str) else ""
            return dumps(error(request_id, "INTERNAL_ERROR", "Internal error."))

    def handle(self, peer: ControlPeer, request: dict) -> dict:
        request_id = request.get("request_id") if isinstance(request.get("request_id"), str) else ""
        request_type = request.get("type") if isinstance(request.get("type"), str) else ""
        version = request.get("protocol_version")
        if not is_int(version):
            return error(request_id, "INVALID_REQUEST", "Missing numeric protocol_version.")
        if version != PROTOCOL_VERSION:
            return error(request_id, "UNSUPPORTED_PROTOCOL_VERSION", "Only protocol_version=1 is supported.")
        if not request_id or len(request_id) > 128:
            return error("", "INVALID_REQUEST", "request_id must be a string of 1 to 128 characters.")

        read_only = {
            "HELLO": self.hello,
            "GET_NODE_INFO": self.node_info,
            "GET_PEERS": self.get_peers,
            "PEER_ANNOUNCE": self.peer_announce,
            "LIST_DEPLOYMENTS": self.list_deployments,
            "GET_NETWORK_CONFIGURATION": self.network_configuration,
            "GET_STREAM_STATUS": self.stream_status,
        }
        if request_type in read_only:
            return read_only[request_type](request_id, request)
        if request_type in MUTATIONS:
            if denied := self.authorize(peer, request_id, request_type):
                return denied
            handler = {
                "PREPARE_DEPLOYMENT": self.prepare,
                "COMMIT_DEPLOYMENT": self.commit,
                "ABORT_DEPLOYMENT": self.abort,
                "RECOVER_STREAM": self.recover_stream,
                "BEGIN_CONFIGURATION_TRANSFER": self.begin_transfer,
                "CONFIGURATION_CHUNK": self.chunk,
                "END_CONFIGURATION_TRANSFER": self.end_transfer,
            }[request_type]
            return handler(request_id, request)
        return error(request_id, "UNSUPPORTED_MESSAGE_TYPE", f"Unsupported control message type: '{request_type}'.")

    def authorize(self, peer: ControlPeer, request_id: str, request_type: str) -> dict | None:
        """TLS, a verified client certificate, the control-node key purpose and the pinned fingerprint."""
        fingerprint = peer.certificate.fingerprint_sha256 if peer.certificate else ""

        def deny(code, message):
            self.log(f"control.denied type={request_type} code={code} peer_certificate_sha256={fingerprint or 'none'} "
                     f'reason="{message}"')
            return error(request_id, code, message, {"peer_certificate_sha256": fingerprint} if fingerprint else None)

        if not peer.tls:
            return deny("UNAUTHORIZED", "Configuration changes require a mutual-TLS control connection.")
        if not peer.certificate:
            return deny("CERTIFICATE_REQUIRED", "Configuration changes require a verified client certificate.")
        if not self.authorization.configured():
            return deny("UNAUTHORIZED", "No authorized Studio is configured on this node.")
        if self.authorization.studio_key_purpose_oid not in peer.certificate.key_purpose_oids:
            return deny("UNAUTHORIZED", "Client certificate does not carry the control-node key purpose.")
        if not tokens_equal(fingerprint, self.authorization.studio_certificate_sha256):
            return deny("UNAUTHORIZED", "Client certificate is not the authorized Studio certificate.")
        self.log(f"control.authorized type={request_type} peer_certificate_sha256={fingerprint}")
        return None

    def _response(self, response_type: str, request_id: str, **members) -> dict:
        return {"type": response_type, "request_id": request_id, "protocol_version": PROTOCOL_VERSION, **members}

    def _state(self) -> str:
        return "active" if self.active else "idle"

    # ---- read-only ------------------------------------------------------------

    def hello(self, request_id, request):
        d = self.descriptor
        return self._response(
            "HELLO_OK", request_id, node_uuid=d.node_uuid, node_name=d.node_name, runtime_version=d.runtime_version,
            status=self._state(), certificate=d.certificate,
        )

    def node_info(self, request_id, request):
        d = self.descriptor
        sync = self.clock.sync()
        usable = self.clock.usable(sync)
        utc_domain = (
            {"id": "utc", "kind": "utc", "continuous_across_restart": True, "synchronized": True}
            if usable
            else {"id": f"node:{d.node_uuid}:utc", "kind": "utc", "continuous_across_restart": True, "synchronized": False}
        )
        return self._response(
            "NODE_INFO",
            request_id,
            node={
                "node_uuid": d.node_uuid, "node_name": d.node_name, "display_name": d.node_name,
                "runtime_version": d.runtime_version, "protocol_version": PROTOCOL_VERSION,
                "instance_id": d.instance_id, "started_at": d.started_at, "certificate": d.certificate,
            },
            platform={"os_family": d.os_family, "os_version": "unknown", "architecture": d.architecture,
                      "target_triple": d.target_triple},
            control_limits={"max_configuration_bytes": self.max_configuration_bytes,
                            "max_chunk_bytes": self.max_chunk_bytes, "max_transfer_bytes": self.max_transfer_bytes},
            # The data protocol this node speaks (wire draft section 12.1 item 4).
            data_protocol={"packet_versions": list(wire.SUPPORTED_PACKET_VERSIONS),
                           "extensions": [f"0x{e:04X}" for e in wire.SUPPORTED_EXTENSIONS]},
            clock_sync={"synchronized": sync.synchronized, "max_error_ns": sync.max_error_ns,
                        "estimated_error_ns": sync.estimated_error_ns, "source": sync.source,
                        "max_error_bound_ns": self.clock.max_error_bound_ns, "usable": usable},
            clock_domains=[{"id": "model", "kind": "model", "continuous_across_restart": True}, utc_domain],
            network={"listen_url": d.listen_url, "control_path": "/control", "data_path": "/data"},
            libraries=d.libraries(),
            elements={
                "summary": {"count": len(d.element_types)},
                "catalog": [{"type_name": t, "deployable": True, "deployable_reason": "available"} for t in d.element_types],
            },
            hardware={"capabilities": list(d.hardware_capabilities)},
            state={"mode": self._state(), "active_deployment": self.active.deployment_id if self.active else None,
                   "execution": self.host.execution_state(), "timing": self.host.timing()},
        )

    def get_peers(self, request_id, request):
        include_unverified = request.get("include_unverified", True)
        if not isinstance(include_unverified, bool):
            return error(request_id, "INVALID_REQUEST", "include_unverified must be boolean.")
        max_entries = request.get("max_entries", 256)
        if not is_int(max_entries) or max_entries <= 0:
            return error(request_id, "INVALID_REQUEST", "max_entries must be a positive integer.")
        if max_entries > 4096:
            return error(request_id, "INVALID_REQUEST", "max_entries exceeds allowed limit.")
        peers = [p for _, p in sorted(self.peers.items()) if include_unverified or p["trust_state"] == "verified"]
        return self._response("PEERS", request_id, generated_at=iso8601(), peers=peers[:max_entries])

    def add_seed_peer(self, endpoint: str) -> None:
        if endpoint and endpoint not in self.peers:
            self.peers[endpoint] = self._peer_record(endpoint, {}, reachability="offline")
            self._save_peers()

    @staticmethod
    def _peer_record(endpoint: str, claims: dict, reachability: str) -> dict:
        def text(obj, key):
            return obj.get(key) if isinstance(obj, dict) and isinstance(obj.get(key), str) else None

        certificate = claims.get("certificate") if isinstance(claims.get("certificate"), dict) else {}
        platform = claims.get("platform")
        return {
            "endpoint": endpoint,
            "node_uuid": text(claims, "node_uuid"),
            "node_name": text(claims, "node_name"),
            "platform": {"os_family": text(platform, "os_family"), "architecture": text(platform, "architecture")}
            if isinstance(platform, dict) else None,
            "trust_state": "unverified",  # an announcement is a claim, never trust
            "reachability": reachability,
            "last_seen_at": iso8601() if reachability == "online" else None,
            "last_failure_at": None,
            "certificate": {k: certificate[k] for k in ("common_name", "fingerprint_sha256")
                            if isinstance(certificate.get(k), str) and certificate[k]},
        }

    def peer_announce(self, request_id, request):
        claims = request.get("self")
        if not isinstance(claims, dict):
            return error(request_id, "INVALID_REQUEST", "PEER_ANNOUNCE requires object field 'self'.")
        endpoint = claims.get("endpoint")
        if not isinstance(endpoint, str) or not endpoint:
            return error(request_id, "INVALID_REQUEST", "PEER_ANNOUNCE self.endpoint must be a non-empty string.")
        self.peers[endpoint] = self._peer_record(endpoint, claims, reachability="online")
        self._save_peers()
        return self._response("PEER_ANNOUNCE_OK", request_id, accepted=True)

    def list_deployments(self, request_id, request):
        self._expire_prepared()
        active = None
        if self.active:
            a = self.active
            active = {
                "deployment_id": a.deployment_id, "revision": a.revision, "project_revision": a.project_revision,
                "configuration_digest": a.configuration_digest, "committed_at": a.committed_at, "restored": a.restored,
                "activate_at_ns": a.activate_at_ns,
                "activated": a.activate_at_ns is None or a.activate_at_ns <= utc_now_ns(),
            }
        # Prepare tokens are bearer secrets: only the PREPARE_DEPLOYMENT_RESULT carries them.
        prepared = [
            {"deployment_id": p.deployment_id, "revision": p.revision, "base_revision": p.base_revision,
             "configuration_digest": p.configuration_digest, "prepared_at": p.prepared_at, "expires_at": p.expires_at}
            for p in self.prepared.values()
        ]
        return self._response(
            "DEPLOYMENTS", request_id, state=self._state(), execution=self.host.execution_state(),
            timing=self.host.timing(), active_revision=self.active.revision if self.active else 0,
            active_deployment=active, prepared_deployments=prepared, history=list(self.history),
        )

    def network_configuration(self, request_id, request):
        requested = None
        if "revision" in request:
            requested = read_revision(request, "revision", False)
            if requested is None:
                return error(request_id, "INVALID_REQUEST", "revision must be an integer in [1, 2^53].")
        if not self.active or (requested is not None and requested != self.active.revision):
            message = "Only the active revision is retained." if self.active else "No configuration has been committed."
            return error(request_id, "REVISION_NOT_FOUND", message,
                         {"active_revision": self.active.revision if self.active else 0})
        a = self.active
        return self._response(
            "NETWORK_CONFIGURATION", request_id, node_uuid=self.descriptor.node_uuid, deployment_id=a.deployment_id,
            revision=a.revision, project_revision=a.project_revision, configuration_digest=a.configuration_digest,
            committed_at=a.committed_at, diagram=a.configuration["diagram"], node_schema=a.node_schema,
        )

    def stream_status(self, request_id, request):
        return self._response("STREAM_STATUS", request_id, streams=self.streams.statuses() if self.streams else [])

    # ---- deployment ---------------------------------------------------------

    def _record(self, deployment_id: str, revision: int, outcome: str, message: str = "") -> None:
        entry = {"deployment_id": deployment_id, "revision": revision, "outcome": outcome}
        if message:
            entry["message"] = message
        self.history.append(entry)
        del self.history[:-MAX_HISTORY]

    def _in_history(self, deployment_id: str, revision: int, outcomes: tuple[str, ...]) -> bool:
        return any(h["deployment_id"] == deployment_id and h["revision"] == revision and h["outcome"] in outcomes
                   for h in self.history)

    def _expire_prepared(self) -> None:
        now = time.monotonic()
        for key, p in list(self.prepared.items()):
            if p.expires <= now:
                self._record(p.deployment_id, p.revision, "expired")
                del self.prepared[key]

    def _expire_transfers(self) -> None:
        now = time.monotonic()
        self.transfers = {k: t for k, t in self.transfers.items() if t.expires > now}

    def prepare(self, request_id, request):
        def invalid(message, details=None):
            return error(request_id, "INVALID_REQUEST", message, details)

        deployment = request.get("deployment")
        if not isinstance(deployment, dict):
            return invalid("PREPARE_DEPLOYMENT requires object field 'deployment'.")
        deployment_id = deployment.get("deployment_id")
        if not isinstance(deployment_id, str) or not deployment_id:
            return invalid("deployment.deployment_id must be a non-empty string.")
        revision = read_revision(deployment, "revision", False)
        if revision is None:
            return invalid("deployment.revision must be an integer in [1, 2^53].")
        base_revision = read_revision(deployment, "base_revision", True)
        if base_revision is None:
            return invalid("deployment.base_revision must be an integer in [0, 2^53] (0: no active deployment).")

        # The configuration comes in the request, or from a completed chunked transfer.
        transfer_id = deployment.get("configuration_transfer_id")
        if ("configuration" in deployment) == isinstance(transfer_id, str):
            return invalid("deployment needs either configuration (an object) or configuration_transfer_id.")
        if isinstance(transfer_id, str):
            self._expire_transfers()
            transfer = self.transfers.get(transfer_id)
            if transfer is None or transfer.configuration is None:
                return error(request_id, "TRANSFER_NOT_FOUND",
                             f"No completed configuration transfer '{transfer_id}' (it may have expired).")
            configuration = transfer.configuration
        else:
            configuration = deployment["configuration"]
            if not isinstance(configuration, dict):
                return invalid("deployment.configuration must be an object.")
            size = len(dumps(configuration).encode("utf-8"))
            if size > self.max_configuration_bytes:
                return error(request_id, "CONFIGURATION_TOO_LARGE",
                             "The configuration exceeds max_configuration_bytes; send it by chunked transfer.",
                             {"bytes": size, "max_configuration_bytes": self.max_configuration_bytes})
        project_revision = configuration.get("project_revision")
        if not isinstance(project_revision, str) or not project_revision:
            return invalid("configuration.project_revision must be a non-empty string.")
        claimed = configuration.get("configuration_digest")
        if not isinstance(claimed, str) or not claimed:
            return invalid("configuration.configuration_digest must be a non-empty string.")
        diagram = configuration.get("diagram")
        if not isinstance(diagram, dict):
            return invalid("configuration.diagram must be an object.")
        try:
            digest = configuration_digest(configuration)
        except (ValueError, TypeError) as ex:
            return invalid(f"configuration cannot be canonicalized: {ex}")
        if digest != claimed:
            return invalid("configuration_digest does not match the configuration content.",
                           {"expected": digest, "received": claimed})

        incompatibilities = []
        requirements = deployment.get("requires", {})
        if not isinstance(requirements, dict):
            return invalid("deployment.requires must be an object.")
        if problem := self._check_requirements(requirements, incompatibilities):
            return invalid(problem)

        result = self._response(
            "PREPARE_DEPLOYMENT_RESULT", request_id, deployment_id=deployment_id, revision=revision,
            configuration_digest=digest, reservations={"hardware": [], "streams": []},
        )

        def not_ready(issues):
            result.update(prepare_status="NOT_READY", prepare_token=None, prepared_at=None, expires_at=None,
                          incompatibilities=issues)
            return result

        def ready(p: Prepared):
            result.update(prepare_status="READY", prepare_token=p.prepare_token, prepared_at=p.prepared_at,
                          expires_at=p.expires_at, incompatibilities=[])
            return result

        self._expire_prepared()
        active_revision = self.active.revision if self.active else 0
        if base_revision != active_revision:
            return error(request_id, "REVISION_CONFLICT", "base_revision does not match the node's active revision.",
                         {"active_revision": active_revision, "base_revision": base_revision})
        key = (deployment_id, revision)
        if existing := self.prepared.get(key):
            if existing.configuration_digest != digest:
                return invalid("This deployment revision is already prepared with a different configuration.")
            return ready(existing)
        if incompatibilities:
            return not_ready(incompatibilities)

        # This node runs its own part of the diagram; compiled now, run on commit.
        try:
            if self.descriptor.node_uuid not in diagrams.placed_nodes(diagram):
                raise SchemaError(f"No element of the diagram is placed on this node ({self.descriptor.node_uuid}).")
            node_schema = diagrams.extract_node_schema(diagram, self.descriptor.node_uuid)
            data_peers = diagrams.producer_endpoints(diagram, self.descriptor.node_uuid)
            if self.data is not None:
                try:
                    self.data.check_peers(data_peers)
                except ValueError as ex:
                    raise SchemaError(str(ex)) from None
            staged = self.host.stage(node_schema, diagrams.model_time_step_ns(diagram), data_peers)
        except SchemaError as ex:
            return not_ready([self._issue("INVALID_CONFIGURATION", "configuration", deployment_id, str(ex))])

        prepared = Prepared(
            deployment_id=deployment_id, revision=revision, base_revision=base_revision,
            project_revision=project_revision, configuration_digest=digest,
            prepare_token="ptok_" + secrets.token_hex(32), prepared_at=iso8601(),
            expires_at=iso8601(self.prepare_ttl_s), expires=time.monotonic() + self.prepare_ttl_s,
            staged=staged, configuration=configuration, node_schema=node_schema,
        )
        self.prepared[key] = prepared
        return ready(prepared)

    @staticmethod
    def _issue(code, scope, target, message, details=None) -> dict:
        return {"code": code, "scope": scope, "target": target, "message": message, "details": details or {}}

    def _check_requirements(self, requirements: dict, issues: list) -> str | None:
        """Appends missing capabilities to issues; returns a message for a malformed entry."""
        libraries = {lib["library_id"]: lib for lib in self.descriptor.libraries()}
        if "libraries" in requirements:
            if not isinstance(requirements["libraries"], list):
                return "requires.libraries must be an array."
            for entry in requirements["libraries"]:
                library_id = entry.get("library_id") if isinstance(entry, dict) else None
                if not isinstance(library_id, str) or not library_id:
                    return "requires.libraries entries must be objects with a non-empty library_id."
                rule = entry.get("version", "")
                if not isinstance(rule, str) or (rule and not rule.startswith(">=")):
                    return "requires.libraries version rules must have the form '>=X.Y.Z'."
                if library_id not in libraries:
                    issues.append(self._issue("MISSING_LIBRARY", "library", library_id, "Required library is not installed."))
                elif rule and _version(libraries[library_id]["version"]) < _version(rule[2:]):
                    issues.append(self._issue("LIBRARY_VERSION_MISMATCH", "library", library_id,
                                              "Installed library version is lower than required.",
                                              {"installed": libraries[library_id]["version"], "required": rule}))
        if "elements" in requirements:
            if not isinstance(requirements["elements"], list):
                return "requires.elements must be an array."
            for name in requirements["elements"]:
                if not isinstance(name, str) or not name:
                    return "requires.elements entries must be non-empty strings."
                if name not in self.descriptor.element_types:
                    issues.append(self._issue("MISSING_ELEMENT", "element", name, "Required element type is not available."))
        if "hardware" in requirements:
            if not isinstance(requirements["hardware"], list):
                return "requires.hardware must be an array."
            for entry in requirements["hardware"]:
                capability = entry.get("capability") if isinstance(entry, dict) else None
                if not isinstance(capability, str) or not capability:
                    return "requires.hardware entries must be objects with a non-empty capability."
                if capability not in self.descriptor.hardware_capabilities:
                    issues.append(self._issue("HARDWARE_MISSING", "hardware", capability,
                                              "Required hardware capability is missing."))
        return None

    def commit(self, request_id, request):
        deployment_id, token = request.get("deployment_id"), request.get("prepare_token")
        revision = read_revision(request, "revision", False)
        if not isinstance(deployment_id, str) or not deployment_id or not isinstance(token, str) or not token \
                or revision is None:
            return error(request_id, "INVALID_REQUEST",
                         "COMMIT_DEPLOYMENT requires deployment_id, revision in [1, 2^53], and prepare_token.")
        # When the committed graph starts (UTC ns): the same moment on every node.
        activate_at = request.get("activate_at_ns")
        if activate_at is not None:
            if not is_int(activate_at) or activate_at <= 0:
                return error(request_id, "INVALID_REQUEST", "activate_at_ns must be a positive integer (UTC nanoseconds).")
            if activate_at > utc_now_ns() + MAX_ACTIVATION_DELAY_NS:
                return error(request_id, "INVALID_REQUEST", "activate_at_ns is more than 60 seconds ahead.")

        def committed(a: Active):
            scheduled = a.activate_at_ns is not None and a.activate_at_ns > utc_now_ns()
            return self._response(
                "COMMIT_DEPLOYMENT_RESULT", request_id, deployment_id=a.deployment_id, revision=a.revision,
                configuration_digest=a.configuration_digest, committed=True,
                state="scheduled" if scheduled else "active", activate_at_ns=a.activate_at_ns,
                execution=self.host.execution_state(), committed_at=a.committed_at,
            )

        a = self.active
        if a and a.deployment_id == deployment_id and a.revision == revision and tokens_equal(a.prepare_token, token):
            return committed(a)
        key = (deployment_id, revision)
        p = self.prepared.get(key)
        if p is None or not tokens_equal(p.prepare_token, token):
            if self._in_history(deployment_id, revision, ("expired",)):
                return error(request_id, "PREPARE_EXPIRED", "The prepared deployment has expired.")
            return error(request_id, "PREPARE_TOKEN_INVALID", "Unknown deployment or prepare_token.")
        if p.expires <= time.monotonic():
            self._record(p.deployment_id, p.revision, "expired")
            del self.prepared[key]
            return error(request_id, "PREPARE_EXPIRED", "The prepared deployment has expired.")
        if p.base_revision != (a.revision if a else 0):
            self._record(p.deployment_id, p.revision, "superseded")
            del self.prepared[key]
            return error(request_id, "REVISION_CONFLICT", "Another deployment became active after this one was prepared.")
        try:
            self.host.activate(p.staged, activate_at)
        except Exception as ex:
            self._record(p.deployment_id, p.revision, "failed")
            del self.prepared[key]
            return error(request_id, "INTERNAL_ERROR", f"Activation failed; the previous configuration remains active: {ex}")
        self.active = Active(
            deployment_id=p.deployment_id, revision=p.revision, project_revision=p.project_revision,
            configuration_digest=p.configuration_digest, committed_at=iso8601(), prepare_token=p.prepare_token,
            configuration=p.configuration, node_schema=p.node_schema, activate_at_ns=activate_at,
        )
        self._persist_active()
        self._record(p.deployment_id, p.revision, "committed")
        del self.prepared[key]
        return committed(self.active)

    def abort(self, request_id, request):
        deployment_id, token = request.get("deployment_id"), request.get("prepare_token")
        revision = read_revision(request, "revision", False)
        if not isinstance(deployment_id, str) or not deployment_id or not isinstance(token, str) or not token \
                or revision is None:
            return error(request_id, "INVALID_REQUEST",
                         "ABORT_DEPLOYMENT requires deployment_id, revision in [1, 2^53], and prepare_token.")

        def aborted():
            return self._response("ABORT_DEPLOYMENT_RESULT", request_id, deployment_id=deployment_id, revision=revision,
                                  aborted=True, state=self._state(), aborted_at=iso8601())

        key = (deployment_id, revision)
        if p := self.prepared.get(key):
            if not tokens_equal(p.prepare_token, token):
                return error(request_id, "PREPARE_TOKEN_INVALID", "Unknown deployment or prepare_token.")
            self._record(deployment_id, revision, "aborted")  # an expired preparation is discarded the same way
            del self.prepared[key]
            return aborted()
        if self.active and self.active.deployment_id == deployment_id and self.active.revision == revision:
            return error(request_id, "INVALID_REQUEST",
                         "A committed deployment cannot be aborted; deploy an earlier revision instead.")
        # Abort is idempotent: a preparation that was already discarded stays discarded.
        if self._in_history(deployment_id, revision, ("aborted", "expired", "superseded", "failed")):
            return aborted()
        return error(request_id, "PREPARE_TOKEN_INVALID", "Unknown deployment or prepare_token.")

    def recover_stream(self, request_id, request):
        stream_id = request.get("stream_id")
        if not isinstance(stream_id, str) or len(stream_id) != 36 or stream_id.count("-") != 4:
            return error(request_id, "INVALID_REQUEST", "stream_id must be a UUID.")
        recovered = False
        if self.streams is not None:
            recovered = self.streams.recover(wire.parse_stream_id(stream_id))
            if recovered:
                self.host.resume()  # a graph stopped by the stream fault steps again
        return self._response("RECOVER_STREAM_RESULT", request_id, stream_id=stream_id, recovered=recovered)

    # ---- configuration transfer ---------------------------------------------

    def begin_transfer(self, request_id, request):
        transfer_id, digest, total = request.get("transfer_id"), request.get("configuration_digest"), request.get("total_bytes")
        if not isinstance(transfer_id, str) or not 0 < len(transfer_id) <= 128 or not isinstance(digest, str) \
                or not digest or not is_int(total) or total <= 0:
            return error(request_id, "INVALID_REQUEST", "BEGIN_CONFIGURATION_TRANSFER requires transfer_id "
                         "(1-128 characters), total_bytes > 0 and configuration_digest.")
        if total > self.max_transfer_bytes:
            return error(request_id, "CONFIGURATION_TOO_LARGE", "total_bytes exceeds max_transfer_bytes.",
                         {"total_bytes": total, "max_transfer_bytes": self.max_transfer_bytes})
        self._expire_transfers()
        if existing := self.transfers.get(transfer_id):
            if existing.total_bytes != total or existing.configuration_digest != digest:
                return error(request_id, "TRANSFER_INVALID", f"Transfer '{transfer_id}' exists with other parameters.")
        else:
            if len(self.transfers) >= MAX_TRANSFERS:
                return error(request_id, "RESOURCE_LIMIT", "Too many configuration transfers in progress.")
            self.transfers[transfer_id] = Transfer(total, digest, time.monotonic() + self.prepare_ttl_s)
        return self._response("CONFIGURATION_TRANSFER_STARTED", request_id, transfer_id=transfer_id,
                              max_chunk_bytes=self.max_chunk_bytes)

    def chunk(self, request_id, request):
        transfer_id, index, offset, data = (request.get(k) for k in ("transfer_id", "index", "offset", "data"))
        if not isinstance(transfer_id, str) or not transfer_id or not is_int(index) or index < 0 \
                or not is_int(offset) or offset < 0 or not isinstance(data, str):
            return error(request_id, "INVALID_REQUEST", "CONFIGURATION_CHUNK requires transfer_id, index, offset and data.")
        # Checked against the encoded size first, so an oversized chunk is not decoded.
        chunk = decode_base64url(data) if len(data) <= (self.max_chunk_bytes + 2) // 3 * 4 else None

        def refuse(message):
            return error(request_id, "TRANSFER_INVALID", message, {"transfer_id": transfer_id, "index": index})

        self._expire_transfers()
        transfer = self.transfers.get(transfer_id)
        if transfer is None:
            return error(request_id, "TRANSFER_NOT_FOUND", f"No configuration transfer '{transfer_id}'.")
        if not chunk or len(chunk) > self.max_chunk_bytes:
            return refuse(f"data must be 1 to {self.max_chunk_bytes} bytes in unpadded base64url.")
        if index < len(transfer.chunks):
            # A repeated chunk: the same bytes again are accepted, other bytes fail the transfer.
            known_offset, known_length = transfer.chunks[index]
            same = offset == known_offset and known_length == len(chunk) and (
                transfer.configuration is not None or transfer.data[known_offset:known_offset + known_length] == chunk)
            if not same:
                del self.transfers[transfer_id]
                return refuse(f"Chunk {index} was received with other content; the transfer failed.")
        elif transfer.configuration is not None:
            return refuse("The transfer is complete.")
        elif index != len(transfer.chunks):
            return refuse(f"Chunk {len(transfer.chunks)} is expected next.")
        elif offset != len(transfer.data):
            return refuse(f"Chunk {index} must start at offset {len(transfer.data)}.")
        elif len(transfer.data) + len(chunk) > transfer.total_bytes:
            return refuse("The chunk exceeds total_bytes.")
        else:
            transfer.data += chunk
            transfer.chunks.append((offset, len(chunk)))
        received = transfer.total_bytes if transfer.configuration is not None else len(transfer.data)
        return self._response("CONFIGURATION_CHUNK_ACCEPTED", request_id, transfer_id=transfer_id, index=index,
                              received_bytes=received)

    def end_transfer(self, request_id, request):
        transfer_id = request.get("transfer_id")
        if not isinstance(transfer_id, str) or not transfer_id:
            return error(request_id, "INVALID_REQUEST", "END_CONFIGURATION_TRANSFER requires transfer_id.")
        self._expire_transfers()
        transfer = self.transfers.get(transfer_id)
        if transfer is None:
            return error(request_id, "TRANSFER_NOT_FOUND", f"No configuration transfer '{transfer_id}'.")
        if transfer.configuration is None:
            if len(transfer.data) != transfer.total_bytes:
                return error(request_id, "TRANSFER_INVALID", "The transfer is incomplete.",
                             {"received_bytes": len(transfer.data), "total_bytes": transfer.total_bytes})
            # The complete bundle must be a configuration whose canonical digest is the one announced.
            problem = ""
            try:
                parsed = loads(transfer.data.decode("utf-8"))
                if not isinstance(parsed, dict):
                    problem = "The configuration is not a JSON object."
                elif parsed.get("configuration_digest") != transfer.configuration_digest \
                        or configuration_digest(parsed) != transfer.configuration_digest:
                    problem = "The configuration does not match configuration_digest."
                else:
                    transfer.configuration = parsed
            except (ValueError, TypeError, UnicodeDecodeError, RecursionError) as ex:
                problem = f"The configuration cannot be read: {ex}"
            if problem:
                del self.transfers[transfer_id]
                return error(request_id, "TRANSFER_INVALID", problem + " The transfer failed.")
            transfer.data = bytearray()
        return self._response("CONFIGURATION_TRANSFER_COMPLETE", request_id, transfer_id=transfer_id,
                              configuration_digest=transfer.configuration_digest, total_bytes=transfer.total_bytes)

    # ---- persistence ----------------------------------------------------------

    def _persist_active(self) -> None:
        if not self.state_dir or not self.active:
            return
        a = self.active
        record = {"format": 1, "deployment_id": a.deployment_id, "revision": a.revision, "committed_at": a.committed_at,
                  "configuration": a.configuration, "activate_at_ns": a.activate_at_ns}
        try:
            write_atomically(self.state_dir / DEPLOYMENT_FILE, dumps(record))
        except OSError as ex:
            self.log(f"deployment.persist_failed {ex}")

    def restore_deployment(self) -> bool:
        """Restores the persisted active deployment, back on its original grid. False if there is none or it fails."""
        path = self.state_dir / DEPLOYMENT_FILE if self.state_dir else None
        if path is None or not path.exists():
            return False
        deployment_id, revision = "", 0
        try:
            record = loads(path.read_text(encoding="utf-8"))
            if not isinstance(record, dict):
                raise ValueError("not a JSON object")
            deployment_id = record.get("deployment_id") if isinstance(record.get("deployment_id"), str) else ""
            revision = read_revision(record, "revision", False) or 0
            configuration = record.get("configuration")
            if not deployment_id or not revision or not isinstance(configuration, dict):
                raise ValueError("deployment_id, revision and configuration are required")
            digest = configuration.get("configuration_digest")
            if not digest or configuration_digest(configuration) != digest:
                raise ValueError("the configuration does not match its configuration_digest")
            diagram = configuration.get("diagram")
            if not isinstance(diagram, dict):
                raise ValueError("configuration.diagram must be an object")
            node_schema = diagrams.extract_node_schema(diagram, self.descriptor.node_uuid)
            step_ns = diagrams.model_time_step_ns(diagram)
            staged = self.host.stage(node_schema, step_ns, diagrams.producer_endpoints(diagram, self.descriptor.node_uuid))
            # The next slot of the original activation time; steps missed while down are not caught up.
            original = record.get("activate_at_ns") if is_int(record.get("activate_at_ns")) else None
            activate_at = None
            if original is not None:
                now = utc_now_ns()
                if original > now:
                    activate_at = original
                elif step_ns:
                    activate_at = original + -(-(now - original) // step_ns) * step_ns
            self.host.activate(staged, activate_at)
        except (OSError, ValueError, TypeError, SchemaError) as ex:
            self.log(f"deployment.restore_failed path={path} error={ex}")
            self._record(deployment_id, revision, "restore_failed", str(ex))
            return False
        self.active = Active(
            deployment_id=deployment_id, revision=revision, project_revision=configuration.get("project_revision", ""),
            configuration_digest=digest, committed_at=record.get("committed_at", ""), prepare_token="",
            configuration=configuration, node_schema=node_schema, restored=True, activate_at_ns=original,
        )
        self._record(deployment_id, revision, "restored")
        self.log(f"deployment.restored deployment_id={deployment_id} revision={revision}")
        return True

    def _load_peers(self) -> None:
        path = self.state_dir / PEERS_FILE if self.state_dir else None
        if path is None or not path.exists():
            return
        try:
            records = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        for record in records if isinstance(records, list) else []:
            if isinstance(record, dict) and isinstance(record.get("endpoint"), str) and record["endpoint"]:
                self.peers[record["endpoint"]] = record

    def _save_peers(self) -> None:
        if self.state_dir:
            try:
                write_atomically(self.state_dir / PEERS_FILE, dumps(list(self.peers.values())))
            except OSError as ex:
                self.log(f"peers.persist_failed {ex}")


def _version(text: str) -> list[int]:
    parts = []
    for token in text.split("."):
        try:
            parts.append(int(token))
        except ValueError:
            parts.append(0)
    return parts + [0] * (8 - len(parts))
