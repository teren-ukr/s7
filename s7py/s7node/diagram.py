# SPDX-FileCopyrightText: Oleksiy Lukin and S7 contributors
# SPDX-License-Identifier: GPL-3.0-or-later

"""A node's part of a deployed diagram (s7net/src/diagram_deployment.cpp).

A diagram's schema places each element on a node ("node": node_uuid). The part of a
node is its elements, the connections between them, and an end of each data stream
it takes part in: a NetSink for a stream it produces, a NetSource for one it consumes,
connected where the connection between nodes was (S7_Network_Wire_Protocol_v1.md,
section 12.1 item 6). A connection between nodes without a stream is refused.
"""
from dataclasses import dataclass

from . import wire
from .graph import SchemaError
from .stream import StreamDescriptor


def diagram_schema(diagram: dict) -> dict:
    schema = diagram.get("schema", diagram)
    if not isinstance(schema, dict):
        raise SchemaError("'schema' must be an object")
    return schema


def _elements(schema: dict) -> list:
    elements = schema.get("elements", [])
    if not isinstance(elements, list) or not all(isinstance(e, dict) for e in elements):
        raise SchemaError("schema: 'elements' must be an array of objects")
    return elements


def placed_nodes(diagram: dict) -> list[str]:
    nodes = []
    for element in _elements(diagram_schema(diagram)):
        node = element.get("node")
        if isinstance(node, str) and node not in nodes:
            nodes.append(node)
    return nodes


def model_time_step_ns(diagram: dict) -> int | None:
    """The model-time step `dt` (seconds) in whole nanoseconds, or None."""
    dt = diagram.get("dt")
    if dt is None:
        return None
    if isinstance(dt, bool) or not isinstance(dt, (int, float)) or not (1.0 <= dt * 1e9 <= 9e18):
        raise SchemaError("'dt' must be a positive number of seconds (at least 1 ns)")
    return round(dt * 1e9)


def parse_streams(diagram: dict) -> list[StreamDescriptor]:
    streams = diagram.get("streams", [])
    if not isinstance(streams, list):
        raise SchemaError("'streams' must be an array.")
    try:
        return [StreamDescriptor.from_json(entry) for entry in streams]
    except ValueError as error:
        raise SchemaError(str(error)) from None


@dataclass
class RuntimeNode:
    node_uuid: str
    name: str = ""
    endpoint: str = ""
    data_endpoint: str = ""
    data_security: str = ""


def parse_runtime_nodes(diagram: dict) -> list[RuntimeNode]:
    """runtime_nodes, with the split-transport data_endpoint / data_security checked (ADR-020)."""
    from .transport import _parse_ws_url

    entries = diagram.get("runtime_nodes", [])
    if not isinstance(entries, list):
        raise SchemaError("'runtime_nodes' must be an array.")
    nodes = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise SchemaError("runtime_nodes: an entry must be an object.")
        if not isinstance(entry.get("node_uuid"), str):
            raise SchemaError("runtime node: 'node_uuid' must be a string.")
        node = RuntimeNode(entry["node_uuid"])
        if isinstance(entry.get("name"), str):
            node.name = entry["name"]
        if isinstance(entry.get("endpoint"), str):
            node.endpoint = entry["endpoint"]
        if "data_endpoint" in entry or "data_security" in entry:
            for key in ("data_endpoint", "data_security"):
                if not isinstance(entry.get(key), str):
                    raise SchemaError(f"runtime node: '{key}' must be a string.")
            node.data_endpoint, node.data_security = entry["data_endpoint"], entry["data_security"]
            try:
                secure = _parse_ws_url(node.data_endpoint)[0]
            except ValueError as error:
                raise SchemaError(str(error)) from None
            if node.data_security not in ("mtls", "trusted_plaintext"):
                raise SchemaError("runtime node data_security must be 'mtls' or 'trusted_plaintext'.")
            if secure != (node.data_security == "mtls"):
                raise SchemaError("runtime node data_endpoint scheme conflicts with data_security.")
        nodes.append(node)
    return nodes


def stream_element_id(stream: StreamDescriptor, end: str) -> str:
    return f"__stream_{wire.stream_id_text(stream.stream_id)}_{end}"


def _connection(from_element, from_port, to_element, to_port) -> dict:
    return {"from_element": from_element, "from_port": from_port, "to_element": to_element, "to_port": to_port}


def _with_timing(element: dict, stream: StreamDescriptor) -> dict:
    """A stream end element with the stream's timing parameters."""
    if stream.sample_rate:
        element["params"]["sample_rate"] = list(stream.sample_rate)
    if stream.max_latency_ms is not None and element["type"] == "NetSource":
        element["params"]["max_latency_ms"] = stream.max_latency_ms
    return element


def _index(connection: dict, key: str) -> int:
    value = connection.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise SchemaError(f"connection: '{key}' must be a non-negative integer.")
    return value


def extract_node_schema(diagram: dict, node_uuid: str) -> dict:
    schema = diagram_schema(diagram)
    placement = {}
    for element in _elements(schema):
        if not isinstance(element.get("id"), str):
            raise SchemaError("element: 'id' must be a string.")
        node = element.get("node")
        placement[element["id"]] = node if isinstance(node, str) else ""
    streams = parse_streams(diagram)

    def on_node(element: str) -> bool:
        return placement.get(element) == node_uuid

    name = schema.get("name") if isinstance(schema.get("name"), str) else "diagram"
    elements = [{key: value for key, value in e.items() if key != "node"} for e in _elements(schema) if on_node(e["id"])]
    connections = []
    produced = set()  # (producer element, port) of the streams produced here
    consumed = set()  # (from element, port, to element, port) of the stream connections consumed here
    for stream in streams:
        stream_id = wire.stream_id_text(stream.stream_id)
        roles = [wire.ROLE_NAMES[role] for role, _ in stream.timestamps]
        if stream.producer.node_uuid == node_uuid:
            if not on_node(stream.producer.element):
                raise SchemaError(f"Stream {stream_id}: producer '{stream.producer.element}' is not placed on this node.")
            produced.add((stream.producer.element, stream.producer.port))
            consumer_nodes = []
            for consumer in stream.consumers:
                if consumer.node_uuid not in consumer_nodes:
                    consumer_nodes.append(consumer.node_uuid)
            elements.append(_with_timing({
                "id": stream_element_id(stream, "out"), "type": "NetSink",
                "params": {"stream_id": stream_id, "type": stream.data_type.name,
                           "max_elements_per_packet": stream.max_elements_per_packet,
                           "max_batch_latency_ms": stream.max_batch_latency_ms,
                           "send_log_max_packets": stream.send_log_max_packets, "max_block_ms": stream.max_block_ms,
                           "consumer_nodes": consumer_nodes, "timestamps": roles}}, stream))
            connections.append(_connection(stream.producer.element, stream.producer.port, stream_element_id(stream, "out"), 0))
        consumes = False
        for consumer in stream.consumers:
            if consumer.node_uuid != node_uuid:
                continue
            if not on_node(consumer.element):
                raise SchemaError(f"Stream {stream_id}: consumer '{consumer.element}' is not placed on this node.")
            consumed.add((stream.producer.element, stream.producer.port, consumer.element, consumer.port))
            connections.append(_connection(stream_element_id(stream, "in"), 0, consumer.element, consumer.port))
            consumes = True
        if consumes:
            elements.append(_with_timing({
                "id": stream_element_id(stream, "in"), "type": "NetSource",
                "params": {"stream_id": stream_id, "type": stream.data_type.name, "max_wait_ms": stream.max_wait_ms,
                           "producer_node": stream.producer.node_uuid, "timestamps": roles}}, stream))

    raw = schema.get("connections", [])
    if not isinstance(raw, list):
        raise SchemaError("schema: 'connections' must be an array.")
    for c in raw:
        if not isinstance(c, dict):
            raise SchemaError("schema: a connection must be an object")
        for key in ("from_element", "to_element"):
            if not isinstance(c.get(key), str):
                raise SchemaError(f"connection: '{key}' must be a string.")
        link = (c["from_element"], _index(c, "from_port"), c["to_element"], _index(c, "to_port"))
        from_here, to_here = on_node(link[0]), on_node(link[2])
        described = f"{link[0]}:{link[1]} -> {link[2]}:{link[3]}"
        if from_here and to_here:
            connections.append(_connection(*link))
        elif from_here and (link[0], link[1]) not in produced:
            raise SchemaError(f"Connection {described} leaves this node without a stream.")
        elif to_here and link not in consumed:
            raise SchemaError(f"Connection {described} enters this node without a stream.")
    return {"name": f"{name}@{node_uuid}", "elements": elements, "connections": connections}


def producer_endpoints(diagram: dict, node_uuid: str) -> list:
    """The data peers this node connects to: the producer node of every stream it consumes from
    another node, at its data_endpoint (or its endpoint)."""
    from .transport import DataPeer

    endpoints = {node.node_uuid: DataPeer(node.data_endpoint or node.endpoint, node.node_uuid,
                                          node.data_security == "trusted_plaintext")
                 for node in parse_runtime_nodes(diagram)}
    result = []
    for stream in parse_streams(diagram):
        consumes = any(c.node_uuid == node_uuid for c in stream.consumers)
        if not consumes or stream.producer.node_uuid == node_uuid:
            continue
        peer = endpoints.get(stream.producer.node_uuid)
        if peer is None or not peer.url:
            raise SchemaError(f"Stream {wire.stream_id_text(stream.stream_id)}: producer node "
                              f"{stream.producer.node_uuid} has no endpoint in 'runtime_nodes'.")
        if peer not in result:
            result.append(peer)
    return result
