# SPDX-FileCopyrightText: Oleksiy Lukin and S7 contributors
# SPDX-License-Identifier: GPL-3.0-or-later

"""Data streams between two endpoints over real loopback WebSocket /data connections: delivery,
reconnect with replay, identity checks and the graph-side blocking API.

Run from s7py: python3 -m unittest discover -s tests
"""
import asyncio
import sys
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from s7node import stream, wire  # noqa: E402
from s7node.transport import NODE_HEADER, DataEndpoint, DataPeer, StreamTable  # noqa: E402
from s7node.websocket import accept  # noqa: E402

NODE_A = "11111111-2222-3333-4444-555555555555"
NODE_B = "33333333-4444-5555-6666-777777777777"
STREAM_ID = wire.parse_stream_id("0335c8e1-a3ab-4e8c-8b17-dc8170f5e370")
F64 = wire.wire_type("F64")


def f64(values):
    return wire.from_values(F64, values)


class Node:
    """A data endpoint with a plain WebSocket listener."""

    def __init__(self, uuid):
        self.uuid = uuid
        self.table = StreamTable(stream.MemorySequenceStore())
        self.endpoint = DataEndpoint(self.table, uuid, log=lambda message: None)
        self.inbound = []

    async def start(self):
        self.ticks = self.endpoint.start()

        async def serve(reader, writer):
            ws = await accept(reader, writer, paths=("/data",), max_message_bytes=1 << 20,
                              response_headers={NODE_HEADER: self.uuid})
            if ws is not None:
                self.inbound.append(ws)
                await self.endpoint.serve_inbound(ws, ws.headers.get(NODE_HEADER.lower(), ""))

        self.server = await asyncio.start_server(serve, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]

    async def stop(self):
        self.ticks.cancel()
        self.endpoint.links.clear()
        for connection in list(self.endpoint.connections):
            self.endpoint._close(connection)
        self.server.close()


def config(**more):
    more.setdefault("max_elements_per_packet", 8)
    return stream.StreamConfig(STREAM_ID, F64, **more)


async def in_thread(function, *args):
    return await asyncio.to_thread(function, *args)


class TransportTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.a, self.b = Node(NODE_A), Node(NODE_B)
        await self.a.start()
        await self.b.start()

    async def asyncTearDown(self):
        await self.a.stop()
        await self.b.stop()

    def connect_b_to_a(self):
        self.b.endpoint.set_data_peers([DataPeer(f"ws://127.0.0.1:{self.a.port}/control", NODE_A)])

    async def test_delivery_and_reconnect_without_loss(self):
        producer = self.a.table.open(config(consumer_nodes=[NODE_B]), "producer")
        consumer = self.b.table.open(config(producer_node=NODE_A), "consumer")
        self.connect_b_to_a()
        values = [float(v) for v in range(1, 2001)]

        def publish():  # about 0.4 s, so the connection drops while the stream flows
            for index in range(0, len(values), 10):
                self.assertIsNone(self.a.table.publish(producer, f64(values[index:index + 10])))
                time.sleep(0.002)

        def receive(count):
            got, fault, _ = self.b.table.receive(consumer, count)
            self.assertIsNone(fault)
            return wire.values(F64, got)

        received = []
        sender = threading.Thread(target=publish)
        sender.start()
        received += await in_thread(receive, 700)
        # Drop the data connection from the producer side: the consumer reconnects and RESUMEs.
        for ws in self.a.inbound:
            ws.writer.transport.abort()
        received += await in_thread(receive, 1300)
        sender.join()
        self.assertEqual(received, values, "every value once and in order across the dropped connection")
        status = {s["role"]: s for s in self.a.table.statuses() + self.b.table.statuses()}
        self.assertEqual(status["producer"]["fault"], "NONE")
        self.assertEqual(status["consumer"]["fault"], "NONE")
        self.assertEqual(status["consumer"]["elements"], 2000)
        self.assertGreaterEqual(len(self.a.inbound), 2, "the consumer reconnected")
        self.assertGreater(status["producer"]["replayed"], 0, "packets lost with the connection were replayed")

    async def test_consumer_waits_then_underruns(self):
        consumer = self.b.table.open(config(producer_node=NODE_A, max_wait_ms=100), "consumer")
        got, fault, _ = await in_thread(self.b.table.receive, consumer, 1)
        self.assertEqual((got, fault), ([], stream.UNDERRUN), "no data within max_wait_ms faults the stream")
        self.assertTrue(self.b.table.recover(STREAM_ID))
        self.assertEqual(self.b.table.statuses()[0]["fault"], "NONE")

    async def test_backpressure_overflows_after_max_block(self):
        producer = self.a.table.open(config(send_log_max_packets=2, max_elements_per_packet=1, max_block_ms=100), "producer")
        fault = await in_thread(self.a.table.publish, producer, f64([1.0, 2.0, 3.0]))
        self.assertEqual(fault, stream.SEND_LOG_OVERFLOW, "nobody acknowledges: the full send log faults the stream")
        self.assertGreaterEqual(self.a.table.statuses()[0]["blocked_ms_total"], 90)

    async def test_only_configured_nodes_take_part(self):
        # The producer serves the stream only to its consumer nodes: B is not one.
        self.a.table.open(config(consumer_nodes=["99999999-0000-4000-8000-000000000000"]), "producer")
        consumer = self.b.table.open(config(producer_node=NODE_A, max_wait_ms=300), "consumer")
        self.connect_b_to_a()
        got, fault, _ = await in_thread(self.b.table.receive, consumer, 1)
        self.assertEqual(fault, stream.UNDERRUN)
        producer = next(s for s in self.a.table.statuses() if s["role"] == "producer")
        self.assertGreaterEqual(producer["unauthorized"], 1)
        self.assertEqual(producer["recent_faults"][0]["code"], stream.UNAUTHORIZED_CONSUMER)

    async def test_identity_mismatch_is_refused(self):
        # The data peer announces another node than the diagram names: no stream connection.
        self.b.endpoint.set_data_peers([DataPeer(f"ws://127.0.0.1:{self.a.port}/data", "99999999-0000-4000-8000-000000000000")])
        for _ in range(50):
            if self.b.endpoint.errors:
                break
            await asyncio.sleep(0.02)
        self.assertIn("identity mismatch", self.b.endpoint.errors[0])
        self.assertEqual(self.b.endpoint.connections, set())


if __name__ == "__main__":
    unittest.main()
