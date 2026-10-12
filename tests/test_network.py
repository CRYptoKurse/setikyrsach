import asyncio
import socket
import tempfile
import unittest

from overlay.core import Contact
from overlay.network import OverlayNetwork


def available_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


class NetworkIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def test_nodes_exchange_ping_over_mutual_tls_13(self):
        with tempfile.TemporaryDirectory() as directory:
            network = OverlayNetwork(directory, count=2, base_port=available_port())
            try:
                await network.start()
                response = await network.node(1).rpc(network.contacts[0], "PING", {})
                self.assertEqual(response["node_id"], network.node(0).identity.node_id)
                self.assertEqual(network.node(1).client_context.maximum_version, 772)
                spoofed = Contact(network.node(1).identity.node_id, network.contacts[0].host, network.contacts[0].port)
                with self.assertRaises(Exception):
                    await network.node(1).rpc(spoofed, "PING", {})
            finally:
                await network.stop()


if __name__ == "__main__":
    unittest.main()