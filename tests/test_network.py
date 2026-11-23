import ssl
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
                self.assertEqual(network.node(1).client_context.maximum_version, ssl.TLSVersion.TLSv1_3)
                self.assertEqual(network.node(1).client_context.minimum_version, ssl.TLSVersion.TLSv1_3)
                self.assertTrue(network.node(1).client_context.options & ssl.OP_NO_TICKET)
                spoofed = Contact(network.node(1).identity.node_id, network.contacts[0].host, network.contacts[0].port)
                with self.assertRaises(Exception):
                    await network.node(1).rpc(spoofed, "PING", {})
            finally:
                await network.stop()

    async def test_tunnel_prepares_activates_delivers_and_closes(self):
        with tempfile.TemporaryDirectory() as directory:
            network = OverlayNetwork(directory, count=5, base_port=available_port(), bootstrap="star")
            try:
                await network.start()
                sender = network.node(1)
                receiver = network.node(4)
                tunnel = await sender.build_tunnel(receiver.identity.node_id)
                self.assertEqual(tunnel["state"], "ACTIVE")
                nodes_by_id = {node.identity.node_id: node for node in network.nodes}
                relays = [nodes_by_id[peer.node_id] for peer in tunnel["route"]]
                self.assertTrue(all(relay.tunnels[tunnel["tunnel_id"]]["state"] == "ACTIVE" for relay in relays))
                result = await sender.send_via_tunnel(tunnel, "tunnel integration")
                self.assertTrue(result["delivered"])
                self.assertEqual(len(result["relay_ids"]), 2)

                await sender.close_tunnel(tunnel)
                self.assertEqual(tunnel["state"], "DEAD")
                self.assertTrue(all(relay.tunnels[tunnel["tunnel_id"]]["state"] == "DEAD" for relay in relays))
                self.assertIn("BUILDING", {event["state"] for event in sender.tunnel_history})
                self.assertIn("CLOSING", {event["state"] for event in sender.tunnel_history})
                self.assertIn("DEAD", {event["state"] for event in sender.tunnel_history})
                with self.assertRaises(Exception):
                    await sender.send_via_tunnel(tunnel, "after close")
            finally:
                await network.stop()


if __name__ == "__main__":
    unittest.main()