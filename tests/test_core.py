import asyncio
import time
import unittest

from overlay.core import (
    Contact,
    EndToEndBox,
    FRAME_HEADER,
    Identity,
    MAX_FRAME_PAYLOAD,
    NodeRecord,
    ProtocolError,
    RecordStore,
    RoutingTable,
    decode_frame_header,
    encode_frame,
    node_record_key,
)
from overlay.config import OverlayConfig


class FrameTests(unittest.IsolatedAsyncioTestCase):
    async def test_multiple_and_fragmented_frames_preserve_boundaries(self):
        first = encode_frame("PING", {"number": 1})
        second = encode_frame("PONG", {"number": 2})
        reader = asyncio.StreamReader()
        reader.feed_data(first[:7])
        reader.feed_data(first[7:] + second)
        reader.feed_eof()

        from overlay.core import read_frame

        self.assertEqual((await read_frame(reader)).payload, {"number": 1})
        self.assertEqual((await read_frame(reader)).payload, {"number": 2})

    async def test_oversized_length_rejected_from_header(self):
        import struct

        header = FRAME_HEADER.pack(1, 1, 0, b"0" * 16, MAX_FRAME_PAYLOAD + 1)
        with self.assertRaises(ProtocolError):
            decode_frame_header(header)

    async def test_one_hundred_variable_size_frames(self):
        from overlay.core import read_frame

        packets = [encode_frame("APP_MESSAGE", {"index": index, "text": "x" * (index * 11)})
                   for index in range(100)]
        stream = asyncio.StreamReader()
        combined = b"".join(packets)
        for offset in range(0, len(combined), 137):
            stream.feed_data(combined[offset:offset + 137])
        stream.feed_eof()
        received = [await read_frame(stream) for _ in packets]
        self.assertEqual([frame.payload["index"] for frame in received], list(range(100)))


class IdentityAndRecordTests(unittest.TestCase):
    def test_identity_and_signed_record_validation(self):
        identity = Identity()
        record = NodeRecord.create(identity, ("127.0.0.1:19000",), 1)
        self.assertTrue(record.validate())
        self.assertEqual(len(node_record_key(identity.node_id)), 64)
        self.assertFalse(NodeRecord(
            record.node_id, record.identity_public_key, record.addresses, 1,
            record.issued_at, record.expires_at, "00",
        ).validate())

    def test_store_rejects_rollback(self):
        identity = Identity()
        key = node_record_key(identity.node_id)
        newer = NodeRecord.create(identity, ("127.0.0.1:19000",), 2)
        older = NodeRecord.create(identity, ("127.0.0.1:19000",), 1)
        store = RecordStore()
        self.assertTrue(store.put(key, newer))
        self.assertFalse(store.put(key, older))

    def test_store_rejects_expired_or_identity_mismatched_records(self):
        identity = Identity()
        expired = NodeRecord.create(identity, ("127.0.0.1:19000",), 1, ttl=0)
        self.assertFalse(expired.validate())
        valid = NodeRecord.create(identity, ("127.0.0.1:19000",), 2)
        mismatched = NodeRecord("f" * 64, valid.identity_public_key, valid.addresses,
                                valid.sequence_number, valid.issued_at, valid.expires_at,
                                valid.signature, valid.encryption_public_key)
        self.assertFalse(mismatched.validate())


class RoutingTableTests(unittest.IsolatedAsyncioTestCase):
    async def test_bucket_is_bounded_and_live_lru_is_retained(self):
        owner = "0" * 64
        table = RoutingTable(owner, capacity=2)
        contacts = [Contact(f"8{index:063x}", "127.0.0.1", 19000 + index) for index in range(3)]
        async def alive(_contact):
            return True

        await table.observe(contacts[0], alive)
        await table.observe(contacts[1], alive)
        await table.observe(contacts[2], alive)
        ids = [contact.node_id for contact in table.all_contacts()]
        self.assertEqual(len(ids), 2)
        self.assertIn(contacts[0].node_id, ids)
        self.assertIn(contacts[1].node_id, ids)
        self.assertNotIn(contacts[2].node_id, ids)

    async def test_parallel_lru_probes_do_not_remove_the_same_contact_twice(self):
        owner = "0" * 64
        table = RoutingTable(owner, capacity=1)
        first = Contact("8" + "0" * 63, "127.0.0.1", 19001)
        second = Contact("8" + "1" * 63, "127.0.0.1", 19002)
        third = Contact("8" + "2" * 63, "127.0.0.1", 19003)
        await table.observe(first, lambda _peer: asyncio.sleep(0, result=True))
        ready = asyncio.Event()
        probes = 0

        async def dead_lru(_peer):
            nonlocal probes
            probes += 1
            if probes == 2:
                ready.set()
            await ready.wait()
            return False

        async def live_lru(_peer):
            return True

        await asyncio.gather(table.observe(second, dead_lru), table.observe(third, dead_lru))
        self.assertEqual(len(table.all_contacts()), 1)
        self.assertIn(table.all_contacts()[0].node_id, {second.node_id, third.node_id})


class ConfigTests(unittest.TestCase):
    def test_simplified_profile_and_invalid_republish_interval(self):
        OverlayConfig().validate()
        with self.assertRaises(ValueError):
            OverlayConfig(republish_interval_seconds=91).validate()


class EndToEndTests(unittest.TestCase):
    def test_authenticated_encryption_rejects_tamper_replay_and_wrong_recipient(self):
        sender = Identity()
        recipient_identity = Identity()
        recipient = EndToEndBox()
        envelope = EndToEndBox().seal(
            recipient.public_bytes, sender, recipient_identity.node_id, b"secret payload",
        )
        self.assertEqual(recipient.open(envelope, recipient_identity.node_id, sender.node_id), b"secret payload")
        with self.assertRaises(ProtocolError):
            recipient.open(envelope, recipient_identity.node_id, sender.node_id)

        fresh = EndToEndBox()
        tampered = dict(envelope)
        tampered["ciphertext"] = "00"
        with self.assertRaises(ProtocolError):
            fresh.open(tampered, recipient_identity.node_id, sender.node_id)
        with self.assertRaises(ProtocolError):
            fresh.open(envelope, Identity().node_id)


if __name__ == "__main__":
    unittest.main()