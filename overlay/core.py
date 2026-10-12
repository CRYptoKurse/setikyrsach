from __future__ import annotations

import asyncio
import hashlib
import json
import os
import struct
import time
import uuid
from collections import OrderedDict
from dataclasses import dataclass
from typing import Awaitable, Callable

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


PROTOCOL_VERSION = 1
MAX_FRAME_PAYLOAD = 65_536
FRAME_HEADER = struct.Struct("!BBH16sI")
ALPHA = 3
DEFAULT_TTL = 180

MESSAGE_TYPES = {
    "PING": 1,
    "PONG": 2,
    "FIND_NODE_REQUEST": 3,
    "FIND_NODE_RESPONSE": 4,
    "STORE_REQUEST": 5,
    "STORE_RESPONSE": 6,
    "FIND_VALUE_REQUEST": 7,
    "FIND_VALUE_RESPONSE": 8,
    "TUNNEL_BUILD": 9,
    "TUNNEL_BUILD_OK": 10,
    "TUNNEL_BUILD_FAIL": 11,
    "TUNNEL_DATA": 12,
    "TUNNEL_ACK": 13,
    "TUNNEL_CLOSE": 14,
    "APP_MESSAGE": 15,
    "APP_ACK": 16,
    "ERROR": 255,
}
MESSAGE_NAMES = {value: key for key, value in MESSAGE_TYPES.items()}


class ProtocolError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class Frame:
    message_type: str
    payload: dict
    request_id: bytes
    flags: int = 0


def encode_frame(message_type: str, payload: dict, request_id: bytes | None = None, flags: int = 0) -> bytes:
    if message_type not in MESSAGE_TYPES:
        raise ProtocolError("unknown message type")
    request_id = request_id or uuid.uuid4().bytes
    if len(request_id) != 16:
        raise ProtocolError("request_id must be 16 bytes")
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    if len(body) > MAX_FRAME_PAYLOAD:
        raise ProtocolError("frame payload exceeds limit")
    return FRAME_HEADER.pack(PROTOCOL_VERSION, MESSAGE_TYPES[message_type], flags, request_id, len(body)) + body


def decode_frame_header(header: bytes) -> tuple[str, int, bytes, int]:
    if len(header) != FRAME_HEADER.size:
        raise ProtocolError("invalid frame header length")
    version, message_code, flags, request_id, payload_length = FRAME_HEADER.unpack(header)
    if version != PROTOCOL_VERSION:
        raise ProtocolError("unsupported protocol version")
    if message_code not in MESSAGE_NAMES:
        raise ProtocolError("unknown message type")
    if payload_length > MAX_FRAME_PAYLOAD:
        raise ProtocolError("frame payload exceeds limit")
    return MESSAGE_NAMES[message_code], flags, request_id, payload_length


async def read_frame(reader: asyncio.StreamReader) -> Frame:
    header = await reader.readexactly(FRAME_HEADER.size)
    message_type, flags, request_id, payload_length = decode_frame_header(header)
    body = await reader.readexactly(payload_length)
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError("invalid JSON payload") from exc
    if not isinstance(payload, dict):
        raise ProtocolError("frame payload must be an object")
    return Frame(message_type, payload, request_id, flags)


def canonical_json(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def public_key_bytes(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def node_id_from_public_key(raw_key: bytes) -> str:
    if len(raw_key) != 32:
        raise ProtocolError("invalid Ed25519 public key size")
    return hashlib.sha256(raw_key).hexdigest()


class Identity:
    def __init__(self, signing_key: Ed25519PrivateKey | None = None):
        self.signing_key = signing_key or Ed25519PrivateKey.generate()
        self.public_key = self.signing_key.public_key()
        self.public_bytes = public_key_bytes(self.public_key)
        self.node_id = node_id_from_public_key(self.public_bytes)

    def sign(self, data: bytes) -> str:
        return self.signing_key.sign(data).hex()

    def verify(self, data: bytes, signature: str) -> bool:
        try:
            self.public_key.verify(bytes.fromhex(signature), data)
            return True
        except (InvalidSignature, ValueError):
            return False

    def save(self, path: str) -> None:
        encoded = self.signing_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, "wb") as key_file:
            key_file.write(encoded)

    @classmethod
    def load_or_create(cls, path: str) -> Identity:
        if os.path.exists(path):
            with open(path, "rb") as key_file:
                key = serialization.load_pem_private_key(key_file.read(), password=None)
            if not isinstance(key, Ed25519PrivateKey):
                raise ProtocolError("identity key must use Ed25519")
            return cls(key)
        identity = cls()
        identity.save(path)
        return identity


def xor_distance(left: str, right: str) -> int:
    return int(left, 16) ^ int(right, 16)


def bucket_index(left: str, right: str) -> int:
    distance = xor_distance(left, right)
    if distance == 0:
        raise ValueError("a node cannot be its own contact")
    return distance.bit_length() - 1


@dataclass(frozen=True, slots=True)
class Contact:
    node_id: str
    host: str
    port: int

    def to_dict(self) -> dict:
        return {"node_id": self.node_id, "host": self.host, "port": self.port}

    @classmethod
    def from_dict(cls, value: dict) -> Contact:
        return cls(str(value["node_id"]), str(value["host"]), int(value["port"]))


class RoutingTable:
    def __init__(self, owner_id: str, capacity: int = 3):
        self.owner_id = owner_id
        self.capacity = capacity
        self.buckets: list[OrderedDict[str, Contact]] = [OrderedDict() for _ in range(256)]

    async def observe(self, contact: Contact, ping: Callable[[Contact], Awaitable[bool]]) -> None:
        if contact.node_id == self.owner_id:
            return
        bucket = self.buckets[bucket_index(self.owner_id, contact.node_id)]
        while True:
            if contact.node_id in bucket:
                bucket.pop(contact.node_id)
                bucket[contact.node_id] = contact
                return
            if len(bucket) < self.capacity:
                bucket[contact.node_id] = contact
                return
            oldest_id, oldest = next(iter(bucket.items()))
            oldest_is_alive = await ping(oldest)
            if oldest_id not in bucket:
                continue
            if oldest_is_alive:
                bucket.move_to_end(oldest_id)
                return
            bucket.pop(oldest_id, None)

    def all_contacts(self) -> list[Contact]:
        return [contact for bucket in self.buckets for contact in bucket.values()]

    def closest(self, target_id: str, count: int) -> list[Contact]:
        return sorted(self.all_contacts(), key=lambda peer: xor_distance(peer.node_id, target_id))[:count]

    def bucket_sizes(self) -> list[int]:
        return [len(bucket) for bucket in self.buckets]


@dataclass(frozen=True, slots=True)
class NodeRecord:
    node_id: str
    identity_public_key: str
    addresses: tuple[str, ...]
    sequence_number: int
    issued_at: int
    expires_at: int
    signature: str
    encryption_public_key: str = ""

    def unsigned_dict(self) -> dict:
        return {
            "node_id": self.node_id,
            "identity_public_key": self.identity_public_key,
            "addresses": list(self.addresses),
            "sequence_number": self.sequence_number,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "encryption_public_key": self.encryption_public_key,
        }

    def to_dict(self) -> dict:
        return {**self.unsigned_dict(), "signature": self.signature}

    @classmethod
    def create(cls, identity: Identity, addresses: tuple[str, ...], sequence_number: int, ttl: int = DEFAULT_TTL,
               encryption_public_key: bytes = b"") -> NodeRecord:
        now = int(time.time())
        unsigned = {
            "node_id": identity.node_id,
            "identity_public_key": identity.public_bytes.hex(),
            "addresses": list(addresses),
            "sequence_number": sequence_number,
            "issued_at": now,
            "expires_at": now + ttl,
            "encryption_public_key": encryption_public_key.hex(),
        }
        signature = identity.sign(canonical_json(unsigned))
        return cls(identity.node_id, identity.public_bytes.hex(), addresses, sequence_number, now, now + ttl,
                   signature, encryption_public_key.hex())

    @classmethod
    def from_dict(cls, value: dict) -> NodeRecord:
        return cls(
            str(value["node_id"]), str(value["identity_public_key"]), tuple(map(str, value["addresses"])),
            int(value["sequence_number"]), int(value["issued_at"]), int(value["expires_at"]),
            str(value["signature"]), str(value.get("encryption_public_key", "")),
        )

    def validate(self, now: int | None = None) -> bool:
        try:
            raw_key = bytes.fromhex(self.identity_public_key)
            if node_id_from_public_key(raw_key) != self.node_id:
                return False
            if self.encryption_public_key and len(bytes.fromhex(self.encryption_public_key)) != 32:
                return False
            if not self.addresses or any(len(address) > 255 or not address for address in self.addresses):
                return False
            if self.expires_at <= (now or int(time.time())) or self.expires_at <= self.issued_at:
                return False
            if not 120 <= self.expires_at - self.issued_at <= 300 or self.sequence_number < 0:
                return False
            Ed25519PublicKey.from_public_bytes(raw_key).verify(bytes.fromhex(self.signature), canonical_json(self.unsigned_dict()))
            return True
        except (InvalidSignature, ValueError, KeyError, TypeError):
            return False


class RecordStore:
    def __init__(self):
        self.records: dict[str, NodeRecord] = {}

    def put(self, key: str, record: NodeRecord) -> bool:
        if not record.validate():
            return False
        current = self.records.get(key)
        if current and current.sequence_number > record.sequence_number:
            return False
        self.records[key] = record
        return True

    def get(self, key: str) -> NodeRecord | None:
        record = self.records.get(key)
        if record and record.expires_at > int(time.time()):
            return record
        self.records.pop(key, None)
        return None


def node_record_key(node_id: str) -> str:
    return hashlib.sha256(("node:" + node_id).encode("ascii")).hexdigest()


class EndToEndBox:
    def __init__(self, private_key: X25519PrivateKey | None = None):
        self.private_key = private_key or X25519PrivateKey.generate()
        self.public_bytes = self.private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw,
        )
        self.seen_messages: set[tuple[str, str]] = set()
        self.closed_sessions: set[str] = set()

    @staticmethod
    def _derive(shared_secret: bytes, session_id: str, sender_id: str, recipient_id: str) -> bytes:
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=bytes.fromhex(session_id),
                    info=f"seti-e2e-v1:{sender_id}:{recipient_id}".encode("ascii")).derive(shared_secret)

    def seal(self, recipient_public: bytes, sender_identity: Identity, recipient_id: str, plaintext: bytes,
             session_id: str | None = None, message_id: str | None = None) -> dict:
        sender_id = sender_identity.node_id
        session_id = session_id or uuid.uuid4().hex
        message_id = message_id or uuid.uuid4().hex
        ephemeral = X25519PrivateKey.generate()
        ephemeral_public = ephemeral.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        shared = ephemeral.exchange(X25519PublicKey.from_public_bytes(recipient_public))
        key = self._derive(shared, session_id, sender_id, recipient_id)
        nonce = os.urandom(12)
        aad = canonical_json({"sender_id": sender_id, "recipient_id": recipient_id, "session_id": session_id, "message_id": message_id})
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
        envelope = {"sender_id": sender_id, "recipient_id": recipient_id, "session_id": session_id,
                    "message_id": message_id, "ephemeral_public": ephemeral_public.hex(),
                    "identity_public_key": sender_identity.public_bytes.hex(),
                    "nonce": nonce.hex(), "ciphertext": ciphertext.hex()}
        envelope["signature"] = sender_identity.sign(canonical_json(envelope))
        return envelope

    def open(self, envelope: dict, expected_recipient_id: str, expected_sender_id: str | None = None) -> bytes:
        session_id = str(envelope["session_id"])
        message_id = str(envelope["message_id"])
        replay_key = (session_id, message_id)
        if session_id in self.closed_sessions or replay_key in self.seen_messages:
            raise ProtocolError("replayed or closed-session message")
        if envelope["recipient_id"] != expected_recipient_id:
            raise ProtocolError("recipient mismatch")
        sender_id = str(envelope["sender_id"])
        recipient_id = str(envelope["recipient_id"])
        identity_key = bytes.fromhex(envelope["identity_public_key"])
        if node_id_from_public_key(identity_key) != sender_id or (expected_sender_id and sender_id != expected_sender_id):
            raise ProtocolError("sender identity mismatch")
        signed_envelope = {key: value for key, value in envelope.items() if key != "signature"}
        try:
            Ed25519PublicKey.from_public_bytes(identity_key).verify(
                bytes.fromhex(envelope["signature"]), canonical_json(signed_envelope),
            )
        except (InvalidSignature, ValueError) as exc:
            raise ProtocolError("invalid sender signature") from exc
        shared = self.private_key.exchange(X25519PublicKey.from_public_bytes(bytes.fromhex(envelope["ephemeral_public"])))
        key = self._derive(shared, session_id, sender_id, recipient_id)
        aad = canonical_json({"sender_id": sender_id, "recipient_id": recipient_id, "session_id": session_id, "message_id": message_id})
        try:
            plaintext = AESGCM(key).decrypt(bytes.fromhex(envelope["nonce"]), bytes.fromhex(envelope["ciphertext"]), aad)
        except (InvalidTag, ValueError) as exc:
            raise ProtocolError("invalid encrypted message") from exc
        self.seen_messages.add(replay_key)
        return plaintext

    def close_session(self, session_id: str) -> None:
        self.closed_sessions.add(session_id)
