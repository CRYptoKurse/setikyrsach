from __future__ import annotations

import asyncio
import hashlib
import json
import os
import secrets
import ssl
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.x509.oid import NameOID

from .core import (
    ALPHA,
    DEFAULT_TTL,
    Contact,
    EndToEndBox,
    Identity,
    NodeRecord,
    ProtocolError,
    RecordStore,
    RoutingTable,
    canonical_json,
    encode_frame,
    node_id_from_public_key,
    node_record_key,
    read_frame,
    xor_distance,
)
from .config import OverlayConfig


K_BUCKET_SIZE = 3
REPLICATION_FACTOR = 3
RPC_TIMEOUT = 0.8


def _write_private_key(path: Path, key) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption(),
    ))


class LabPKI:
    """Изолированный CA лабораторного запуска; не участвует в DHT discovery."""

    def __init__(self, state_dir: Path):
        self.state_dir = state_dir
        self.ca_key_path = state_dir / "lab-ca-key.pem"
        self.ca_cert_path = state_dir / "lab-ca-cert.pem"

    def prepare(self, count: int) -> list[tuple[Identity, EndToEndBox, Path, Path]]:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        if self.ca_key_path.exists() and self.ca_cert_path.exists():
            ca_key = serialization.load_pem_private_key(self.ca_key_path.read_bytes(), password=None)
            ca_cert = x509.load_pem_x509_certificate(self.ca_cert_path.read_bytes())
        else:
            ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            now = datetime.now(timezone.utc)
            subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SETI isolated lab CA")])
            ca_cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
                       .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
                       .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=365))
                       .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                       .add_extension(x509.KeyUsage(
                           digital_signature=True, content_commitment=False, key_encipherment=False,
                           data_encipherment=False, key_agreement=False, key_cert_sign=True,
                           crl_sign=True, encipher_only=None, decipher_only=None,
                       ), critical=True)
                       .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
                       .sign(ca_key, hashes.SHA256()))
            _write_private_key(self.ca_key_path, ca_key)
            self.ca_cert_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))

        result = []
        for index in range(count):
            directory = self.state_dir / f"node-{index:02d}"
            directory.mkdir(parents=True, exist_ok=True)
            identity = Identity.load_or_create(str(directory / "identity-ed25519.pem"))
            dh_path = directory / "identity-x25519.pem"
            if dh_path.exists():
                dh_key = serialization.load_pem_private_key(dh_path.read_bytes(), password=None)
            else:
                dh_key = X25519PrivateKey.generate()
                _write_private_key(dh_path, dh_key)
            box = EndToEndBox(dh_key)
            cert_path = directory / "node-cert.pem"
            if not cert_path.exists():
                now = datetime.now(timezone.utc)
                subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, identity.node_id)])
                cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(ca_cert.subject)
                        .public_key(identity.public_key).serial_number(x509.random_serial_number())
                        .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=30))
                        .add_extension(x509.SubjectAlternativeName([x509.DNSName(identity.node_id[:63])]), critical=False)
                        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
                        .add_extension(x509.ExtendedKeyUsage([
                            x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                            x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                        ]), critical=False)
                        .sign(ca_key, hashes.SHA256()))
                cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
            else:
                cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
                if cert.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw) != identity.public_bytes:
                    raise ProtocolError(f"TLS certificate does not match identity for {directory}")
            result.append((identity, box, cert_path, directory / "identity-ed25519.pem"))
        return result

    def server_context(self, cert_path: Path, key_path: Path) -> ssl.SSLContext:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.options |= ssl.OP_NO_TICKET
        context.load_cert_chain(str(cert_path), str(key_path))
        context.load_verify_locations(cafile=str(self.ca_cert_path))
        context.verify_mode = ssl.CERT_REQUIRED
        return context

    def client_context(self, cert_path: Path, key_path: Path) -> ssl.SSLContext:
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(self.ca_cert_path))
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.options |= ssl.OP_NO_TICKET
        context.load_cert_chain(str(cert_path), str(key_path))
        context.check_hostname = True
        return context


@dataclass(slots=True)
class LookupResult:
    contacts: list[Contact]
    lookup_id: str
    target_id: str
    queried: list[list[str]]
    rpc_count: int
    iterations: int
    errors: list[str]
    duration_ms: float


class OverlayNode:
    def __init__(self, contact: Contact, identity: Identity, box: EndToEndBox, state_dir: Path,
                 server_context: ssl.SSLContext, client_context: ssl.SSLContext,
                 config: OverlayConfig | None = None):
        self.contact = contact
        self.identity = identity
        self.box = box
        self.state_dir = state_dir
        self.server_context = server_context
        self.client_context = client_context
        self.config = config or OverlayConfig()
        self.config.validate()
        self.routing = RoutingTable(identity.node_id, self.config.bucket_size)
        self.store = RecordStore()
        self.server: asyncio.AbstractServer | None = None
        self.record_sequence = 0
        self.received_messages: list[dict] = []
        self.message_history: list[dict] = []
        self.tunnels: dict[str, dict] = {}
        self.lookup_logs: list[dict] = []
        self.metrics: dict[str, list[float]] = {"tunnel_build_ms": [], "message_e2e_ms": [], "recovery_ms": []}
        self.rpc_counts: dict[str, int] = {}
        self.last_store_diagnostics: dict = {}
        self.log_path = state_dir / "events.jsonl"
        self._maintenance_task: asyncio.Task | None = None
        self._maintenance_enabled = False
        self._last_republish = time.monotonic()

    async def start(self) -> None:
        self.server = await asyncio.start_server(
            self._handle_connection, self.contact.host, self.contact.port, ssl=self.server_context,
        )
        if self._maintenance_enabled:
            self.start_maintenance()

    async def stop(self) -> None:
        if self._maintenance_task:
            self._maintenance_task.cancel()
            await asyncio.gather(self._maintenance_task, return_exceptions=True)
            self._maintenance_task = None
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            self.server = None

    def _event(self, event: dict) -> None:
        event = {"time": time.time(), "node_id": self.identity.node_id, **event}
        self.state_dir.mkdir(parents=True, exist_ok=True)
        with self.log_path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(event, sort_keys=True) + "\n")

    def _peer_node_id(self, writer: asyncio.StreamWriter) -> str:
        ssl_object = writer.get_extra_info("ssl_object")
        if ssl_object is None:
            raise ProtocolError("TLS is required")
        certificate_der = ssl_object.getpeercert(binary_form=True)
        certificate = x509.load_der_x509_certificate(certificate_der)
        public_key = certificate.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw,
        )
        peer_id = node_id_from_public_key(public_key)
        names = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
        if peer_id[:63] not in names:
            raise ProtocolError("peer certificate identity mismatch")
        return peer_id

    async def _handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            peer_id = self._peer_node_id(writer)
            frame = await asyncio.wait_for(read_frame(reader), self.config.rpc_timeout_seconds)
            response_type, response_payload = await self._dispatch(frame.message_type, frame.payload, peer_id)
            writer.write(encode_frame(response_type, response_payload, frame.request_id, flags=1))
            await asyncio.wait_for(writer.drain(), self.config.rpc_timeout_seconds)
        except Exception as exc:
            try:
                writer.write(encode_frame("ERROR", {"error": str(exc)[:256]}, flags=1))
                await writer.drain()
            except Exception:
                pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def _dispatch(self, message_type: str, payload: dict, peer_id: str) -> tuple[str, dict]:
        self.rpc_counts[message_type] = self.rpc_counts.get(message_type, 0) + 1
        if message_type == "PING":
            await self._observe_peer_from_payload(payload, peer_id)
            return "PONG", {"node_id": self.identity.node_id}
        if message_type == "FIND_NODE_REQUEST":
            await self._observe_peer_from_payload(payload, peer_id)
            target_id = str(payload["target_id"])
            contacts = {peer.node_id: peer for peer in self.routing.closest(target_id, self.config.bucket_size)}
            contacts[self.identity.node_id] = self.contact
            closest = sorted(contacts.values(), key=lambda peer: xor_distance(peer.node_id, target_id))[:self.config.bucket_size]
            return "FIND_NODE_RESPONSE", {"contacts": [peer.to_dict() for peer in closest]}
        if message_type == "STORE_REQUEST":
            await self._observe_peer_from_payload(payload, peer_id)
            record = NodeRecord.from_dict(payload["record"])
            accepted = self.store.put(str(payload["key"]), record)
            return "STORE_RESPONSE", {"stored": accepted}
        if message_type == "FIND_VALUE_REQUEST":
            await self._observe_peer_from_payload(payload, peer_id)
            key = str(payload["key"])
            record = self.store.get(key)
            if record:
                return "FIND_VALUE_RESPONSE", {"record": record.to_dict(), "contacts": []}
            contacts = {peer.node_id: peer for peer in self.routing.closest(key, self.config.bucket_size)}
            contacts[self.identity.node_id] = self.contact
            return "FIND_VALUE_RESPONSE", {
                "record": None,
                "contacts": [peer.to_dict() for peer in sorted(
                    contacts.values(), key=lambda peer: xor_distance(peer.node_id, key),
                )[:self.config.bucket_size]],
            }
        if message_type == "TUNNEL_BUILD":
            if peer_id != payload["initiator_id"]:
                raise ProtocolError("tunnel build initiator mismatch")
            route = payload["route"]
            position = int(payload["position"])
            if position < 0 or position >= len(route) or route[position]["node_id"] != self.identity.node_id:
                raise ProtocolError("invalid tunnel route position")
            self.tunnels[str(payload["tunnel_id"])] = {
                "initiator_id": peer_id, "destination_id": payload["destination_id"],
                "route": route, "position": position, "state": "ACTIVE",
                "expires_at": time.time() + self.config.tunnel_ttl_seconds,
            }
            return "TUNNEL_BUILD_OK", {"node_id": self.identity.node_id, "tunnel_id": payload["tunnel_id"]}
        if message_type == "TUNNEL_DATA":
            return await self._forward_tunnel_data(payload, peer_id)
        if message_type == "APP_MESSAGE":
            if payload["destination_id"] != self.identity.node_id:
                raise ProtocolError("application message addressed to another node")
            envelope = payload["envelope"]
            plaintext = self.box.open(envelope, self.identity.node_id)
            message = {"message_id": envelope["message_id"], "sender_id": envelope["sender_id"],
                       "text": plaintext.decode("utf-8"), "received_at": time.time(),
                       "tunnel_id": payload["tunnel_id"]}
            self.received_messages.append(message)
            self._event({"event": "message_received", **message})
            return "APP_ACK", {"message_id": envelope["message_id"], "delivered": True}
        if message_type == "TUNNEL_CLOSE":
            self.tunnels.pop(str(payload["tunnel_id"]), None)
            return "TUNNEL_ACK", {"closed": True}
        raise ProtocolError(f"unsupported request: {message_type}")

    async def _observe_peer_from_payload(self, payload: dict, peer_id: str) -> None:
        raw_contact = payload.get("contact")
        if raw_contact:
            contact = Contact.from_dict(raw_contact)
            if contact.node_id != peer_id:
                raise ProtocolError("contact does not match authenticated TLS peer")
            await self.routing.observe(contact, self._ping)

    async def _ping(self, contact: Contact) -> bool:
        try:
            response = await self.rpc(contact, "PING", {"contact": self.contact.to_dict()})
            return response.get("node_id") == contact.node_id
        except Exception:
            return False

    async def rpc(self, contact: Contact, message_type: str, payload: dict) -> dict:
        full_payload = dict(payload)
        full_payload.setdefault("contact", self.contact.to_dict())
        writer = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(contact.host, contact.port, ssl=self.client_context,
                                        server_hostname=contact.node_id[:63]), self.config.rpc_timeout_seconds,
            )
            ssl_object = writer.get_extra_info("ssl_object")
            server_certificate = x509.load_der_x509_certificate(ssl_object.getpeercert(binary_form=True))
            server_public_key = server_certificate.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw,
            )
            if node_id_from_public_key(server_public_key) != contact.node_id:
                raise ProtocolError("server certificate does not match expected NodeID")
            packet = encode_frame(message_type, full_payload)
            writer.write(packet)
            await asyncio.wait_for(writer.drain(), self.config.rpc_timeout_seconds)
            response = await asyncio.wait_for(read_frame(reader), self.config.rpc_timeout_seconds)
            if not response.flags & 1:
                raise ProtocolError("response flag missing")
            if response.message_type == "ERROR":
                raise ProtocolError(response.payload.get("error", "remote error"))
            return response.payload
        except Exception:
            self._remove_contact(contact.node_id)
            raise
        finally:
            if writer:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

    def _remove_contact(self, node_id: str) -> None:
        for bucket in self.routing.buckets:
            bucket.pop(node_id, None)

    async def join(self, bootstrap_peers: list[Contact]) -> None:
        for peer in bootstrap_peers:
            if await self._ping(peer):
                await self.routing.observe(peer, self._ping)
        if self.routing.all_contacts():
            await self.lookup_node(self.identity.node_id)

    async def lookup_node(self, target_id: str) -> LookupResult:
        started = time.perf_counter()
        lookup_id = uuid.uuid4().hex
        candidates = {peer.node_id: peer for peer in self.routing.closest(target_id, self.config.bucket_size)}
        queried: list[list[str]] = []
        errors: list[str] = []
        rpc_count = 0
        iterations = 0
        while iterations < 32:
            ordered = sorted(candidates.values(), key=lambda peer: xor_distance(peer.node_id, target_id))
            pending = [peer for peer in ordered if peer.node_id not in {node for batch in queried for node in batch}][:self.config.alpha]
            if not pending:
                break
            queried.append([peer.node_id for peer in pending])
            iterations += 1
            replies = await asyncio.gather(*(
                self.rpc(peer, "FIND_NODE_REQUEST", {"target_id": target_id}) for peer in pending
            ), return_exceptions=True)
            rpc_count += len(pending)
            for peer, reply in zip(pending, replies):
                if isinstance(reply, Exception):
                    errors.append(f"{peer.node_id}: {type(reply).__name__}")
                    candidates.pop(peer.node_id, None)
                    continue
                for raw_contact in reply.get("contacts", []):
                    contact = Contact.from_dict(raw_contact)
                    if contact.node_id == self.identity.node_id:
                        continue
                    candidates[contact.node_id] = contact
                    await self.routing.observe(contact, self._ping)
        result = LookupResult(
            sorted(candidates.values(), key=lambda peer: xor_distance(peer.node_id, target_id))[:self.config.bucket_size],
            lookup_id, target_id, queried, rpc_count, iterations, errors,
            (time.perf_counter() - started) * 1000,
        )
        log = {"lookup_id": lookup_id, "initiator_id": self.identity.node_id, "target_id": target_id,
               "queried_by_iteration": queried, "rpc_count": rpc_count, "iterations": iterations,
               "timeouts_errors": errors, "result_ids": [peer.node_id for peer in result.contacts],
               "duration_ms": result.duration_ms}
        self.lookup_logs.append(log)
        self._event({"event": "lookup", **log})
        return result

    async def put_record(self, key: str, record: NodeRecord) -> bool:
        if not record.validate():
            return False
        lookup = await self.lookup_node(key)
        replicas = {peer.node_id: peer for peer in lookup.contacts}
        replicas[self.identity.node_id] = self.contact
        selected = sorted(replicas.values(), key=lambda peer: xor_distance(peer.node_id, key))[:self.config.replication_factor]
        for attempt in range(2):
            replies = await asyncio.gather(*(
                self._store_local_or_remote(peer, key, record) for peer in selected
            ), return_exceptions=True)
            acknowledgements = [peer.node_id for peer, reply in zip(selected, replies) if reply is True]
            errors = [f"{peer.node_id}:{type(reply).__name__}:{str(reply)[:96]}"
                      for peer, reply in zip(selected, replies) if reply is not True]
            self.last_store_diagnostics = {
                "key": key, "selected_replica_ids": [peer.node_id for peer in selected],
                "acknowledged_replica_ids": acknowledgements, "errors": errors,
                "attempts": attempt + 1,
            }
            if len(acknowledgements) >= 2:
                self._event({"event": "store", **self.last_store_diagnostics, "accepted": True})
                return True
            if attempt == 0:
                await asyncio.sleep(0.05)
        self._event({"event": "store", **self.last_store_diagnostics, "accepted": False})
        return False

    async def _store_local_or_remote(self, peer: Contact, key: str, record: NodeRecord) -> bool:
        if peer.node_id == self.identity.node_id:
            return self.store.put(key, record)
        response = await self.rpc(peer, "STORE_REQUEST", {"key": key, "record": record.to_dict()})
        return bool(response.get("stored"))

    async def get_record(self, key: str) -> NodeRecord | None:
        local = self.store.get(key)
        if local:
            return local
        lookup = await self.lookup_node(key)
        candidates = list(lookup.contacts)
        queried: set[str] = set()
        while candidates:
            pending = [peer for peer in candidates if peer.node_id not in queried][:ALPHA]
            if not pending:
                break
            queried.update(peer.node_id for peer in pending)
            responses = await asyncio.gather(*(
                self.rpc(peer, "FIND_VALUE_REQUEST", {"key": key}) for peer in pending
            ), return_exceptions=True)
            next_contacts = {}
            for response in responses:
                if isinstance(response, Exception):
                    continue
                if response.get("record"):
                    record = NodeRecord.from_dict(response["record"])
                    if record.validate():
                        self.store.put(key, record)
                        return record
                for raw_contact in response.get("contacts", []):
                    contact = Contact.from_dict(raw_contact)
                    if contact.node_id not in queried:
                        next_contacts[contact.node_id] = contact
            candidates = sorted(next_contacts.values(), key=lambda peer: xor_distance(peer.node_id, key))
        return None

    async def publish_address_record(self) -> bool:
        self.record_sequence += 1
        record = NodeRecord.create(
            self.identity, (f"{self.contact.host}:{self.contact.port}",), self.record_sequence,
            self.config.record_ttl_seconds, self.box.public_bytes,
        )
        stored = await self.put_record(node_record_key(self.identity.node_id), record)
        self._last_republish = time.monotonic()
        return stored

    def start_maintenance(self) -> None:
        self._maintenance_enabled = True
        if self._maintenance_task is None:
            self._maintenance_task = asyncio.create_task(self._maintenance_loop())

    async def _maintenance_loop(self) -> None:
        interval = min(self.config.refresh_interval_seconds, self.config.republish_interval_seconds)
        try:
            while True:
                await asyncio.sleep(interval)
                if self.routing.all_contacts():
                    try:
                        await self.lookup_node(secrets.token_hex(32))
                    except Exception as exc:
                        self._event({"event": "refresh_error", "error": str(exc)[:128]})
                if time.monotonic() - self._last_republish >= self.config.republish_interval_seconds:
                    try:
                        await self.publish_address_record()
                    except Exception as exc:
                        self._event({"event": "republish_error", "error": str(exc)[:128]})
        except asyncio.CancelledError:
            raise

    async def _forward_tunnel_data(self, payload: dict, peer_id: str) -> tuple[str, dict]:
        tunnel_id = str(payload["tunnel_id"])
        state = self.tunnels.get(tunnel_id)
        if not state or state["state"] != "ACTIVE":
            raise ProtocolError("tunnel is not active")
        if state["expires_at"] <= time.time():
            state["state"] = "DEAD"
            raise ProtocolError("tunnel TTL expired")
        route = state["route"]
        position = int(payload["position"])
        if position != state["position"] or position < 0 or position >= len(route):
            raise ProtocolError("invalid tunnel data position")
        if route[position]["node_id"] != self.identity.node_id:
            raise ProtocolError("tunnel route does not include this relay")
        expected_sender = state["initiator_id"] if position == 0 else route[position - 1]["node_id"]
        if peer_id != expected_sender:
            raise ProtocolError("unexpected tunnel hop sender")
        if position + 1 < len(route):
            next_contact = Contact.from_dict(route[position + 1])
            next_payload = {**payload, "position": position + 1}
            return "TUNNEL_ACK", await self.rpc(next_contact, "TUNNEL_DATA", next_payload)
        destination = Contact.from_dict(payload["destination"])
        response = await self.rpc(destination, "APP_MESSAGE", {
            "destination_id": state["destination_id"], "tunnel_id": tunnel_id,
            "envelope": payload["envelope"],
        })
        return "TUNNEL_ACK", response

    async def build_tunnel(self, destination_id: str, relay_count: int | None = None,
                           excluded_ids: set[str] | None = None) -> dict:
        relay_count = relay_count or self.config.required_relays
        if relay_count > self.config.max_tunnel_hops:
            raise ProtocolError("requested relay count exceeds max_tunnel_hops")
        started = time.perf_counter()
        excluded = excluded_ids or set()
        lookup = await self.lookup_node(destination_id)
        destination = next((peer for peer in lookup.contacts if peer.node_id == destination_id), None)
        if destination is None:
            record = await self.get_record(node_record_key(destination_id))
            if not record or not record.validate():
                raise ProtocolError("destination not found in DHT")
            host, port = record.addresses[0].rsplit(":", 1)
            destination = Contact(destination_id, host, int(port))
        candidates = {peer.node_id: peer for peer in lookup.contacts}
        candidates.update({peer.node_id: peer for peer in self.routing.all_contacts()})
        candidates.pop(self.identity.node_id, None)
        candidates.pop(destination_id, None)
        for excluded_id in excluded:
            candidates.pop(excluded_id, None)
        live = []
        for candidate in sorted(candidates.values(), key=lambda peer: xor_distance(peer.node_id, destination_id)):
            if await self._ping(candidate):
                live.append(candidate)
            if len(live) == relay_count:
                break
        if len(live) < relay_count:
            raise ProtocolError(f"need {relay_count} live relays; found {len(live)}")
        if len({peer.node_id for peer in live}) != len(live) or any(
            peer.node_id in {self.identity.node_id, destination_id} for peer in live
        ):
            raise ProtocolError("tunnel contains a repeated or endpoint node")
        tunnel_id = uuid.uuid4().hex
        route = [peer.to_dict() for peer in live]
        for position, relay in enumerate(live):
            response = await self.rpc(relay, "TUNNEL_BUILD", {
                "tunnel_id": tunnel_id, "initiator_id": self.identity.node_id,
                "destination_id": destination_id, "route": route, "position": position,
            })
            if response.get("node_id") != relay.node_id:
                raise ProtocolError("relay did not confirm tunnel build")
        build_ms = (time.perf_counter() - started) * 1000
        tunnel = {"tunnel_id": tunnel_id, "destination": destination, "route": live,
                  "state": "ACTIVE", "built_at": time.time(), "build_ms": build_ms}
        self.tunnels[tunnel_id] = tunnel
        self.metrics["tunnel_build_ms"].append(build_ms)
        self._event({"event": "tunnel_built", "tunnel_id": tunnel_id,
                     "destination_id": destination_id, "relay_ids": [peer.node_id for peer in live],
                     "build_ms": build_ms})
        return tunnel

    async def send_via_tunnel(self, tunnel: dict, text: str) -> dict:
        started = time.perf_counter()
        destination = tunnel["destination"]
        record = await self.get_record(node_record_key(destination.node_id))
        if not record or not record.encryption_public_key:
            raise ProtocolError("destination encryption key unavailable")
        envelope = self.box.seal(
            bytes.fromhex(record.encryption_public_key), self.identity, destination.node_id,
            text.encode("utf-8"),
        )
        try:
            first = tunnel["route"][0]
            response = await self.rpc(first, "TUNNEL_DATA", {
                "tunnel_id": tunnel["tunnel_id"], "position": 0,
                "destination": destination.to_dict(), "envelope": envelope,
            })
            if not response.get("delivered"):
                raise ProtocolError("application acknowledgement missing")
            elapsed = (time.perf_counter() - started) * 1000
            self.metrics["message_e2e_ms"].append(elapsed)
            result = {"delivered": True, "message_id": envelope["message_id"],
                      "tunnel_id": tunnel["tunnel_id"], "relay_ids": [peer.node_id for peer in tunnel["route"]],
                      "e2e_ms": elapsed}
            self.message_history.append(result)
            self._event({"event": "message_sent", **result})
            return result
        except Exception:
            tunnel["state"] = "DEGRADED"
            raise

    async def send_with_recovery(self, destination_id: str, text: str,
                                 failed_relay_ids: set[str] | None = None) -> dict:
        excluded: set[str] = set(failed_relay_ids or set())
        started = time.perf_counter()
        last_error: Exception | None = None
        for attempt in range(2):
            tunnel = await self.build_tunnel(destination_id, excluded_ids=excluded)
            try:
                result = await self.send_via_tunnel(tunnel, text)
                if attempt:
                    recovery_ms = (time.perf_counter() - started) * 1000
                    self.metrics["recovery_ms"].append(recovery_ms)
                    result["recovery_ms"] = recovery_ms
                return result
            except Exception as exc:
                last_error = exc
                failed_relays = []
                for peer in tunnel["route"]:
                    if not await self._ping(peer):
                        failed_relays.append(peer.node_id)
                excluded.update(failed_relays or [peer.node_id for peer in tunnel["route"]])
        raise ProtocolError(f"delivery failed after tunnel rebuild: {last_error}") from last_error


class OverlayNetwork:
    def __init__(self, state_dir: str | Path, count: int = 12, base_port: int = 19000,
                 bootstrap: str = "star", bucket_size: int = K_BUCKET_SIZE,
                 config: OverlayConfig | None = None):
        self.state_dir = Path(state_dir)
        self.count = count
        self.base_port = base_port
        self.bootstrap = bootstrap
        self.config = config or OverlayConfig(bucket_size=bucket_size)
        self.config.validate()
        self.pki = LabPKI(self.state_dir)
        self.nodes: list[OverlayNode] = []
        self.contacts: list[Contact] = []
        self.convergence_rounds: list[dict] = []
        self.cold_convergence_ms: float | None = None

    async def start(self) -> None:
        materials = self.pki.prepare(self.count)
        for index, (identity, box, cert_path, key_path) in enumerate(materials):
            contact = Contact(identity.node_id, "127.0.0.1", self.base_port + index)
            node_dir = self.state_dir / f"node-{index:02d}"
            node = OverlayNode(
                contact, identity, box, node_dir,
                self.pki.server_context(cert_path, key_path),
                self.pki.client_context(cert_path, key_path), self.config,
            )
            await node.start()
            self.nodes.append(node)
            self.contacts.append(contact)
        await asyncio.sleep(0.05)
        discovery_started = time.perf_counter()
        for index, node in enumerate(self.nodes):
            if self.bootstrap == "ring":
                peers = [self.contacts[(index - 1) % self.count]]
            elif self.bootstrap == "star":
                peers = [] if index == 0 else [self.contacts[0]]
            else:
                raise ValueError("bootstrap must be star or ring")
            await node.join(peers)
        targets = [node.identity.node_id for node in self.nodes]
        for round_index in range(6):
            contacts_before = sum(len(node.routing.all_contacts()) for node in self.nodes)
            successes = 0
            attempts = 0
            for index, node in enumerate(self.nodes):
                for offset in range(1, min(self.count, 5)):
                    target_id = targets[(index + offset + round_index) % self.count]
                    lookup = await node.lookup_node(target_id)
                    attempts += 1
                    successes += any(peer.node_id == target_id for peer in lookup.contacts)
            contacts_after = sum(len(node.routing.all_contacts()) for node in self.nodes)
            contact_change = abs(contacts_after - contacts_before) / max(contacts_before, 1)
            round_result = {
                "round": round_index + 1,
                "lookup_attempts": attempts,
                "lookup_success_rate": successes / attempts if attempts else 0,
                "contacts_before": contacts_before,
                "contacts_after": contacts_after,
                "contact_change_fraction": contact_change,
                "converged": successes / attempts >= 0.95 and contact_change <= 0.10,
            }
            self.convergence_rounds.append(round_result)
            if len(self.convergence_rounds) >= 2 and all(
                item["converged"] for item in self.convergence_rounds[-2:]
            ):
                self.cold_convergence_ms = (time.perf_counter() - discovery_started) * 1000
                break
        if self.cold_convergence_ms is None:
            self.cold_convergence_ms = (time.perf_counter() - discovery_started) * 1000
        for node in self.nodes:
            await node.publish_address_record()
        for node in self.nodes:
            node.start_maintenance()

    async def stop(self) -> None:
        await asyncio.gather(*(node.stop() for node in self.nodes), return_exceptions=True)

    def node(self, index: int) -> OverlayNode:
        return self.nodes[index]

    def summary(self) -> dict:
        tables = [len(node.routing.all_contacts()) for node in self.nodes]
        return {
            "node_count": self.count,
            "bootstrap": self.bootstrap,
            "bucket_size": self.config.bucket_size,
            "alpha": self.config.alpha,
            "replication_factor": self.config.replication_factor,
            "profile": self.config.to_dict(),
            "routing_contact_counts": tables,
            "convergence_rounds": self.convergence_rounds,
            "operationally_converged": len(self.convergence_rounds) >= 2 and all(
                item["converged"] for item in self.convergence_rounds[-2:]
            ),
            "cold_convergence_ms": self.cold_convergence_ms,
            "underlay": "shared localhost TCP stack; bootstrap graph is not a physical topology",
            "dht_degenerate_fraction": sum(count >= self.count - 1 for count in tables) / self.count,
        }
