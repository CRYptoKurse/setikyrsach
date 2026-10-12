from __future__ import annotations

import asyncio
import csv
import hashlib
import json
import platform
import random
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .core import NodeRecord, ProtocolError, node_record_key
from .config import OverlayConfig
from .network import OverlayNetwork


def distribution(values: list[float]) -> dict:
    if not values:
        return {"n": 0, "min": None, "max": None, "median": None, "mean": None}
    return {"n": len(values), "min": min(values), "max": max(values),
            "median": statistics.median(values), "mean": statistics.fmean(values)}


async def run_acceptance(output_dir: str | Path, count: int = 12, bootstrap: str = "star",
                         base_port: int = 19000, seed: int = 20261012,
                         config: OverlayConfig | None = None) -> dict:
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    started_wall = datetime.now(timezone.utc)
    started = time.perf_counter()
    random.seed(seed)
    network = OverlayNetwork(output_path / "state", count=count, base_port=base_port,
                             bootstrap=bootstrap, config=config)
    results: dict = {"schema_version": 1, "started_at": started_wall.isoformat(), "seed": seed,
                     "code_version": __version__, "python_version": platform.python_version(),
                     "platform": platform.platform()}
    try:
        await network.start()
        results["config"] = network.summary()
        results["cold_convergence_ms"] = network.cold_convergence_ms
        results["startup_total_ms"] = (time.perf_counter() - started) * 1000

        bootstrap_node = network.node(0)
        reader = network.node(1)
        target_node = network.node(count - 1)
        bootstrap_key = node_record_key(target_node.identity.node_id)
        await bootstrap_node.stop()
        bootstrap_lookup = await reader.lookup_node(target_node.identity.node_id)
        bootstrap_record = await reader.get_record(bootstrap_key)
        await bootstrap_node.start()
        results["bootstrap_failure"] = {
            "stopped_node_id": bootstrap_node.identity.node_id,
            "lookup_target_found": any(peer.node_id == target_node.identity.node_id for peer in bootstrap_lookup.contacts),
            "find_value_succeeded": bootstrap_record is not None,
            "lookup_rpc_count": bootstrap_lookup.rpc_count,
        }

        lookup_initiator = network.node(1)
        lookup_targets = [node.identity.node_id for node in network.nodes
                  if node.identity.node_id != lookup_initiator.identity.node_id
                          if node.identity.node_id not in {peer.node_id for peer in lookup_initiator.routing.all_contacts()}]
        lookup_target = lookup_targets[0] if lookup_targets else network.node(count - 1).identity.node_id
        failed_candidate = lookup_initiator.routing.closest(lookup_target, 1)[0]
        candidate_node = next(node for node in network.nodes if node.identity.node_id == failed_candidate.node_id)
        await candidate_node.stop()
        interrupted_lookup = await lookup_initiator.lookup_node(lookup_target)
        await candidate_node.start()
        results["lookup_candidate_failure"] = {
            "stopped_candidate_id": failed_candidate.node_id,
            "target_id": lookup_target,
            "candidate_absent_from_initiator_before": True,
            "failure_observed": bool(interrupted_lookup.errors),
            "target_found": any(peer.node_id == lookup_target for peer in interrupted_lookup.contacts),
            "rpc_count": interrupted_lookup.rpc_count,
            "errors": interrupted_lookup.errors,
        }

        lookup_observations = []
        node_ids = [node.identity.node_id for node in network.nodes]
        pair_order = [(initiator, target) for initiator in range(count) for target in range(count)
                      if initiator != target]
        random.Random(seed).shuffle(pair_order)
        for initiator_index, target_index in pair_order:
            if len(lookup_observations) >= 30:
                break
            initiator = network.node(initiator_index)
            target_id = node_ids[target_index]
            if target_id in {peer.node_id for peer in initiator.routing.all_contacts()}:
                continue
            lookup = await initiator.lookup_node(target_id)
            lookup_observations.append({
                "lookup_id": lookup.lookup_id,
                "initiator_id": initiator.identity.node_id,
                "target_id": target_id,
                "target_absent_before": True,
                "used_intermediate": any(peer_id != target_id for batch in lookup.queried for peer_id in batch),
                "target_found": any(peer.node_id == target_id for peer in lookup.contacts),
                "rpc_count": lookup.rpc_count,
                "iterations": lookup.iterations,
                "duration_ms": lookup.duration_ms,
                "errors": len(lookup.errors),
            })
        results["lookups"] = lookup_observations

        store_failures = []
        publisher = network.node(0)
        for injection in range(min(5, count - 3)):
            key = hashlib.sha256(f"experiment:store:{seed}:{injection}".encode()).hexdigest()
            record = NodeRecord.create(
                publisher.identity, (f"{publisher.contact.host}:{publisher.contact.port}",),
                publisher.record_sequence + injection + 1, 180, publisher.box.public_bytes,
            )
            stored = False
            holders = []
            store_attempts = 0
            while store_attempts < 3:
                stored = await publisher.put_record(key, record)
                holders = [node for node in network.nodes if node.store.get(key) is not None]
                store_attempts += 1
                if stored and len(holders) == 3:
                    break
            if not stored or len(holders) < 3:
                store_failures.append({"injection": injection, "stored": stored, "replica_count": len(holders),
                                       "store_attempts": store_attempts, "diagnostics": publisher.last_store_diagnostics,
                                       "recovered": False})
                continue
            failed_holder = holders[0]
            readers = [node for node in network.nodes if node not in holders]
            reader = readers[0] if readers else publisher
            await failed_holder.stop()
            try:
                recovered_record = await reader.get_record(key)
            finally:
                await failed_holder.start()
            store_failures.append({"injection": injection, "failed_holder_id": failed_holder.identity.node_id,
                                   "replica_count_before_failure": len(holders), "store_attempts": store_attempts,
                                   "recovered": bool(recovered_record)})
        results["storage_failure_injections"] = store_failures

        sender = network.node(0)
        receiver = network.node(count - 1)
        baseline_tunnel = await sender.build_tunnel(receiver.identity.node_id)
        delivered_messages = []
        for message_index in range(30):
            delivered_messages.append(await sender.send_via_tunnel(baseline_tunnel, f"SETI acceptance message {message_index}"))
        results["messages"] = delivered_messages

        relay_failures = []
        for injection in range(min(5, count - 3)):
            tunnel = await sender.build_tunnel(receiver.identity.node_id)
            failed_relay = tunnel["route"][0]
            failed_node = next(node for node in network.nodes if node.identity.node_id == failed_relay.node_id)
            await failed_node.stop()
            started_recovery = time.perf_counter()
            first_error = None
            try:
                await sender.send_via_tunnel(tunnel, f"failure probe {injection}")
                first_attempt_failed = False
            except Exception as exc:
                first_attempt_failed = True
                first_error = str(exc)
            try:
                recovered = await sender.send_with_recovery(
                    receiver.identity.node_id, f"recovered message {injection}",
                    failed_relay_ids={failed_relay.node_id},
                )
            except Exception as exc:
                recovered = {"delivered": False, "error": str(exc)}
            recovery_ms = (time.perf_counter() - started_recovery) * 1000
            relay_failures.append({"injection": injection, "failed_relay_id": failed_relay.node_id,
                                   "first_attempt_failed": first_attempt_failed,
                                   "first_attempt_error": first_error,
                                   "recovered": bool(recovered.get("delivered")), "recovery_ms": recovery_ms,
                                   "recovery_error": recovered.get("error"),
                                   "replacement_relay_ids": recovered.get("relay_ids", [])})
            await failed_node.start()
        results["relay_failure_injections"] = relay_failures

        lookup_times = [item["duration_ms"] for item in lookup_observations]
        message_times = [item["e2e_ms"] for item in delivered_messages]
        results["metrics"] = {
            "lookup_duration_ms": distribution(lookup_times),
            "lookup_success_rate": (sum(item["target_found"] for item in lookup_observations) / len(lookup_observations)
                                    if lookup_observations else 0),
            "lookup_absent_target_count": sum(item["target_absent_before"] for item in lookup_observations),
            "lookup_intermediate_count": sum(item["used_intermediate"] for item in lookup_observations),
            "lookup_rpc_count": distribution([item["rpc_count"] for item in lookup_observations]),
            "lookup_iterations": distribution([item["iterations"] for item in lookup_observations]),
            "tunnel_build_ms": distribution(sender.metrics["tunnel_build_ms"]),
            "message_e2e_ms": distribution(message_times),
            "recovery_ms": distribution([item["recovery_ms"] for item in relay_failures]),
            "storage_recovery_rate": (sum(item["recovered"] for item in store_failures) / len(store_failures)
                                      if store_failures else 0),
            "relay_recovery_rate": (sum(item["recovered"] for item in relay_failures) / len(relay_failures)
                                    if relay_failures else 0),
            "tunnel_build_samples_ms": list(sender.metrics["tunnel_build_ms"]),
        }
        results["node_tables"] = [{"node_id": node.identity.node_id,
                                   "total_contacts": len(node.routing.all_contacts()),
                                   "bucket_sizes": node.routing.bucket_sizes()} for node in network.nodes]
        results["duration_seconds"] = time.perf_counter() - started
        results["limitations"] = [
            "This is a localhost prototype; bootstrap schemes do not represent physical IP topologies.",
            "The generated lab CA is an isolated experiment trust anchor, not a discovery service.",
            "File transfer, network namespaces/netem, browser UI, and packet capture are not part of the simplified profile.",
        ]
        write_artifacts(output_path, results)
        return results
    finally:
        await network.stop()


def write_artifacts(output_path: Path, results: dict) -> None:
    (output_path / "results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    with (output_path / "lookups.csv").open("w", newline="", encoding="utf-8") as stream:
        rows = results.get("lookups", [])
        columns = ["lookup_id", "initiator_id", "target_id", "target_absent_before", "used_intermediate",
                   "target_found", "rpc_count", "iterations", "duration_ms", "errors"]
        writer = csv.DictWriter(stream, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)
    with (output_path / "messages.csv").open("w", newline="", encoding="utf-8") as stream:
        rows = results.get("messages", [])
        columns = ["message_id", "tunnel_id", "delivered", "e2e_ms"]
        writer = csv.DictWriter(stream, fieldnames=columns)
        writer.writeheader()
        writer.writerows({key: row.get(key) for key in columns} for row in rows)
    values = [node["total_contacts"] for node in results.get("node_tables", [])]
    _write_bar_chart(output_path / "routing-tables.svg", values, "Unique routing contacts per node")
    lookup_values = [row["duration_ms"] for row in results.get("lookups", [])]
    _write_bar_chart(output_path / "lookup-duration.svg", lookup_values, "DHT lookup duration (ms)")


def _write_bar_chart(path: Path, values: list[float], title: str) -> None:
    width, height = 900, 420
    margin_left, margin_top, plot_width, plot_height = 70, 70, 790, 280
    maximum = max(values, default=1) or 1
    gap = 4
    bar_width = max(2, (plot_width - gap * max(0, len(values) - 1)) / max(1, len(values)))
    bars = []
    for index, value in enumerate(values):
        x = margin_left + index * (bar_width + gap)
        bar_height = value / maximum * plot_height
        y = margin_top + plot_height - bar_height
        bars.append(f'<rect x="{x:.1f}" y="{y:.1f}" width="{bar_width:.1f}" height="{bar_height:.1f}" fill="#167d8d"/>')
    svg = (f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">'
           f'<rect width="100%" height="100%" fill="#fbfaf7"/><text x="{margin_left}" y="36" font-family="sans-serif" font-size="20" fill="#172a32">{title}</text>'
           f'<path d="M {margin_left} {margin_top} V {margin_top + plot_height} H {margin_left + plot_width}" fill="none" stroke="#66777d"/>'
           + "".join(bars) + "</svg>")
    path.write_text(svg, encoding="utf-8")
