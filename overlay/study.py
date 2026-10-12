from __future__ import annotations

import asyncio
import csv
import json
import math
import platform
import statistics
import sys
import time
from pathlib import Path

from . import __version__
from .config import OverlayConfig
from .experiment import run_acceptance


def summarize(values: list[float]) -> dict:
    if not values:
        return {"n": 0, "min": None, "max": None, "median": None, "mean": None, "p95": None}
    ordered = sorted(values)
    p95 = ordered[math.ceil(0.95 * len(ordered)) - 1] if len(ordered) >= 20 else None
    return {
        "n": len(values), "min": min(values), "max": max(values),
        "median": statistics.median(values), "mean": statistics.fmean(values), "p95": p95,
    }


def validate_run(result: dict) -> dict[str, bool]:
    count = result["config"]["node_count"]
    bucket_size = result["config"]["bucket_size"]
    node_tables = result["node_tables"]
    non_full_tables = sum(node["total_contacts"] < count - 1 for node in node_tables)
    tables_bounded = all(max(node["bucket_sizes"], default=0) <= bucket_size for node in node_tables)
    dht_non_degenerate = len(node_tables) == count and non_full_tables >= math.ceil(0.8 * count) and tables_bounded
    lookups = result["lookups"]
    bootstrap_failure = result["bootstrap_failure"]
    candidate_failure = result["lookup_candidate_failure"]
    storage_failures = result["storage_failure_injections"]
    relay_failures = result["relay_failure_injections"]
    messages = result["messages"]
    required_relays = result["config"]["profile"]["required_relays"]
    return {
        "operational_convergence": result["config"]["operationally_converged"],
        "non_degenerate_bounded_dht": dht_non_degenerate,
        "30_absent_target_lookups_via_intermediary": (
            len(lookups) >= 30 and all(row["target_absent_before"] and row["used_intermediate"]
                                       and row["target_found"] for row in lookups[:30])
        ),
        "lookup_survives_candidate_failure": candidate_failure["failure_observed"] and candidate_failure["target_found"],
        "dht_survives_bootstrap_failure": bootstrap_failure["lookup_target_found"] and bootstrap_failure["find_value_succeeded"],
        "five_replica_failure_injections": (
            len(storage_failures) >= 5 and all(row.get("replica_count_before_failure", row.get("replica_count", 0)) == 3
                                               and row["recovered"]
                                               for row in storage_failures)
        ),
        "30_messages_through_required_relays": (
            len(messages) >= 30 and all(row["delivered"] and len(row["relay_ids"]) == required_relays
                                        and len(set(row["relay_ids"])) == required_relays for row in messages[:30])
        ),
        "five_relay_failure_recoveries": (
            len(relay_failures) >= 5 and all(row["first_attempt_failed"] and row["recovered"]
                                             and len(row["replacement_relay_ids"]) == required_relays
                                             and row["failed_relay_id"] not in row["replacement_relay_ids"]
                                             for row in relay_failures)
        ),
    }


async def run_study(output_dir: str | Path, count: int = 12, runs_per_scheme: int = 5,
                    base_port: int = 21000, seed: int = 20261012,
                    config: OverlayConfig | None = None) -> dict:
    if not 12 <= count <= 15:
        raise ValueError("the simplified study uses 12..15 logical nodes")
    if runs_per_scheme < 5:
        raise ValueError("the technical specification requires at least five independent runs per bootstrap scheme")
    active_config = config or OverlayConfig()
    active_config.validate()
    root = Path(output_dir)
    root.mkdir(parents=True, exist_ok=True)
    if any((root / scheme).exists() for scheme in ("star", "ring")):
        raise FileExistsError("study output already contains star/ or ring/; select a fresh --output directory")
    started = time.perf_counter()
    run_rows = []
    all_results = {"star": [], "ring": []}
    for run_index in range(runs_per_scheme):
        paired_seed = seed + run_index
        for scheme_index, scheme in enumerate(("star", "ring")):
            run_dir = root / scheme / f"run-{run_index + 1:02d}"
            port = base_port + (run_index * 2 + scheme_index) * (count + 16)
            result = await run_acceptance(
                run_dir, count, scheme, port, paired_seed, active_config,
            )
            checks = validate_run(result)
            all_results[scheme].append(result)
            run_rows.append({
                "bootstrap": scheme,
                "run": run_index + 1,
                "seed": paired_seed,
                "port_base": port,
                "duration_seconds": result["duration_seconds"],
                "cold_convergence_ms": result["cold_convergence_ms"],
                "lookup_success_rate": result["metrics"]["lookup_success_rate"],
                "lookup_median_ms": result["metrics"]["lookup_duration_ms"]["median"],
                "message_median_ms": result["metrics"]["message_e2e_ms"]["median"],
                "recovery_median_ms": result["metrics"]["recovery_ms"]["median"],
                "storage_recovery_rate": result["metrics"]["storage_recovery_rate"],
                "relay_recovery_rate": result["metrics"]["relay_recovery_rate"],
                "operationally_converged": result["config"]["operationally_converged"],
                "checks_passed": sum(checks.values()),
                "checks_total": len(checks),
                "accepted": all(checks.values()),
            })

    comparison = {}
    for scheme, results in all_results.items():
        lookup_values = [row["duration_ms"] for result in results for row in result["lookups"]]
        tunnel_values = [value for result in results
                         for value in result["metrics"]["tunnel_build_samples_ms"]]
        message_values = [row["e2e_ms"] for result in results for row in result["messages"]]
        recovery_values = [row["recovery_ms"] for result in results for row in result["relay_failure_injections"]]
        convergence_values = [result["cold_convergence_ms"] for result in results]
        table_sizes = [node["total_contacts"] for result in results for node in result["node_tables"]]
        checks = [validate_run(result) for result in results]
        comparison[scheme] = {
            "runs": len(results),
            "accepted_runs": sum(all(check.values()) for check in checks),
            "checks": {name: all(check[name] for check in checks) for name in checks[0]},
            "cold_convergence_ms": summarize(convergence_values),
            "lookup_duration_ms": summarize(lookup_values),
            "message_e2e_ms": summarize(message_values),
            "tunnel_build_ms": summarize(tunnel_values),
            "tunnel_recovery_ms": summarize(recovery_values),
            "routing_contacts_per_node": summarize(table_sizes),
            "lookup_success_rate_mean": statistics.fmean(result["metrics"]["lookup_success_rate"] for result in results),
            "storage_recovery_rate_mean": statistics.fmean(result["metrics"]["storage_recovery_rate"] for result in results),
            "relay_recovery_rate_mean": statistics.fmean(result["metrics"]["relay_recovery_rate"] for result in results),
            "sample_sizes": {
                "cold_convergence_runs": len(convergence_values),
                "lookups": len(lookup_values),
                "messages": len(message_values),
                "storage_failures": sum(len(result["storage_failure_injections"]) for result in results),
                "relay_failures": len(recovery_values),
            },
        }

    study = {
        "schema_version": 1,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "code_version": __version__,
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "config": active_config.to_dict(),
        "node_count": count,
        "runs_per_scheme": runs_per_scheme,
        "paired_seeds": [seed + index for index in range(runs_per_scheme)],
        "underlay": "shared localhost TCP; star/ring describe bootstrap relationships only",
        "duration_seconds": time.perf_counter() - started,
        "comparison": comparison,
        "runs": run_rows,
        "accepted": all(row["accepted"] for row in run_rows),
        "limitations": [
            "All measurements are from a single Windows host and are not representative of a WAN.",
            "Bootstrap links are not physical topologies; no IP reachability restrictions were applied.",
            "Only the simplified profile is covered; file transfer and the advanced AKE are out of scope.",
        ],
    }
    _write_study_artifacts(root, study)
    return study


def _write_study_artifacts(root: Path, study: dict) -> None:
    (root / "study-summary.json").write_text(json.dumps(study, indent=2), encoding="utf-8")
    rows = study["runs"]
    columns = list(rows[0]) if rows else []
    with (root / "study-runs.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)
    checks_rows = []
    for scheme in ("star", "ring"):
        for check, passed in study["comparison"][scheme]["checks"].items():
            checks_rows.append({"bootstrap": scheme, "check": check, "passed_all_runs": passed})
    with (root / "acceptance-checks.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=["bootstrap", "check", "passed_all_runs"])
        writer.writeheader()
        writer.writerows(checks_rows)
    _write_comparison_chart(root / "bootstrap-comparison.svg", study["comparison"])


def _write_comparison_chart(path: Path, comparison: dict) -> None:
    width, height = 900, 430
    left, top, plot_width, plot_height = 90, 80, 760, 280
    labels = ("cold convergence ms", "lookup median ms", "message median ms", "recovery median ms")
    keys = ("cold_convergence_ms", "lookup_duration_ms", "message_e2e_ms", "tunnel_recovery_ms")
    values = [[comparison[scheme][key]["median"] for key in keys] for scheme in ("star", "ring")]
    maximum = max((value or 0) for group in values for value in group) or 1
    group_width = plot_width / len(labels)
    bar_width = 34
    bars = []
    for group_index, label in enumerate(labels):
        center = left + group_index * group_width + group_width / 2
        for scheme_index, color in enumerate(("#167d8d", "#d26a42")):
            value = values[scheme_index][group_index] or 0
            bar_height = value / maximum * plot_height
            x = center + (scheme_index - 0.5) * (bar_width + 5) - bar_width / 2
            y = top + plot_height - bar_height
            bars.append(f'<rect x="{x:.1f}" y="{y:.1f}" width="{bar_width}" height="{bar_height:.1f}" fill="{color}"/>')
        bars.append(f'<text x="{center:.1f}" y="{top + plot_height + 24}" text-anchor="middle" font-family="sans-serif" font-size="12">{label}</text>')
    svg = (f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">'
           f'<rect width="100%" height="100%" fill="#fbfaf7"/><text x="{left}" y="36" font-family="sans-serif" font-size="20" fill="#172a32">Bootstrap comparison, median across five runs</text>'
           f'<path d="M {left} {top} V {top + plot_height} H {left + plot_width}" fill="none" stroke="#66777d"/>'
           + "".join(bars)
           + '<rect x="600" y="55" width="14" height="14" fill="#167d8d"/><text x="620" y="67" font-family="sans-serif" font-size="13">star</text>'
           + '<rect x="680" y="55" width="14" height="14" fill="#d26a42"/><text x="700" y="67" font-family="sans-serif" font-size="13">ring</text></svg>')
    path.write_text(svg, encoding="utf-8")