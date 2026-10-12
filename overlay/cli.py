from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

from .config import OverlayConfig
from .experiment import run_acceptance
from .study import run_study


def main() -> None:
    parser = argparse.ArgumentParser(prog="seti-overlay")
    subparsers = parser.add_subparsers(dest="command", required=True)
    experiment = subparsers.add_parser("experiment", help="run the 12-node acceptance and metrics scenario")
    experiment.add_argument("--output", default="results/run-001")
    experiment.add_argument("--nodes", type=int, default=12)
    experiment.add_argument("--bootstrap", choices=("star", "ring"), default="star")
    experiment.add_argument("--port", type=int, default=19000)
    experiment.add_argument("--seed", type=int, default=20261012)
    experiment.add_argument("--config", help="JSON file overriding the simplified profile")
    study = subparsers.add_parser("study", help="run five paired experiments for star and ring bootstrap")
    study.add_argument("--output", default="results/study-001")
    study.add_argument("--nodes", type=int, default=12)
    study.add_argument("--runs", type=int, default=5)
    study.add_argument("--port", type=int, default=21000)
    study.add_argument("--seed", type=int, default=20261012)
    study.add_argument("--config", help="JSON file overriding the simplified profile")
    args = parser.parse_args()
    config = OverlayConfig.load(args.config) if args.config else OverlayConfig()
    if args.command == "experiment":
        if args.nodes < 6 or args.nodes > 15:
            parser.error("simplified profile supports 6..15 nodes; recommended N=12")
        result = asyncio.run(run_acceptance(args.output, args.nodes, args.bootstrap, args.port, args.seed, config))
        report = {"output": str(Path(args.output).resolve()),
                  "lookup_success_rate": result["metrics"]["lookup_success_rate"],
                  "storage_recovery_rate": result["metrics"]["storage_recovery_rate"],
                  "relay_recovery_rate": result["metrics"]["relay_recovery_rate"]}
    else:
        try:
            result = asyncio.run(run_study(args.output, args.nodes, args.runs, args.port, args.seed, config))
        except (ValueError, FileExistsError) as exc:
            parser.error(str(exc))
        report = {"output": str(Path(args.output).resolve()), "accepted": result["accepted"],
                  "runs_per_scheme": result["runs_per_scheme"],
                  "star_accepted_runs": result["comparison"]["star"]["accepted_runs"],
                  "ring_accepted_runs": result["comparison"]["ring"]["accepted_runs"]}
        if not result["accepted"]:
            print(json.dumps(report, indent=2))
            raise SystemExit(1)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()