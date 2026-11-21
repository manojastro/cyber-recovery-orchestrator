"""Simulate the ransomware incident at T0: inject + deterministic detection.

Usage:
    python scripts/simulate_ransomware_incident.py [--scenario standard|corrupted_latest]
                                                   [--seed-first]
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import simulator  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Simulate a ransomware incident")
    parser.add_argument("--scenario", default="standard",
                        choices=["standard", "corrupted_latest"])
    parser.add_argument("--seed-first", action="store_true",
                        help="reset + reseed the lab before injecting")
    args = parser.parse_args()
    if args.seed_first:
        rc = simulator.cmd_seed(args.scenario)
        if rc != 0:
            return rc
    return simulator.cmd_incident(args.scenario)


if __name__ == "__main__":
    raise SystemExit(main())
