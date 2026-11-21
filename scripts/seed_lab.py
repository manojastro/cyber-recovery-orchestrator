"""Seed the cyber recovery lab (thin wrapper over `python -m simulator seed`).

Usage: python scripts/seed_lab.py [--scenario standard|corrupted_latest]
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import simulator  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Seed the lab")
    parser.add_argument("--scenario", default="standard",
                        choices=["standard", "corrupted_latest"])
    args = parser.parse_args()
    return simulator.cmd_seed(args.scenario)


if __name__ == "__main__":
    raise SystemExit(main())
