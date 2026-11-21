"""Lab simulator CLI implementation.

Usage (from the project root):
    python -m simulator seed [--scenario standard|corrupted_latest]
    python -m simulator incident [--scenario standard|corrupted_latest]
    python -m simulator status
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Make `app` package importable from backend/
BACKEND_DIR = Path(__file__).resolve().parents[1] / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.config import get_settings  # noqa: E402
from app.db import init_schema, make_engine, make_session_factory  # noqa: E402
from app.lab.detector import detect_incident  # noqa: E402
from app.lab.incident import inject_ransomware  # noqa: E402
from app.lab.integrity import evaluate_all_snapshots  # noqa: E402
from app.lab.state import seed_lab, wipe_all  # noqa: E402


def _session():
    settings = get_settings()
    engine = make_engine(settings.database_url)
    init_schema(engine)
    return settings, make_session_factory(engine)()


def cmd_seed(scenario: str) -> int:
    settings, session = _session()
    try:
        wipe_all(session)
        summary = seed_lab(session, scenario=scenario)
        print("lab seeded (destructive reset):")
        for key, value in summary.items():
            print(f"  {key}: {value}")
        return 0
    finally:
        session.close()


def cmd_incident(scenario: str) -> int:
    settings, session = _session()
    try:
        incident = inject_ransomware(session, scenario=scenario)
        incident = detect_incident(session, incident)
        stats = incident.detection_stats or {}
        print(f"incident: {incident.public_id}")
        print(f"  detected : {incident.status == 'open'}")
        print(f"  rules    : {', '.join(stats.get('fired_rules', []))}")
        print(f"  encrypted records      : {stats.get('encrypted_records')}")
        print(f"  deleted objects        : {stats.get('deleted_objects')}")
        print(f"  corrupted configs      : {stats.get('corrupted_configs')}")
        print(f"  compromised credentials: {stats.get('compromised_credentials')}")
        evaluations = evaluate_all_snapshots(session)
        session.commit()
        failed = [e["label"] for e in evaluations if e["status"] == "failed"]
        print(f"  unsafe snapshots (post-scan): {', '.join(failed) or 'none'}")
        if incident.status != "open":
            print("ERROR: detector did not raise an incident", file=sys.stderr)
            return 2
        print("next: run scripts/run_recovery_demo.py or POST "
              "/api/v1/investigations/{id}/run")
        return 0
    finally:
        session.close()


def cmd_status() -> int:
    settings, session = _session()
    try:
        from app.models import Asset, BackupSnapshot, Investigation
        assets = session.query(Asset).count()
        snaps = session.query(BackupSnapshot).order_by(BackupSnapshot.taken_at).all()
        investigations = session.query(Investigation).all()
        print(f"assets={assets} snapshots={len(snaps)} "
              f"investigations={len(investigations)} llm_mode={settings.llm_mode}")
        for snap in snaps:
            print(f"  {snap.label} taken_at={snap.taken_at.isoformat()} "
                  f"integrity={snap.integrity_status} "
                  f"indicators={snap.malicious_indicator_count}")
        for inv in investigations:
            print(f"  investigation {inv.public_id} state={inv.current_state}")
        return 0
    finally:
        session.close()


def main() -> int:
    parser = argparse.ArgumentParser(prog="simulator",
                                     description="Cyber recovery lab simulator")
    sub = parser.add_subparsers(dest="command", required=True)
    seed_p = sub.add_parser("seed", help="reset + seed the lab and backup history")
    seed_p.add_argument("--scenario", default="standard",
                        choices=["standard", "corrupted_latest"])
    inc_p = sub.add_parser("incident", help="inject ransomware + detect")
    inc_p.add_argument("--scenario", default="standard",
                       choices=["standard", "corrupted_latest"])
    sub.add_parser("status", help="print lab state summary")
    args = parser.parse_args()
    if args.command == "seed":
        return cmd_seed(args.scenario)
    if args.command == "incident":
        return cmd_incident(args.scenario)
    if args.command == "status":
        return cmd_status()
    return 1
