"""Simulator + lab routes: seed, assets, dependency map, backup catalog."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import get_app_settings, get_db
from app.lab.integrity import evaluate_all_snapshots
from app.lab.state import seed_lab
from app.models import Asset, BackupSnapshot, Dependency
from app.schemas import AssetOut, DependencyOut, SeedRequest, SnapshotOut

router = APIRouter(prefix="/api/v1", tags=["simulator"])


@router.post("/simulator/seed")
def seed(request: SeedRequest, session: Session = Depends(get_db),
         settings=Depends(get_app_settings)) -> dict:
    """Reset and reseed the lab. Destructive: wipes lab + case-file state."""
    from app.lab.state import wipe_all

    wipe_all(session)
    summary = seed_lab(session, scenario=request.scenario)
    session.commit()
    return {"status": "seeded", **summary}


@router.get("/assets", response_model=list[AssetOut])
def list_assets(session: Session = Depends(get_db)) -> list[AssetOut]:
    assets = session.query(Asset).order_by(Asset.tier, Asset.name).all()
    return [AssetOut.model_validate(a) for a in assets]


@router.get("/dependencies", response_model=list[DependencyOut])
def list_dependencies(session: Session = Depends(get_db)) -> list[DependencyOut]:
    deps = session.query(Dependency).order_by(Dependency.from_asset).all()
    return [DependencyOut(from_asset=d.from_asset, to_asset=d.to_asset,
                          dep_type=d.dep_type) for d in deps]


@router.get("/backups", response_model=list[SnapshotOut])
def list_backups(session: Session = Depends(get_db)) -> list[SnapshotOut]:
    evaluate_all_snapshots(session)
    session.commit()
    snaps = session.query(BackupSnapshot).order_by(
        BackupSnapshot.taken_at.desc()).all()
    return [SnapshotOut.model_validate(s) for s in snaps]


@router.get("/backups/{label}")
def get_backup(label: str, session: Session = Depends(get_db)) -> dict:
    from app.lab.backups import get_snapshot
    snap = get_snapshot(session, label)
    if snap is None:
        raise HTTPException(status_code=404, detail=f"unknown snapshot: {label}")
    from app.lab.integrity import evaluate_snapshot
    evaluation = evaluate_snapshot(session, snap)
    session.commit()
    return evaluation


@router.get("/tools/list")
def list_tools_real(session: Session = Depends(get_db)) -> dict:
    from app.tools.base import build_default_registry
    registry = build_default_registry()
    return {"tools": registry.list_all()}
