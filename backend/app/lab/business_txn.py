"""End-to-end business transaction probe: login -> browse -> cart -> checkout
-> order created. Implemented against simulated service state. Recovery is NOT
successful just because restores completed - this probe is the arbiter."""
from __future__ import annotations

from typing import Dict, List

from sqlalchemy.orm import Session

from app.models import Asset, ConfigEntry, Credential, DbRecord
from app.util import new_id, utcnow


def run_business_transaction(session: Session) -> dict:
    """Execute the transaction against live lab state.

    Returns {"passed": bool, "steps": [...], "failed_step": name|None}.
    On success a submitted order row is persisted as proof.
    """
    steps: List[dict] = []

    def step(name: str, passed: bool, detail: str) -> bool:
        steps.append({"name": name, "passed": passed, "detail": detail})
        return passed

    # 1. authenticate (identity + credentials + config)
    identity = session.query(Asset).filter(Asset.name == "identity-service").first()
    if not step("authenticate", bool(identity and identity.state == "running"),
                f"identity-service state={identity.state if identity else 'missing'}"):
        return _finish(steps)
    compromised = session.query(Credential).filter(Credential.status == "compromised").count()
    portal = session.query(Credential).filter(
        Credential.principal == "svc-customer-portal").first()
    if not step("authenticate_credentials",
                compromised == 0 and portal is not None and portal.status == "active"
                and portal.generation >= 1,
                f"compromised_credentials={compromised} portal_status="
                f"{portal.status if portal else 'missing'} gen={portal.generation if portal else '-'}"):
        return _finish(steps)

    config_ok = session.query(ConfigEntry).filter(ConfigEntry.integrity_ok.is_(False)).count() == 0
    frontend = session.query(Asset).filter(Asset.name == "web-frontend").first()
    if not step("load_storefront_config", config_ok and frontend.state == "running",
                f"config_integrity_ok={config_ok} web-frontend={frontend.state}"):
        return _finish(steps)

    # 2. browse product catalog
    product = session.query(DbRecord).filter(
        DbRecord.table_name == "products", DbRecord.encrypted.is_(False),
        DbRecord.corrupted.is_(False), DbRecord.deleted.is_(False)
    ).order_by(DbRecord.id).first()
    order_svc = session.query(Asset).filter(Asset.name == "order-service").first()
    if not step("browse_product", product is not None and order_svc.state == "running",
                f"catalog_readable={product is not None} order-service={order_svc.state}"):
        return _finish(steps)

    # 3. add to cart (write path through order-service into core-postgres)
    db_asset = session.query(Asset).filter(Asset.name == "core-postgres").first()
    cart_ref = new_id("cart-")
    cart_row = DbRecord(table_name="orders", record_key=cart_ref,
                        payload='{"status":"cart"}', created_at=utcnow())
    session.add(cart_row)
    session.flush()
    if not step("add_to_cart", db_asset.state in ("running",) and db_asset.health > 50,
                f"cart={cart_ref} core-postgres health={db_asset.health}"):
        return _finish(steps)

    # 4. checkout via payment-service (+ customer-service lookup)
    payment = session.query(Asset).filter(Asset.name == "payment-service").first()
    customer = session.query(Asset).filter(Asset.name == "customer-service").first()
    if not step("checkout_payment",
                payment.state == "running" and customer.state == "running",
                f"payment-service={payment.state} customer-service={customer.state}"):
        return _finish(steps)
    cart_row.payload = '{"status":"submitted"}'
    session.flush()

    # 5. order created and readable back
    persisted = session.query(DbRecord).filter(
        DbRecord.record_key == cart_ref, DbRecord.deleted.is_(False)).first()
    ok = bool(persisted and '"submitted"' in (persisted.payload or "")
              and not persisted.encrypted and not persisted.corrupted)
    if not step("order_created", ok,
                f"order={cart_ref} encrypted={getattr(persisted, 'encrypted', None)}"):
        return _finish(steps)

    session.commit()
    return {"passed": True, "steps": steps, "failed_step": None,
            "order_ref": cart_ref}


def _finish(steps: List[dict]) -> dict:
    failed = next((s["name"] for s in steps if not s["passed"]), None)
    return {"passed": False, "steps": steps, "failed_step": failed}


def project_business_transaction(chosen_snapshot_ok: bool,
                                 planned_assets_recovered: List[str],
                                 integrity_flags_clean: bool) -> dict:
    """Dry-run projection used by pre-flight validation (no mutation).

    Predicts whether the business transaction would pass after executing the
    plan, purely from planned facts.
    """
    required = ["identity-service", "web-frontend", "order-service",
                "payment-service", "customer-service"]
    missing = [a for a in required if a not in planned_assets_recovered]
    problems = []
    if not chosen_snapshot_ok:
        problems.append("chosen recovery point did not verify clean")
    if missing:
        problems.append(f"plan does not recover required services: {missing}")
    if not integrity_flags_clean:
        problems.append("data-plane integrity flags would remain suspect")
    return {"predicted_pass": not problems, "problems": problems}
