"""Lab topology definitions: assets, typed dependencies, business tiers.

Dependency edge semantics: (from_asset, to_asset, type) means
`from_asset` depends on `to_asset`.
"""
from __future__ import annotations

from typing import Dict, List, Tuple

# name -> (asset_type, tier, criticality, owner)
ASSETS: Dict[str, Tuple[str, int, str, str]] = {
    "config-store": ("config", 0, "critical", "platform-team"),
    "core-postgres": ("database", 0, "critical", "data-team"),
    "identity-service": ("identity", 0, "critical", "security-team"),
    "object-storage": ("storage", 0, "critical", "platform-team"),
    "core-networking": ("network", 0, "critical", "network-team"),
    "web-frontend": ("service", 1, "critical", "ecommerce-team"),
    "order-service": ("service", 1, "critical", "ecommerce-team"),
    "customer-service": ("service", 1, "critical", "crm-team"),
    "payment-service": ("service", 1, "critical", "payments-team"),
    "reporting-service": ("service", 2, "medium", "analytics-team"),
}

DEPENDENCIES: List[Tuple[str, str, str]] = [
    ("web-frontend", "order-service", "SERVICE_CALLS_SERVICE"),
    ("web-frontend", "customer-service", "SERVICE_CALLS_SERVICE"),
    ("order-service", "payment-service", "SERVICE_CALLS_SERVICE"),
    ("payment-service", "customer-service", "SERVICE_CALLS_SERVICE"),
    ("order-service", "core-postgres", "SERVICE_DEPENDS_ON_DATABASE"),
    ("customer-service", "core-postgres", "SERVICE_DEPENDS_ON_DATABASE"),
    ("payment-service", "core-postgres", "SERVICE_DEPENDS_ON_DATABASE"),
    ("reporting-service", "core-postgres", "SERVICE_DEPENDS_ON_DATABASE"),
    ("identity-service", "core-postgres", "SERVICE_DEPENDS_ON_DATABASE"),
    ("web-frontend", "identity-service", "SERVICE_REQUIRES_IDENTITY"),
    ("order-service", "identity-service", "SERVICE_REQUIRES_IDENTITY"),
    ("customer-service", "identity-service", "SERVICE_REQUIRES_IDENTITY"),
    ("payment-service", "identity-service", "SERVICE_REQUIRES_IDENTITY"),
    ("order-service", "object-storage", "SERVICE_REQUIRES_STORAGE"),
    ("reporting-service", "object-storage", "SERVICE_REQUIRES_STORAGE"),
    ("core-postgres", "config-store", "SERVICE_REQUIRES_CONFIG"),
    ("web-frontend", "config-store", "SERVICE_REQUIRES_CONFIG"),
]

TIER_NAMES = {0: "Tier 0 - Foundation (identity/db/storage/network/config)",
              1: "Tier 1 - Core business services",
              2: "Tier 2 - Supporting / analytics"}

DB_TABLE_SIZES = {"products": 40, "customers": 30, "orders": 60, "order_items": 80}

STORAGE_BUCKETS = {"app-data": 36, "audit-logs": 12}

CONFIG_KEYS = [
    "feature.checkout.v2", "payments.provider.endpoint", "orders.max-line-items",
    "identity.token.ttl", "storage.bucket.app-data.name", "search.index.enabled",
    "notifications.smtp.host", "reporting.cron.daily", "db.pool.max-size",
    "cache.ttl.products", "session.cookie.domain", "api.rate-limit.per-minute",
    "tax.engine.enabled", "currency.conversion.source", "logging.level.services",
    "backup.schedule.hourly", "cdn.base-url", "maintenance.window.utc",
]

CREDENTIAL_PRINCIPALS = [
    ("svc-order", "service"), ("svc-payment", "service"), ("svc-reporting", "service"),
    ("svc-customer-portal", "user"), ("admin-ops", "admin"), ("ci-pipeline", "service"),
]

COMPROMISED_PRINCIPALS = ["admin-ops", "svc-payment", "ci-pipeline"]

SCENARIO_COMPROMISE_START_OFFSET_S = 5400   # incident window begins 90 min before T0 detect
SNAPSHOT_COUNT = 8
SNAPSHOT_INTERVAL_S = 3600


def snapshot_taken_at(now, index: int):
    """BKP-k timestamps: BKP-008 newest (now - 1h), BKP-001 oldest (now - 8h)."""
    from datetime import timedelta

    return now - timedelta(seconds=SNAPSHOT_INTERVAL_S * (SNAPSHOT_COUNT + 1 - index))


def compromise_start(now):
    from datetime import timedelta

    return now - timedelta(seconds=SCENARIO_COMPROMISE_START_OFFSET_S)
