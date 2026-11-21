/* Cyber Recovery Orchestrator SPA - vanilla ES modules, no external deps. */

const API = "";
const ACTIVE_STATES = new Set([
  "DETECTED", "INVESTIGATING", "DIAGNOSED", "PLANNED", "VALIDATING",
  "AWAITING_APPROVAL", "APPROVED", "EXECUTING", "VERIFYING",
]);

let meta = null;
let currentInvestigation = null;

// ---------------------------------------------------------------- utilities

async function getJSON(url) {
  const res = await fetch(`${API}${url}`);
  if (!res.ok) throw new Error(`${url} -> ${res.status}`);
  return res.json();
}

function fmtTime(iso) {
  if (!iso) return "-";
  const d = new Date(iso + (iso.endsWith("Z") ? "" : "Z"));
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function fmtSeconds(v, unit = "s") {
  if (v === null || v === undefined) return "-";
  if (unit === "s") return `${Number(v).toFixed(0)}s`;
  return String(v);
}

function el(id) { return document.getElementById(id); }

function showEmpty(sectionId, show) {
  const panel = el(sectionId).closest(".panel");
  if (!panel) return;
  panel.querySelectorAll(".empty").forEach((n) => n.classList.toggle("hidden", !show));
}

function chipClassFor(status) {
  if (status === "verified") return "chip chip-clean";
  if (status === "failed") return "chip chip-suspicious";
  return "chip chip-unverified";
}

// ---------------------------------------------------------------- panels

function renderKpis(bundle, summary) {
  const row = el("kpi-row");
  if (!bundle) {
    row.innerHTML = "";
    showEmpty("kpi-row", true);
    return;
  }
  showEmpty("kpi-row", false);
  const outcome = bundle.outcomes && bundle.outcomes.length
    ? bundle.outcomes[bundle.outcomes.length - 1] : null;
  const decisionClean = bundle.decisions.find((d) => d.kind === "recovery_point_selection");
  const cleanLabel = outcome?.clean_point_label ||
    (decisionClean ? decisionClean.payload?.selection?.chosen_label : null);
  const state = bundle.current_state;
  const stateCls = state === "COMPLETED" ? "status-ok"
    : state === "FAILED" || state === "ROLLED_BACK" ? "status-danger" : "status-warn";
  const incidentStatus = bundle.incident.status.toUpperCase();

  const cards = [
    { label: "Incident Status", value: incidentStatus, cls: incidentStatus === "OPEN" ? "status-danger" : "status-ok",
      sub: `scenario: ${bundle.scenario}` },
    { label: "Workflow State", value: state.replace(/_/g, " "), cls: stateCls,
      sub: bundle.failure_reason || "" },
    { label: "Chosen Clean Point", value: cleanLabel || "-",
      cls: "", sub: decisionClean ? `RPO cost ${fmtSeconds(decisionClean.payload?.selection?.rpo_achieved_seconds)}` : "" },
    { label: "RTO (modeled)", value: outcome ? `${Number(outcome.measured_rto_seconds ?? 0).toFixed(0)}s` : "-",
      cls: "", sub: outcome ? `planned ${fmtSeconds(outcome.planned_rto_seconds)}` : "awaiting execution" },
    { label: "RPO Achieved", value: outcome && outcome.measured_rpo_seconds !== null && outcome.measured_rpo_seconds !== undefined
        ? fmtSeconds(outcome.measured_rpo_seconds) : "-",
      cls: "", sub: "data-loss window vs clean point" },
    { label: "Order Correctness", value: outcome ? (outcome.dependency_order_correct ? "PASS" : "FAIL") : "-",
      cls: outcome ? (outcome.dependency_order_correct ? "status-ok" : "status-danger") : "",
      sub: summary ? `tool calls: ${summary.tool_calls_total} (errors ${summary.tool_errors_total})` : "" },
  ];
  row.innerHTML = cards.map((c) => `
    <div class="kpi">
      <div class="label">${c.label}</div>
      <div class="value ${c.cls}">${escapeHtml(String(c.value))}</div>
      <div class="sub">${escapeHtml(String(c.sub || ""))}</div>
    </div>`).join("");
}

function renderTimeline(bundle) {
  const list = el("timeline");
  const events = bundle ? bundle.timeline : [];
  list.innerHTML = events.map((e) => `
    <li class="sev-${e.severity}">
      <span class="t">${fmtTime(e.ts)} &middot; ${escapeHtml(e.event_type)}</span>
      <span class="m">${escapeHtml(e.message)}</span>
    </li>`).join("");
  list.parentElement.querySelector(".empty").classList.toggle("hidden", events.length > 0);
}

function renderAffectedAssets(bundle) {
  const tbody = el("assets-table").querySelector("tbody");
  const rows = bundle ? bundle.affected_assets : [];
  tbody.innerHTML = rows.map((a) => `
    <tr>
      <td>${escapeHtml(a.name)}</td>
      <td><span class="chip chip-tier${a.tier}">T${a.tier}</span></td>
      <td>${escapeHtml(a.asset_type)}</td>
      <td class="state-${a.state}">${a.state}</td>
      <td>${a.health}%</td>
    </tr>`).join("");
  showEmpty("assets-table", rows.length === 0);
}

function renderBackups(backups, decisions) {
  const tbody = el("backups-table").querySelector("tbody");
  const chosenDecision = decisions.find((d) => d.kind === "recovery_point_selection");
  const chosen = chosenDecision?.payload?.selection?.chosen_label;
  const rpoBylabel = {};
  (chosenDecision?.payload?.selection?.scores || []).forEach((s) => {
    rpoBylabel[s.label] = s.rpo_cost_seconds;
  });
  tbody.innerHTML = backups.map((b) => `
    <tr class="${b.label === chosen ? "row-chosen" : ""}" style="${b.label === chosen ? "background:rgba(63,178,127,.06)" : ""}">
      <td><strong>${escapeHtml(b.label)}</strong>${b.label === chosen ? ' <span class="chip chip-clean">CLEAN POINT</span>' : ""}</td>
      <td class="t">${fmtTime(b.taken_at)}</td>
      <td><span class="${chipClassFor(b.integrity_status)}">${b.integrity_status}</span></td>
      <td>${b.malicious_indicator_count}</td>
      <td>${rpoBylabel[b.label] !== undefined ? fmtSeconds(rpoBylabel[b.label]) : "-"}</td>
    </tr>`).join("");
  showEmpty("backups-table", backups.length === 0);
}

const TIER_LABELS = {
  0: "Tier 0 - Foundation (identity / db / storage / network / config)",
  1: "Tier 1 - Core business services",
  2: "Tier 2 - Reporting / analytics / notifications",
};

function renderTiers(assets) {
  const wrap = el("tiers");
  if (!assets.length) { wrap.innerHTML = ""; showEmpty("tiers", true); return; }
  showEmpty("tiers", false);
  const groups = {};
  assets.forEach((a) => { (groups[a.tier] = groups[a.tier] || []).push(a); });
  wrap.innerHTML = Object.keys(groups).sort().map((tier) => `
    <div class="tier-group">
      <div class="tier-title">${TIER_LABELS[tier] || `Tier ${tier}`}</div>
      <div class="asset-chips">
        ${groups[tier].map((a) => `<span class="chip chip-tier${a.tier}" title="${a.asset_type} - ${a.criticality}">${escapeHtml(a.name)}</span>`).join("")}
      </div>
    </div>`).join("");
}

function tierColor(tier) {
  return tier === 0 ? "#6ea8dc" : tier === 1 ? "#56b4a0" : "#b48ec4";
}

function renderDependencyGraph(assets, dependencies) {
  const svg = el("dep-graph");
  el("dep-legend").innerHTML =
    '<span class="l-tier0">Tier 0</span><span class="l-tier1">Tier 1</span><span class="l-tier2">Tier 2</span>';
  if (!assets.length) {
    svg.innerHTML = `<text x="450" y="170" fill="#8b96a5" text-anchor="middle">Seed the lab to render the dependency map.</text>`;
    return;
  }
  const byName = Object.fromEntries(assets.map((a) => [a.name, a]));
  const layers = { 0: [], 1: [], 2: [] };
  assets.forEach((a) => { (layers[a.tier] = layers[a.tier] || []).push(a.name); });
  Object.values(layers).forEach((names) => names.sort());

  // Layered layout: Tier 0 bottom (foundation), Tier 1 middle, Tier 2 top.
  const W = 900, H = 340;
  const layerY = { 0: H - 70, 1: H / 2 - 30, 2: 60 };
  const positions = {};
  Object.entries(layers).forEach(([tier, names]) => {
    const y = layerY[tier];
    const count = Math.max(names.length, 1);
    names.forEach((name, idx) => {
      positions[name] = { x: ((idx + 1) * W) / (count + 1), y };
    });
  });

  const parts = [];
  const edgeColors = {
    SERVICE_DEPENDS_ON_DATABASE: "#e5534b",
    SERVICE_REQUIRES_IDENTITY: "#d29922",
    SERVICE_REQUIRES_STORAGE: "#8b96a5",
    SERVICE_REQUIRES_CONFIG: "#6ea8dc",
    SERVICE_CALLS_SERVICE: "#3fb27f",
  };
  dependencies.forEach((dep) => {
    const a = positions[dep.from_asset], b = positions[dep.to_asset];
    if (!a || !b) return;
    parts.push(`<line x1="${a.x}" y1="${a.y + 18}" x2="${b.x}" y2="${b.y - 18}"
      stroke="${edgeColors[dep.dep_type] || "#555"}" stroke-width="1.4" opacity="0.75">
      </line>`);
  });
  assets.forEach((asset) => {
    const p = positions[asset.name];
    const color = tierColor(asset.tier);
    const stateColor = asset.state === "running" ? "#3fb27f"
      : asset.state === "degraded" ? "#d29922" : "#e5534b";
    parts.push(`
      <g>
        <circle cx="${p.x}" cy="${p.y}" r="5" fill="${stateColor}">
          <title>${escapeHtml(asset.name)}: ${asset.state} (${asset.health}%)</title>
        </circle>
        <rect x="${p.x - 62}" y="${p.y + 10}" width="124" height="26" rx="6"
          fill="#161b22" stroke="${color}" stroke-width="1.2"></rect>
        <text x="${p.x}" y="${p.y + 27}" fill="#d7dde5" font-size="11"
          text-anchor="middle" font-family="inherit">${escapeHtml(shortName(asset.name))}</text>
      </g>`);
  });
  svg.innerHTML = parts.join("");
}

function shortName(name) {
  return name.replace("-service", "").replace("core-", "");
}

function renderPlan(bundle) {
  const list = el("plan-steps");
  const bar = el("plan-progress");
  const actions = bundle ? bundle.actions : [];
  if (!actions.length) {
    list.innerHTML = ""; bar.style.width = "0%";
    showEmpty("plan-steps", true);
    return;
  }
  showEmpty("plan-steps", false);
  const done = actions.filter((a) => a.status === "executed").length;
  bar.style.width = `${(done / actions.length) * 100}%`;
  list.innerHTML = actions.map((a) => `
    <li class="st-${a.status}">
      <span class="seq">#${String(a.seq).padStart(2, "0")}</span>
      <span>
        <span class="target">${escapeHtml(a.target_asset)}</span>
        <span class="meta"> &middot; ${escapeHtml(a.action_type)}
          ${a.source_snapshot_label ? ` &middot; from ${escapeHtml(a.source_snapshot_label)}` : ""}
          &middot; est RTO ${fmtSeconds(a.estimated_rto_seconds)}</span>
        <div class="meta">validation: ${escapeHtml(a.validation_test || "-")} &middot; risk ${escapeHtml(a.risk_level)}</div>
      </span>
      <span class="st status-${a.status === "executed" ? "ok" : a.status === "failed" ? "danger" : "warn"}">${a.status}</span>
    </li>`).join("");
}

function renderValidations(bundle) {
  const list = el("validations");
  const rows = bundle ? bundle.validations : [];
  list.innerHTML = rows.map((v) => `
    <li>
      <span class="mark ${v.passed ? "pass" : "fail"}">${v.passed ? "PASS" : "FAIL"}</span>
      <span>${escapeHtml(v.name)}${v.target ? ` <span class="meta">(${escapeHtml(v.target)})</span>` : ""}</span>
      <span class="phase-tag">${escapeHtml(v.phase)}</span>
    </li>`).join("");
  list.parentElement.querySelector(".empty").classList.toggle("hidden", rows.length > 0);
}

async function renderAudit(bundle) {
  const tbody = el("audit-table").querySelector("tbody");
  let toolCalls = [];
  try {
    toolCalls = bundle
      ? await getJSON(`/api/v1/tool-calls?investigation_id=${encodeURIComponent(bundle.investigation_id)}`)
      : [];
  } catch { toolCalls = []; }
  const approvalRows = (bundle ? bundle.approvals : []).map((a) => ({
    created_at: a.decided_at || a.requested_at,
    tool_name: `approval (${a.requested_by})`,
    status: a.status,
    risk_level: "gate",
    summary: a.decided_by ? `decided by ${a.decided_by}${a.note ? ": " + a.note : ""}`
      : "awaiting human decision",
  }));
  const merged = [...approvalRows, ...toolCalls].slice(0, 60);
  tbody.innerHTML = merged.map((t) => `
    <tr>
      <td class="t">${fmtTime(t.created_at)}</td>
      <td>${escapeHtml(t.tool_name)}</td>
      <td><span class="${t.status === "success" || t.status === "approved" ? "state-running" : t.status === "pending" ? "state-degraded" : "state-down"}">${escapeHtml(t.status)}</span></td>
      <td>${escapeHtml(String(t.risk_level))}</td>
      <td>${escapeHtml(String(t.summary || ""))}</td>
    </tr>`).join("");
  showEmpty("audit-table", merged.length === 0);
}

function escapeHtml(text) {
  const div = document.createElement("div");
  div.textContent = text ?? "";
  return div.innerHTML;
}

// ---------------------------------------------------------------- polling

function isActive(state) {
  return state && ACTIVE_STATES.has(state);
}

async function refreshOnce() {
  try {
    const investigations = await getJSON("/api/v1/investigations");
    currentInvestigation = investigations.length ? investigations[0] : null;

    const [assets, backups, summary] = await Promise.all([
      getJSON("/api/v1/assets"),
      getJSON("/api/v1/backups"),
      getJSON("/api/v1/metrics/summary").catch(() => null),
    ]);

    let bundle = null;
    if (currentInvestigation) {
      bundle = await getJSON(
        `/api/v1/investigations/${encodeURIComponent(currentInvestigation.public_id)}`);
    }

    renderKpis(bundle, summary);
    renderTimeline(bundle);
    renderAffectedAssets(bundle);
    renderDependencyGraph(assets, await getJSON("/api/v1/dependencies"));
    renderBackups(backups, bundle ? bundle.decisions : []);
    renderTiers(assets);
    renderPlan(bundle);
    renderValidations(bundle);
    await renderAudit(bundle);

    el("footer-state").textContent = bundle
      ? `investigation ${bundle.investigation_id.slice(0, 13)}... in ${bundle.current_state}`
      : "idle - no investigation yet";
    el("conn-dot").className = "conn conn-on";
    return bundle;
  } catch (err) {
    console.warn("refresh failed:", err);
    el("conn-dot").className = "conn conn-off";
    el("footer-state").textContent = "API unreachable; retrying...";
    return null;
  }
}

async function pollLoop() {
  let timer = null;
  const tick = async () => {
    const bundle = await refreshOnce();
    const interval = bundle && isActive(bundle.current_state) ? 3000 : 8000;
    timer = setTimeout(tick, interval);
  };
  await tick();
  return () => clearTimeout(timer);
}

async function init() {
  try {
    meta = await getJSON("/api/v1/meta");
    const badge = el("llm-badge");
    if (meta.mock) badge.classList.remove("hidden");
    else badge.classList.add("hidden");
  } catch {
    el("conn-dot").className = "conn conn-off";
  }
  setInterval(() => { el("clock").textContent = new Date().toLocaleTimeString(); }, 1000);
  await pollLoop();
}

init();
