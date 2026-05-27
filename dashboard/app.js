// selfdef dashboard — single-file vanilla JS. No bundler, no node_modules.
//
// Talks to the read-only selfdef HTTP API:
//   GET /status
//   GET /findings?n=N
//   GET /events?n=N
//   GET /events/stream   (Server-Sent Events)
//
// API base URL is configurable via the `?api=` query param. When the
// dashboard is served from the same origin as the daemon (typical when
// fronted by a reverse proxy), the default empty base "" works.
//
// Bearer token is read from `?token=` (one-off) or sessionStorage
// (sticky for the tab). It's only attached to fetch when present, so the
// UNIX-socket transport (which trusts ambient auth) works unconfigured.

(() => {
  const SEVERITY_LABELS = {
    0: "Unknown",
    1: "Informational",
    2: "Low",
    3: "Medium",
    4: "High",
    5: "Critical",
    6: "Fatal",
  };

  const params = new URLSearchParams(window.location.search);
  const apiBase = params.get("api") || "";
  let token = params.get("token") || sessionStorage.getItem("selfdef.token") || "";
  if (params.get("token")) {
    sessionStorage.setItem("selfdef.token", token);
  }

  const headers = () => (token ? { Authorization: `Bearer ${token}` } : {});

  async function get(path) {
    const url = `${apiBase}${path}`;
    const res = await fetch(url, { headers: headers(), cache: "no-store" });
    if (!res.ok) {
      throw new Error(`${res.status} ${res.statusText}`);
    }
    return res.json();
  }

  /// POST helper for control endpoints. Returns the parsed body even on
  /// non-2xx — the API responds with JSON for both success and error so
  /// the dashboard can surface what happened. The thrown Error carries
  /// the status + the API's error message.
  async function post(path, body) {
    const url = `${apiBase}${path}`;
    const init = {
      method: "POST",
      headers: { ...headers() },
      cache: "no-store",
    };
    if (body !== undefined) {
      init.headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(body);
    }
    const res = await fetch(url, init);
    const text = await res.text();
    let parsed = null;
    try {
      parsed = text ? JSON.parse(text) : null;
    } catch {
      // Non-JSON response; surface raw text in the error path.
    }
    if (!res.ok) {
      const detail = parsed?.error || text || res.statusText;
      const err = new Error(`${res.status} ${detail}`);
      err.status = res.status;
      err.body = parsed;
      throw err;
    }
    return parsed;
  }

  function severityClass(id) {
    return (SEVERITY_LABELS[id] || "info").toLowerCase();
  }

  function fmtTime(iso) {
    if (!iso) return "—";
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return iso;
    // Drop the date if it's today.
    const today = new Date();
    const sameDay = d.toDateString() === today.toDateString();
    const h = d.getHours().toString().padStart(2, "0");
    const m = d.getMinutes().toString().padStart(2, "0");
    const s = d.getSeconds().toString().padStart(2, "0");
    return sameDay ? `${h}:${m}:${s}` : d.toISOString().slice(0, 19).replace("T", " ");
  }

  function renderEvent(ev) {
    const li = document.createElement("li");
    const sev = severityClass(ev.severity_id);

    const time = document.createElement("span");
    time.className = "time";
    time.textContent = fmtTime(ev.time_dt);

    const severity = document.createElement("span");
    severity.className = `sev ${sev}`;
    severity.textContent = SEVERITY_LABELS[ev.severity_id] || ev.severity_id;

    const src = document.createElement("span");
    src.className = "src";
    src.textContent = ev.source || "—";

    const msg = document.createElement("span");
    msg.className = "msg";
    msg.title = ev.message || "";
    msg.textContent = ev.message || "(no message)";

    li.append(time, severity, src, msg);
    return li;
  }

  function setEmpty(ul, text) {
    ul.innerHTML = "";
    const li = document.createElement("li");
    li.className = "empty";
    li.textContent = text;
    ul.appendChild(li);
  }

  async function refresh(kind) {
    // Three-watchdog-trio panels — different endpoint shapes.
    if (kind === "friction-audit") {
      return refreshFrictionAudit();
    }
    if (kind === "perimeter") {
      return refreshPerimeter();
    }
    if (kind === "guardian") {
      return refreshGuardian();
    }
    if (kind === "scheduler") {
      return refreshScheduler();
    }
    if (kind === "modules") {
      return refreshModules();
    }
    if (kind === "capability-tokens") {
      return refreshCapabilityTokens();
    }
    if (kind === "tool-authority") {
      return refreshToolAuthority();
    }
    if (kind === "commit-authority") {
      return refreshCommitAuthority();
    }
    if (kind === "sandbox-tiers") {
      return refreshSandboxTiers();
    }
    if (kind === "filesystem-boundary") {
      return refreshFilesystemBoundary();
    }
    if (kind === "network-boundary") {
      return refreshNetworkBoundary();
    }
    if (kind === "communication-boundary") {
      return refreshCommunicationBoundary();
    }
    if (kind === "authority") {
      return refreshAuthority();
    }
    if (kind === "policy") {
      return refreshPolicy();
    }
    if (kind === "alerts") {
      return refreshAlerts();
    }
    if (kind === "hardware") {
      return refreshHardware();
    }
    if (kind === "network") {
      return refreshNetwork();
    }
    if (kind === "storage") {
      return refreshStorage();
    }
    if (kind === "raid") {
      return refreshRaid();
    }
    if (kind === "gpu") {
      return refreshGpu();
    }
    if (kind === "cpu") {
      return refreshCpu();
    }
    if (kind === "flex-profile") {
      return refreshFlexProfile();
    }
    if (kind === "inference-backends") {
      return refreshInferenceBackends();
    }
    if (kind === "health") {
      return refreshHealth();
    }
    if (kind === "audit-chains") {
      return refreshAuditChains();
    }
    const ul = document.getElementById(kind);
    try {
      const data = await get(`/${kind}?n=50`);
      if (!Array.isArray(data) || data.length === 0) {
        setEmpty(ul, `no ${kind} yet`);
        return;
      }
      ul.innerHTML = "";
      for (const ev of data) {
        ul.appendChild(renderEvent(ev));
      }
    } catch (e) {
      setEmpty(ul, `error: ${e.message}`);
    }
  }

  // Friction-audit panel — reads GET /v1/friction-audit.
  // SDD-027 / MS046. Operator-facing surface, read-only.
  const FA_GATE_LABEL = {
    pcie: "PCIe Bifurcation",
    zfs: "ZFS Pool Health",
    memory: "Memory Geometry",
    immutability: "Script Immutability",
    signature: "MS003 Signature",
    timeout: "Gate Timeout",
  };
  const FA_RUNBOOK_BASE = "/wiki/runbooks/friction-audit-";
  const FA_GATE_ORDER = ["pcie", "zfs", "memory", "immutability", "signature", "timeout"];

  function faStatusToBadgeColor(status) {
    // Status is the mirror's Status enum (`pass | fail(code) | skipped(detail) | override-active{...}`).
    if (!status) return { badge: "—", color: "gray", detail: "" };
    if (status.status === "pass") return { badge: "PASS", color: "green", detail: "" };
    if (status.status === "skipped")
      return { badge: "SKIP", color: "green", detail: `operator-extended skip · ${status.detail || ""}` };
    if (status.status === "fail")
      return { badge: "FAIL", color: "red", detail: `exit ${status.detail}` };
    if (status.status === "override-active")
      return { badge: "OVRD", color: "yellow", detail: `manifest ${(status.manifest_sha256 || "").slice(0, 8)}…` };
    return { badge: "—", color: "gray", detail: "" };
  }

  function faFreshness(nowMs, tsMs) {
    if (!tsMs) return "no verdict yet";
    const delta = Math.max(0, nowMs - tsMs);
    const s = Math.floor(delta / 1000);
    if (s < 5) return "just now";
    if (s < 60) return `${s}s ago`;
    if (s < 3600) return `${Math.floor(s / 60)}m ago`;
    if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
    if (s < 86400 * 30) return `${Math.floor(s / 86400)}d ago · stale`;
    return "stale (>30d)";
  }

  async function refreshFrictionAudit() {
    const ul = document.getElementById("friction-audit-rows");
    const aggEl = document.getElementById("fa-aggregate");
    try {
      const body = await get("/v1/friction-audit");
      // Aggregate badge.
      aggEl.textContent = (body.aggregate || "unknown").toUpperCase();
      aggEl.className = `fa-aggregate fa-${body.aggregate || "unknown"}`;

      // Index verdicts + overrides by gate.
      const verdictByGate = {};
      for (const v of body.verdicts || []) {
        verdictByGate[v.gate] = v;
      }
      const overrideByGate = {};
      for (const m of body.overrides || []) {
        overrideByGate[m.gate] = m;
      }

      ul.innerHTML = "";
      for (const gate of FA_GATE_ORDER) {
        const li = document.createElement("li");
        const v = verdictByGate[gate];
        let badgeInfo;
        if (overrideByGate[gate]) {
          badgeInfo = {
            badge: "OVRD",
            color: "yellow",
            detail: `operator override · expires ${new Date(overrideByGate[gate].expires_at_ms).toISOString().slice(0, 19)}Z`,
          };
        } else if (v) {
          badgeInfo = faStatusToBadgeColor(v.status);
          if (!badgeInfo.detail) badgeInfo.detail = faFreshness(body.now_ms, v.ts_ms);
          else badgeInfo.detail = `${badgeInfo.detail} · ${faFreshness(body.now_ms, v.ts_ms)}`;
        } else {
          badgeInfo = { badge: "—", color: "gray", detail: "no verdict yet recorded" };
        }

        li.className = `fa-${badgeInfo.color}`;

        const labelSpan = document.createElement("span");
        labelSpan.className = "fa-gate-label";
        labelSpan.textContent = FA_GATE_LABEL[gate] || gate;

        const badgeSpan = document.createElement("span");
        badgeSpan.className = `fa-badge fa-${badgeInfo.color}`;
        badgeSpan.textContent = badgeInfo.badge;

        const detailSpan = document.createElement("span");
        detailSpan.className = "fa-detail";
        detailSpan.textContent = badgeInfo.detail;

        const linkA = document.createElement("a");
        linkA.className = "fa-runbook-link";
        // The runbook is served by the info-hub second brain (gateway
        // ingress). When the operator's wiki is running on the same
        // host, the relative path resolves; otherwise the operator
        // configures their wiki origin separately.
        linkA.href = `${FA_RUNBOOK_BASE}${gate}`;
        linkA.target = "_blank";
        linkA.rel = "noopener";
        linkA.textContent = "runbook ↗";

        li.appendChild(labelSpan);
        li.appendChild(badgeSpan);
        li.appendChild(detailSpan);
        li.appendChild(linkA);
        ul.appendChild(li);
      }
    } catch (e) {
      setEmpty(ul, `error: ${e.message}`);
      aggEl.textContent = "ERROR";
      aggEl.className = "fa-aggregate fa-fail";
    }
  }

  // Perimeter panel — reads GET /v1/perimeter.
  // SDD-028 / MS047. Operator-facing surface, read-only.
  const PERIM_RUNBOOK_BASE = "/wiki/runbooks/perimeter-";

  function perimOutcomeBadge(outcome) {
    if (!outcome) return { badge: "—", color: "gray" };
    if (outcome.outcome === "sigkill") return { badge: "SIGKILL", color: "red" };
    if (outcome.outcome === "allowlisted") return { badge: "ALLOWED", color: "green" };
    if (outcome.outcome === "extension-allowed") {
      const stub = (outcome.detail && outcome.detail.manifest_sha256 || "").slice(0, 8);
      return { badge: `EXTEND[${stub}]`, color: "yellow" };
    }
    return { badge: "—", color: "gray" };
  }

  async function refreshPerimeter() {
    const ul = document.getElementById("perimeter-rows");
    const aggEl = document.getElementById("perim-aggregate");
    const metaEl = document.getElementById("perimeter-meta");
    try {
      const body = await get("/v1/perimeter");
      aggEl.textContent = (body.aggregate || "unknown").toUpperCase();
      aggEl.className = `fa-aggregate fa-${body.aggregate || "unknown"}`;

      // Meta line: policy status + active extension count + audit chain length.
      const policyState = body.policy && body.policy.present ? "PRESENT" : "MISSING";
      const extCount = (body.active_extensions || []).length;
      const chainEvents = body.audit_chain_events;
      metaEl.textContent =
        `policy: ${policyState} · ${extCount} operator extension(s) active · ` +
        `OCSF chain events: ${chainEvents === null || chainEvents === undefined ? "—" : chainEvents}`;

      ul.innerHTML = "";

      // Active extension rows first (yellow, time-bound).
      for (const ext of body.active_extensions || []) {
        const li = document.createElement("li");
        li.className = "fa-yellow";
        const label = document.createElement("span");
        label.className = "fa-gate-label";
        label.textContent = `ext: ${ext.extension_id}`;
        const badge = document.createElement("span");
        badge.className = "fa-badge fa-yellow";
        badge.textContent = "EXTEND";
        const detail = document.createElement("span");
        detail.className = "fa-detail";
        const exp = new Date(ext.expires_at_ms).toISOString().slice(0, 19) + "Z";
        const pathCount = (ext.binary_paths || []).length;
        detail.textContent =
          `${pathCount} path(s) · expires ${exp} · signer=${ext.signer_kid} auditor=${ext.auditor_kid}`;
        const link = document.createElement("a");
        link.className = "fa-runbook-link";
        link.href = `${PERIM_RUNBOOK_BASE}extension-create`;
        link.target = "_blank";
        link.rel = "noopener";
        link.textContent = "runbook ↗";
        li.appendChild(label);
        li.appendChild(badge);
        li.appendChild(detail);
        li.appendChild(link);
        ul.appendChild(li);
      }

      // Verdict rows (newest-first; body.verdicts already capped at 16 server-side).
      const verdicts = body.verdicts || [];
      if (verdicts.length === 0 && (body.active_extensions || []).length === 0) {
        setEmpty(ul, "no perimeter verdicts yet recorded");
      }
      for (const v of verdicts) {
        const info = perimOutcomeBadge(v.outcome);
        const li = document.createElement("li");
        li.className = `fa-${info.color}`;
        const label = document.createElement("span");
        label.className = "fa-gate-label";
        label.textContent = v.attempted_binary_path;
        const badge = document.createElement("span");
        badge.className = `fa-badge fa-${info.color}`;
        badge.textContent = info.badge;
        const detail = document.createElement("span");
        detail.className = "fa-detail";
        detail.textContent =
          `pid=${v.attempting_pid} parent=${v.parent_pid} · ${faFreshness(body.now_ms, v.ts_ms)} · host=${v.hostname}`;
        const link = document.createElement("a");
        link.className = "fa-runbook-link";
        link.href = info.color === "red"
          ? `${PERIM_RUNBOOK_BASE}sigkill-investigation`
          : `${PERIM_RUNBOOK_BASE}extension-create`;
        link.target = "_blank";
        link.rel = "noopener";
        link.textContent = "runbook ↗";
        li.appendChild(label);
        li.appendChild(badge);
        li.appendChild(detail);
        li.appendChild(link);
        ul.appendChild(li);
      }
    } catch (e) {
      setEmpty(ul, `error: ${e.message}`);
      aggEl.textContent = "ERROR";
      aggEl.className = "fa-aggregate fa-fail";
    }
  }

  // Guardian panel — reads GET /v1/guardian.
  // SDD-029 / MS044. Operator-facing surface, read-only.
  const GUARD_RUNBOOK_BASE = "/wiki/runbooks/guardian-";

  function guardActionBadge(verdict) {
    const allOk = stepsAllOk(verdict.response_steps || []);
    if (allOk) return { badge: "OK", color: "green" };
    return { badge: "ALERT", color: "red" };
  }

  function stepsAllOk(steps) {
    let haveSigkill = false, haveAudit = false, haveConsole = false;
    for (const s of steps) {
      const out = s.outcome;
      const tag = (out && (out.outcome || out)) || "";
      if (tag === "failed") return false;
      if (s.step === "sigkill") haveSigkill = true;
      if (s.step === "audit-append") haveAudit = true;
      if (s.step === "console-alert") haveConsole = true;
    }
    return haveSigkill && haveAudit && haveConsole;
  }

  async function refreshGuardian() {
    const ul = document.getElementById("guardian-rows");
    const aggEl = document.getElementById("guard-aggregate");
    const metaEl = document.getElementById("guardian-meta");
    try {
      const body = await get("/v1/guardian");
      aggEl.textContent = (body.aggregate || "unknown").toUpperCase();
      aggEl.className = `fa-aggregate fa-${body.aggregate || "unknown"}`;

      const socketState = body.tetragon_socket_present ? "PRESENT" : "MISSING";
      const chainEvents = body.audit_chain_events;
      metaEl.textContent =
        `tetragon socket: ${socketState} · ` +
        `OCSF chain events: ${chainEvents === null || chainEvents === undefined ? "—" : chainEvents}`;

      ul.innerHTML = "";
      const verdicts = body.verdicts || [];
      if (verdicts.length === 0) {
        setEmpty(ul, "no guardian verdicts yet recorded");
        return;
      }
      for (const v of verdicts) {
        const info = guardActionBadge(v);
        const li = document.createElement("li");
        li.className = `fa-${info.color}`;
        const label = document.createElement("span");
        label.className = "fa-gate-label";
        label.textContent = v.target_binary_path;
        const badge = document.createElement("span");
        badge.className = `fa-badge fa-${info.color}`;
        badge.textContent = info.badge;
        const detail = document.createElement("span");
        detail.className = "fa-detail";
        detail.textContent =
          `event=${v.event_id} action=${v.action} pid=${v.target_pid} · ${faFreshness(body.now_ms, v.ts_ms)} · host=${v.hostname}`;
        const link = document.createElement("a");
        link.className = "fa-runbook-link";
        link.href = info.color === "red"
          ? `${GUARD_RUNBOOK_BASE}console-alert-investigation`
          : `${GUARD_RUNBOOK_BASE}not-running`;
        link.target = "_blank";
        link.rel = "noopener";
        link.textContent = "runbook ↗";
        li.appendChild(label);
        li.appendChild(badge);
        li.appendChild(detail);
        li.appendChild(link);
        ul.appendChild(li);
      }
    } catch (e) {
      setEmpty(ul, `error: ${e.message}`);
      aggEl.textContent = "ERROR";
      aggEl.className = "fa-aggregate fa-fail";
    }
  }

  // Scheduler panel — reads GET /v1/scheduler.
  // SDD-031 / MS048. Operator-facing surface, read-only.
  const SCHED_RUNBOOK_BASE = "/wiki/runbooks/scheduler-";

  async function refreshScheduler() {
    const ul = document.getElementById("scheduler-rows");
    const aggEl = document.getElementById("sched-aggregate");
    const metaEl = document.getElementById("scheduler-meta");
    try {
      const body = await get("/v1/scheduler");
      aggEl.textContent = (body.aggregate || "unknown").toUpperCase();
      aggEl.className = `fa-aggregate fa-${body.aggregate || "unknown"}`;

      const chainEvents = body.audit_chain_events;
      metaEl.textContent =
        `decisions: ${body.decisions ? body.decisions.length : 0} · ` +
        `OCSF chain events: ${chainEvents === null || chainEvents === undefined ? "—" : chainEvents}`;

      ul.innerHTML = "";
      const decisions = body.decisions || [];
      if (decisions.length === 0) {
        setEmpty(ul, "no scheduler decisions yet recorded");
        return;
      }
      for (const d of decisions) {
        const bp = d.backpressure || {};
        const anyBp =
          bp.blackwell_vram_high ||
          bp.gpu3090_busy ||
          bp.cpu_pressure ||
          bp.ram_pressure ||
          bp.io_pressure ||
          bp.human_gate_queue_high;
        const isOverride = d.override_signer_kid != null;
        let badge, color, runbook;
        if (isOverride) {
          badge = `OVRD[${d.route}]`;
          color = "yellow";
          runbook = `${SCHED_RUNBOOK_BASE}force-override-investigation`;
        } else if (anyBp) {
          badge = `BP[${d.route}]`;
          color = "yellow";
          runbook = `${SCHED_RUNBOOK_BASE}backpressure-stuck-open`;
        } else {
          badge = (d.route || "?").toUpperCase();
          color = "green";
          runbook = "";
        }
        const li = document.createElement("li");
        li.className = `fa-${color}`;
        const label = document.createElement("span");
        label.className = "fa-gate-label";
        label.textContent = d.request_id;
        const badgeSpan = document.createElement("span");
        badgeSpan.className = `fa-badge fa-${color}`;
        badgeSpan.textContent = badge;
        const detail = document.createElement("span");
        detail.className = "fa-detail";
        const compound = d.axis_scores ? d.axis_scores.compound.toFixed(3) : "?";
        detail.textContent =
          `profile=${d.profile} compound=${compound} · ${faFreshness(body.now_ms, d.ts_ms)} · host=${d.hostname}`;
        const link = document.createElement("a");
        link.className = "fa-runbook-link";
        link.href = runbook || `${SCHED_RUNBOOK_BASE}not-running`;
        link.target = "_blank";
        link.rel = "noopener";
        link.textContent = "runbook ↗";
        li.appendChild(label);
        li.appendChild(badgeSpan);
        li.appendChild(detail);
        li.appendChild(link);
        ul.appendChild(li);
      }
    } catch (e) {
      setEmpty(ul, `error: ${e.message}`);
      aggEl.textContent = "ERROR";
      aggEl.className = "fa-aggregate fa-fail";
    }
  }

  // Modules panel — reads GET /v1/modules (MS006 / SDD-009).
  // Read-only; module activation goes through `selfdefctl modules apply`.
  // Category → palette color mapping (uses the existing fa-* CSS classes).
  const MODULE_CATEGORY_COLOR = {
    detection: "green",
    hardening: "green",
    observability: "green",
    deception: "yellow",
    response: "yellow",
    inference: "yellow",
    network: "green",
    hardware: "green",
    "": "gray",
  };

  async function refreshModules() {
    const ul = document.getElementById("modules-rows");
    const countEl = document.getElementById("modules-count");
    const metaEl = document.getElementById("modules-meta");
    try {
      // SDD-057 step 5 — fetch install-options counts in parallel
      // with the modules list so the meta line surfaces ready /
      // blocked-by-hardware / blocked-by-missing-deps / needs-review.
      // SDD-026 Z-8 — also fetch install-plan to surface path
      // conflicts (modules whose [install_paths].paths overlap).
      const [body, opts, plan] = await Promise.all([
        get("/v1/modules"),
        get("/v1/modules/install-options").catch(() => null),
        get("/v1/modules/install-plan").catch(() => null),
      ]);
      const modules = body.modules || [];
      const activeCount = modules.filter((m) => m.active).length;
      const conflictCount = (plan && plan.path_conflicts && plan.path_conflicts.length) || 0;
      countEl.textContent = `${activeCount}/${modules.length}`;
      countEl.className =
        "fa-aggregate " + (modules.length === 0
          ? "fa-unknown"
          : conflictCount > 0 ? "fa-yellow" : "fa-ok");
      let metaText = `${activeCount} active / ${modules.length} shipped · dir: ${body.modules_dir || "(missing)"}`;
      if (opts && opts.counts) {
        const c = opts.counts;
        metaText += ` · install options: ${c.ready ?? 0} ready, ${c.blocked_by_missing_deps ?? 0} blocked-by-deps, ${c.blocked_by_hardware ?? 0} blocked-by-hw, ${c.needs_review ?? 0} needs-review`;
      }
      if (conflictCount > 0) {
        const conflictPaths = plan.path_conflicts
          .slice(0, 3)
          .map(c => `${c.path} (${c.modules.join(", ")})`)
          .join("; ");
        const more = conflictCount > 3 ? ` + ${conflictCount - 3} more` : "";
        metaText += ` · ⚠ ${conflictCount} path conflict${conflictCount === 1 ? "" : "s"}: ${conflictPaths}${more}`;
      }
      metaEl.textContent = metaText;
      ul.innerHTML = "";
      if (modules.length === 0) {
        setEmpty(ul, "no modules found at the configured dir");
        return;
      }
      // Active first, then alphabetical.
      modules.sort((a, b) => {
        if (a.active !== b.active) return b.active - a.active;
        return (a.name || "").localeCompare(b.name || "");
      });
      for (const m of modules) {
        const li = document.createElement("li");
        // Active modules render in their category color; inactive
        // ones render as gray (operator can see what's installed
        // but not turned on).
        const color = m.active
          ? MODULE_CATEGORY_COLOR[m.category || ""] || "gray"
          : "gray";
        li.className = `fa-${color}`;

        const label = document.createElement("span");
        label.className = "fa-gate-label";
        label.textContent = m.name;

        const badge = document.createElement("span");
        badge.className = `fa-badge fa-${color}`;
        badge.textContent = m.active
          ? "ACTIVE"
          : (m.category || "—").toUpperCase();

        const detail = document.createElement("span");
        detail.className = "fa-detail";
        const deps = (m.depends_on || []).length;
        const prov = (m.provides || []).length;
        const cat = m.category || "—";
        // MS011 Z-8 — surface install_paths.scope ("system" | "container")
        // so operators see container-vs-system distinction at a glance.
        const scope = (m.install_paths && m.install_paths.scope) || "system";
        const scopeBadge = scope === "container" ? " · container-scope" : "";
        detail.textContent = `v${m.version || "?"} · [${cat}]${scopeBadge} · ${m.summary || ""} · ${deps} dep · ${prov} prov`;

        // No runbook per module yet — link to the module catalog doc.
        const link = document.createElement("a");
        link.className = "fa-runbook-link";
        link.href = "/wiki/runbooks/";
        link.target = "_blank";
        link.rel = "noopener";
        link.textContent = "docs ↗";

        li.appendChild(label);
        li.appendChild(badge);
        li.appendChild(detail);
        li.appendChild(link);
        ul.appendChild(li);
      }
    } catch (e) {
      setEmpty(ul, `error: ${e.message}`);
      countEl.textContent = "ERR";
      countEl.className = "fa-aggregate fa-fail";
    }
  }

  // Parse Prometheus exposition format → {series_name: latest_value}.
  // Comment lines (# ...) are skipped; samples with labels are folded
  // by stripping the {labels} block (we only use unlabeled series here).
  function parsePromExposition(text) {
    const out = {};
    for (const line of text.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;
      // Strip any {labels} block.
      const noLabels = trimmed.replace(/\{[^}]*\}/, "");
      const parts = noLabels.split(/\s+/);
      if (parts.length < 2) continue;
      const name = parts[0];
      const val = parseFloat(parts[1]);
      if (Number.isFinite(val)) out[name] = val;
    }
    return out;
  }

  // Alerts overview — surfaces the 9 alert-relevant series from
  // modules/observability/assets/alerts/selfdef.yml.template so
  // operators see the four-watchdog set's alert-state directly in
  // the dashboard without needing an external Prometheus.
  /// Renders the 9 alert rows from a classification object of shape
  /// `{ worst, alerts: [{name, ms, series, threshold, value, state}] }`.
  /// Used by both the `/v1/alerts` happy path and the `/metrics`
  /// client-side fallback so the DOM-render code path stays unified.
  function renderAlertRows(classification) {
    const ul = document.getElementById("alerts-rows");
    const meta = document.getElementById("alerts-meta");
    const aggEl = document.getElementById("alerts-aggregate");
    const rows = classification.alerts;
    const worst = classification.worst;
    const lis = rows.map(r => {
      const label = r.value === null || r.value === undefined ? "—" : String(r.value);
      const cssClass = r.state === "critical" ? "fa-fail"
                     : r.state === "warn"     ? "fa-degraded"
                     : r.state === "ok"       ? "fa-ok"
                     :                          "fa-unknown";
      return `<li class="fa-row">
        <span class="fa-aggregate ${cssClass}">${r.state.toUpperCase()}</span>
        <code>${r.name}</code>
        <small>${r.ms} · ${r.series} · ${r.threshold} · current = ${label}</small>
      </li>`;
    });
    ul.innerHTML = lis.join("");
    meta.textContent = `${rows.length} alert-relevant series · worst = ${worst.toUpperCase()}`;
    aggEl.textContent = worst.toUpperCase();
    aggEl.className = "fa-aggregate " + (
      worst === "critical" ? "fa-fail"
      : worst === "warn"   ? "fa-degraded"
      : worst === "ok"     ? "fa-ok"
      :                      "fa-unknown"
    );
  }

  /// Client-side fallback: parses /metrics exposition and replays the
  /// same 9-row classifier the server uses. Kept resilient against
  /// the /v1/alerts endpoint being unavailable on older daemons.
  async function fallbackClassifyFromMetrics() {
    const url = api("/metrics");
    const res = await fetch(url, { headers: headers(), cache: "no-store" });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const series = parsePromExposition(await res.text());
    const rows = [
      { name: "FrictionAuditFailing",        ms: "MS046", series: "selfdef_friction_audit_failing_total",            threshold: "> 0",           critical: v => v > 0 },
      { name: "PerimeterSigkill",            ms: "MS047", series: "selfdef_perimeter_sigkills_total",                 threshold: "rate > 0 / 5m", warn:     v => v > 0 },
      { name: "PerimeterPolicyMissing",      ms: "MS047", series: "selfdef_perimeter_policy_present",                 threshold: "== 0 for 2m",   critical: v => v === 0 },
      { name: "PerimeterChainBroken",        ms: "MS047", series: "selfdef_perimeter_audit_chain_events",             threshold: "== -1",         critical: v => v === -1 },
      { name: "GuardianFailedResponse",      ms: "MS044", series: "selfdef_guardian_failed_responses_total",          threshold: "> 0",           critical: v => v > 0 },
      { name: "GuardianTetragonSocketMissing", ms: "MS044", series: "selfdef_guardian_tetragon_socket_present",       threshold: "== 0 for 2m",   warn:     v => v === 0 },
      { name: "GuardianChainBroken",         ms: "MS044", series: "selfdef_guardian_audit_chain_events",              threshold: "== -1",         critical: v => v === -1 },
      { name: "SchedulerSustainedBackpressure", ms: "MS048", series: "selfdef_scheduler_backpressured_decisions_total", threshold: "rate > 0 / 10m", warn:    v => v > 0 },
      { name: "SchedulerChainBroken",        ms: "MS048", series: "selfdef_scheduler_audit_chain_events",             threshold: "== -1",         critical: v => v === -1 },
    ];
    let worst = "ok";
    const classified = rows.map(r => {
      const v = series[r.series];
      let state = "unknown", value = null;
      if (Number.isFinite(v)) {
        value = v;
        if (r.critical && r.critical(v))      state = "critical";
        else if (r.warn && r.warn(v))         state = "warn";
        else                                  state = "ok";
      }
      if (state === "critical")                                       worst = "critical";
      else if (state === "warn" && worst !== "critical")              worst = "warn";
      else if (state === "unknown" && worst === "ok")                 worst = "unknown";
      return { name: r.name, ms: r.ms, series: r.series, threshold: r.threshold, value, state };
    });
    return { worst, alerts: classified };
  }

  async function refreshAlerts() {
    const ul = document.getElementById("alerts-rows");
    const meta = document.getElementById("alerts-meta");
    const aggEl = document.getElementById("alerts-aggregate");
    try {
      // Happy path: server has /v1/alerts — typed JSON, classified
      // server-side. Single source of truth shared with `selfdefctl
      // alerts` + the doctor health check.
      let classification;
      try {
        classification = await get("/v1/alerts");
        // Sanity-check the shape: older daemons might return something
        // unexpected on this URL (e.g. 404 HTML). Fall through to the
        // /metrics fallback rather than rendering garbage.
        if (!classification || !Array.isArray(classification.alerts)) {
          throw new Error("malformed /v1/alerts response");
        }
      } catch (apiErr) {
        // Fallback: classify client-side from /metrics. Works against
        // any daemon that exposes the watchdog gauges.
        classification = await fallbackClassifyFromMetrics();
      }
      renderAlertRows(classification);
    } catch (e) {
      setEmpty(ul, `error: ${e.message}`);
      meta.textContent = "";
      aggEl.textContent = "ERR";
      aggEl.className = "fa-aggregate fa-fail";
    }
  }

  /// MS010 + SDD-018: render the host hardware capability summary
  /// and sain-01 reference-platform match verdict. Consumes
  /// /v1/hardware/capabilities + /v1/hardware/sain01. The full
  /// snapshot at /v1/hardware is intentionally NOT rendered in this
  /// panel — it's verbose (PCIe devices, thermals, GPU details) and
  /// belongs in a dedicated drill-down page if/when operators ask.
  async function refreshHardware() {
    const ul = document.getElementById("hardware-rows");
    const meta = document.getElementById("hardware-meta");
    const badge = document.getElementById("hardware-sain01-badge");
    try {
      const [caps, sain01Env] = await Promise.all([
        get("/v1/hardware/capabilities"),
        get("/v1/hardware/sain01"),
      ]);
      const sain01 = sain01Env.sain01;
      const verdict = sain01.overall;
      const verdictClass = verdict === "Match" ? "fa-ok"
                         : verdict === "NearMatch" ? "fa-degraded"
                         : verdict === "NoMatch" ? "fa-fail"
                         : "fa-unknown";

      // Build the per-row inventory. Capability flags are booleans;
      // we render OK/NO/UNKNOWN states matching the alerts panel's
      // visual language so operators read both panels the same way.
      const checks = [
        { name: "CPU AVX-512 VNNI",        ms: "MS010", ok: sain01.cpu_avx512_vnni },
        { name: "CPU AVX-512 BF16",        ms: "MS010", ok: sain01.cpu_avx512_bf16 },
        { name: "Memory ≥ 256 GB",         ms: "MS010", ok: sain01.memory_at_least_256gb },
        { name: "GPU count ≥ 2",           ms: "MS010", ok: sain01.gpu_count_at_least_2 },
        { name: "PCIe dual x8 (Gen4+)",    ms: "MS010", ok: sain01.pcie_dual_x8_present },
      ];
      // Motherboard match is Option<bool> from the server — null
      // means DMI unreadable (operator can't confirm — neutral).
      if (sain01.motherboard_proart_x870e === true) {
        checks.push({ name: "Motherboard ProArt X870E", ms: "MS010", ok: true });
      } else if (sain01.motherboard_proart_x870e === false) {
        checks.push({ name: "Motherboard ProArt X870E", ms: "MS010", ok: false });
      } else {
        checks.push({ name: "Motherboard ProArt X870E (DMI unreadable)", ms: "MS010", ok: null });
      }

      const lis = checks.map(c => {
        const state = c.ok === true ? "ok" : c.ok === false ? "fail" : "unknown";
        const cssClass = state === "ok" ? "fa-ok"
                       : state === "fail" ? "fa-fail"
                       : "fa-unknown";
        const label = state === "ok" ? "YES" : state === "fail" ? "NO" : "?";
        return `<li class="fa-row">
          <span class="fa-aggregate ${cssClass}">${label}</span>
          <code>${c.name}</code>
          <small>${c.ms}</small>
        </li>`;
      });
      ul.innerHTML = lis.join("");

      // Meta line: surface the snapshot timestamp + key capability
      // descriptors (operator wants one-glance sufficiency).
      const metaBits = [];
      if (caps && typeof caps === "object") {
        if (caps.has_avx512) metaBits.push("AVX-512");
        if (caps.has_avx512_vnni) metaBits.push("VNNI");
        if (caps.has_avx512_bf16) metaBits.push("BF16");
        if (caps.dual_x8_pcie) metaBits.push("dual-x8 PCIe");
        if (caps.gpu_count) metaBits.push(`${caps.gpu_count} GPU${caps.gpu_count === 1 ? "" : "s"}`);
        if (caps.memory_tier) metaBits.push(`mem tier: ${caps.memory_tier}`);
      }
      meta.textContent = metaBits.length
        ? `capabilities: ${metaBits.join(" · ")}`
        : "capabilities: (none detected)";

      badge.textContent = String(verdict).toUpperCase();
      badge.className = "fa-aggregate " + verdictClass;
    } catch (e) {
      setEmpty(ul, `error: ${e.message}`);
      meta.textContent = "";
      badge.textContent = "ERR";
      badge.className = "fa-aggregate fa-fail";
    }
  }

  /// MS011 Z-7: render the network state surface — internet
  /// reachability, DNS resolution, cloudflared / tailscale / traefik
  /// systemd unit liveness. The /v1/network endpoint probes each on
  /// every request.
  async function refreshNetwork() {
    const ul = document.getElementById("network-rows");
    const meta = document.getElementById("network-meta");
    const aggEl = document.getElementById("network-aggregate");
    try {
      const resp = await get("/v1/network");
      const worst = resp.worst;
      const aggClass = worst === "green" ? "fa-ok"
                     : worst === "yellow" ? "fa-degraded"
                     : worst === "red" ? "fa-fail"
                     : "fa-unknown";
      const lis = resp.components.map(c => {
        const css = c.state === "green" ? "fa-ok"
                  : c.state === "yellow" ? "fa-degraded"
                  : c.state === "red" ? "fa-fail"
                  : "fa-unknown";
        return `<li class="fa-row">
          <span class="fa-aggregate ${css}">${c.state.toUpperCase()}</span>
          <code>${c.name}</code>
          <small>${c.detail}</small>
        </li>`;
      });
      ul.innerHTML = lis.join("");
      meta.textContent = `${resp.components.length} components · worst = ${worst.toUpperCase()}`;
      aggEl.textContent = worst.toUpperCase();
      aggEl.className = "fa-aggregate " + aggClass;
    } catch (e) {
      setEmpty(ul, `error: ${e.message}`);
      meta.textContent = "";
      aggEl.textContent = "ERR";
      aggEl.className = "fa-aggregate fa-fail";
    }
  }

  /// MS011 Z-10: render the storage state surface — per-mount usage
  /// + selfdef-managed log dirs. Operator-relevant when the daemon's
  /// ZFS audit logs or perimeter Sigkill verdicts are growing the
  /// /var/log/selfdef directory faster than logrotate clears it.
  async function refreshStorage() {
    const ul = document.getElementById("storage-rows");
    const meta = document.getElementById("storage-meta");
    const aggEl = document.getElementById("storage-aggregate");
    try {
      const resp = await get("/v1/storage");
      const worst = resp.worst;
      const aggClass = worst === "green" ? "fa-ok"
                     : worst === "yellow" ? "fa-degraded"
                     : worst === "red" ? "fa-fail"
                     : "fa-unknown";
      // Helper to format bytes as a human-readable string.
      const fmtBytes = (b) => {
        if (b >= 1024 * 1024 * 1024 * 1024) return (b / (1024 ** 4)).toFixed(1) + " TiB";
        if (b >= 1024 * 1024 * 1024) return (b / (1024 ** 3)).toFixed(1) + " GiB";
        if (b >= 1024 * 1024) return (b / (1024 ** 2)).toFixed(1) + " MiB";
        if (b >= 1024) return (b / 1024).toFixed(1) + " KiB";
        return String(b) + " B";
      };
      const mountRows = resp.mounts.map(m => {
        const css = m.state === "green" ? "fa-ok"
                  : m.state === "yellow" ? "fa-degraded"
                  : "fa-fail";
        return `<li class="fa-row">
          <span class="fa-aggregate ${css}">${m.used_pct}%</span>
          <code>${m.mountpoint}</code>
          <small>${m.source} · ${m.fstype} · ${fmtBytes(m.used_bytes)} / ${fmtBytes(m.size_bytes)}</small>
        </li>`;
      });
      const logRows = resp.log_dirs.map(d => {
        const css = d.exists ? "fa-ok" : "fa-unknown";
        const label = d.exists ? "LOG" : "—";
        return `<li class="fa-row">
          <span class="fa-aggregate ${css}">${label}</span>
          <code>${d.path}</code>
          <small>${d.exists ? `${fmtBytes(d.bytes)} · ${d.files} files` : "(directory not present)"}</small>
        </li>`;
      });
      ul.innerHTML = [...mountRows, ...logRows].join("");
      meta.textContent = `${resp.mounts.length} mount(s) · ${resp.log_dirs.length} log dir(s) · worst = ${worst.toUpperCase()}`;
      aggEl.textContent = worst.toUpperCase();
      aggEl.className = "fa-aggregate " + aggClass;
    } catch (e) {
      setEmpty(ul, `error: ${e.message}`);
      meta.textContent = "";
      aggEl.textContent = "ERR";
      aggEl.className = "fa-aggregate fa-fail";
    }
  }

  /// MS011 Z-9: render the software RAID state surface. On hosts
  /// without /proc/mdstat (no Linux MD support), the panel shows a
  /// single "no software RAID configured" row in fa-unknown state.
  async function refreshRaid() {
    const ul = document.getElementById("raid-rows");
    const meta = document.getElementById("raid-meta");
    const aggEl = document.getElementById("raid-aggregate");
    try {
      const resp = await get("/v1/raid");
      const worst = resp.worst;
      const aggClass = worst === "green" ? "fa-ok"
                     : worst === "yellow" ? "fa-degraded"
                     : worst === "red" ? "fa-fail"
                     : "fa-unknown";
      if (!resp.mdstat_present) {
        ul.innerHTML = `<li class="fa-row">
          <span class="fa-aggregate fa-unknown">N/A</span>
          <code>/proc/mdstat</code>
          <small>no software RAID configured on this host</small>
        </li>`;
        meta.textContent = "0 array(s) · mdstat absent";
        aggEl.textContent = "N/A";
        aggEl.className = "fa-aggregate fa-unknown";
        return;
      }
      if (resp.arrays.length === 0) {
        ul.innerHTML = `<li class="empty">no arrays in /proc/mdstat</li>`;
        meta.textContent = "0 array(s)";
        aggEl.textContent = "OK";
        aggEl.className = "fa-aggregate fa-ok";
        return;
      }
      const lis = resp.arrays.map(a => {
        const css = a.state === "green" ? "fa-ok"
                  : a.state === "yellow" ? "fa-degraded"
                  : "fa-fail";
        const memList = a.members.join(" ");
        return `<li class="fa-row">
          <span class="fa-aggregate ${css}">${a.health || "?"}</span>
          <code>${a.name}</code>
          <small>${a.level} · ${memList}</small>
        </li>`;
      });
      ul.innerHTML = lis.join("");
      meta.textContent = `${resp.arrays.length} array(s) · worst = ${worst.toUpperCase()}`;
      aggEl.textContent = worst.toUpperCase();
      aggEl.className = "fa-aggregate " + aggClass;
    } catch (e) {
      setEmpty(ul, `error: ${e.message}`);
      meta.textContent = "";
      aggEl.textContent = "ERR";
      aggEl.className = "fa-aggregate fa-fail";
    }
  }

  /// MS011 Z-5: render per-GPU power-draw state vs the operator-
  /// authored gpu-policy.toml. Shows current draw + expected limit +
  /// tolerance + classification per row.
  async function refreshGpu() {
    const ul = document.getElementById("gpu-rows");
    const meta = document.getElementById("gpu-meta");
    const aggEl = document.getElementById("gpu-aggregate");
    try {
      const resp = await get("/v1/gpu");
      const worst = resp.worst;
      const aggClass = worst === "green" ? "fa-ok"
                     : worst === "yellow" ? "fa-degraded"
                     : worst === "red" ? "fa-fail"
                     : "fa-unknown";
      if (resp.gpus.length === 0) {
        ul.innerHTML = `<li class="fa-row">
          <span class="fa-aggregate fa-unknown">N/A</span>
          <code>nvidia-smi</code>
          <small>no NVIDIA GPUs detected (nvidia-smi unavailable or zero devices)</small>
        </li>`;
        meta.textContent = `0 GPUs · policy: ${resp.policy_path}${resp.policy_present ? "" : " (absent)"}`;
        aggEl.textContent = "N/A";
        aggEl.className = "fa-aggregate fa-unknown";
        return;
      }
      const lis = resp.gpus.map(g => {
        const css = g.state === "green" ? "fa-ok"
                  : g.state === "yellow" ? "fa-degraded"
                  : g.state === "red" ? "fa-fail"
                  : "fa-unknown";
        const watts = g.current_watts === null || g.current_watts === undefined
                    ? "—"
                    : `${g.current_watts} W`;
        return `<li class="fa-row">
          <span class="fa-aggregate ${css}">${watts}</span>
          <code>gpu${g.index}</code>
          <small>${g.detail}</small>
        </li>`;
      });
      ul.innerHTML = lis.join("");
      meta.textContent = `${resp.gpus.length} GPU(s) · policy: ${resp.policy_path}${resp.policy_present ? "" : " (absent — set expected_power_limit_watts to enable deviance warnings)"} · worst = ${worst.toUpperCase()}`;
      aggEl.textContent = worst.toUpperCase();
      aggEl.className = "fa-aggregate " + aggClass;
    } catch (e) {
      setEmpty(ul, `error: ${e.message}`);
      meta.textContent = "";
      aggEl.textContent = "ERR";
      aggEl.className = "fa-aggregate fa-fail";
    }
  }

  /// MS011 Z-4: render the named CPU mode classification with the
  /// underlying scaling_governor + SMT state surfaced so operators
  /// can confirm. Modes: ultra-low-power, balanced, sustained-burst,
  /// peak-inference, custom.
  async function refreshCpu() {
    const ul = document.getElementById("cpu-rows");
    const meta = document.getElementById("cpu-meta");
    const aggEl = document.getElementById("cpu-aggregate");
    try {
      const resp = await get("/v1/cpu");
      const mode = resp.mode;
      // No green/yellow/red here — modes are operator choice, not
      // health. We render the mode as an info aggregate using the
      // unknown class for "custom" and ok for any named mode.
      const aggClass = mode === "custom" ? "fa-unknown" : "fa-ok";
      // Distinct governor values, joined for the meta line.
      const uniqGovs = [...new Set(resp.governors)];
      const rows = [
        { label: "MODE",       code: mode,                       detail: "named mode classification per SDD-026 Z-4", css: aggClass },
        { label: "GOVERNOR",   code: uniqGovs.join(" + ") || "—", detail: `${resp.governors.length} per-cpu governor file(s) read · cpufreq_present=${resp.cpufreq_present}`, css: "fa-ok" },
        { label: resp.smt_enabled ? "SMT ON" : "SMT OFF", code: "smt", detail: `smt_present=${resp.smt_present}`, css: "fa-ok" },
      ];
      ul.innerHTML = rows.map(r => `<li class="fa-row">
        <span class="fa-aggregate ${r.css}">${r.label}</span>
        <code>${r.code}</code>
        <small>${r.detail}</small>
      </li>`).join("");
      meta.textContent = `mode = ${mode.toUpperCase()} · ${resp.governors.length} cpu(s)`;
      aggEl.textContent = mode.toUpperCase();
      aggEl.className = "fa-aggregate " + aggClass;
    } catch (e) {
      setEmpty(ul, `error: ${e.message}`);
      meta.textContent = "";
      aggEl.textContent = "ERR";
      aggEl.className = "fa-aggregate fa-fail";
    }
  }

  /// MS011 Z-3: render the flex-profile live state. When no state
  /// file exists on disk the panel shows a guidance row pointing at
  /// the default path; when state exists, surface the baseline +
  /// active-delta-count + revert-count + the latest delta.
  async function refreshFlexProfile() {
    const ul = document.getElementById("flex-profile-rows");
    const meta = document.getElementById("flex-profile-meta");
    const aggEl = document.getElementById("flex-profile-aggregate");
    try {
      const resp = await get("/v1/flex-profile");
      if (!resp.state_present || !resp.state) {
        ul.innerHTML = `<li class="fa-row">
          <span class="fa-aggregate fa-unknown">EMPTY</span>
          <code>${resp.state_path}</code>
          <small>no flex-profile persisted yet — operator hasn't applied any deltas</small>
        </li>`;
        meta.textContent = `0 deltas · 0 reverts · state path: ${resp.state_path}`;
        aggEl.textContent = "EMPTY";
        aggEl.className = "fa-aggregate fa-unknown";
        return;
      }
      const s = resp.state;
      const deltaCount = (s.deltas || []).length;
      const revertCount = (s.history || []).length;
      const aggClass = deltaCount > 0 ? "fa-ok" : "fa-unknown";
      const rows = [
        { label: "BASELINE", code: s.baseline, detail: `schema_version=${s.schema_version}`, css: "fa-ok" },
        { label: `${deltaCount} ACTIVE`, code: "deltas", detail: deltaCount > 0
            ? `latest: id=${s.deltas[s.deltas.length-1].id} by ${s.deltas[s.deltas.length-1].actor}`
            : "(no active deltas)", css: deltaCount > 0 ? "fa-ok" : "fa-unknown" },
        { label: `${revertCount} HISTORY`, code: "reverts", detail: revertCount > 0
            ? `latest revert: ${s.history[s.history.length-1].original.id} by ${s.history[s.history.length-1].actor}`
            : "(no reverts)", css: "fa-ok" },
      ];
      ul.innerHTML = rows.map(r => `<li class="fa-row">
        <span class="fa-aggregate ${r.css}">${r.label}</span>
        <code>${r.code}</code>
        <small>${r.detail}</small>
      </li>`).join("");
      meta.textContent = `baseline = ${s.baseline} · ${deltaCount} deltas · ${revertCount} reverts`;
      aggEl.textContent = deltaCount > 0 ? "ACTIVE" : "BASELINE";
      aggEl.className = "fa-aggregate " + aggClass;
    } catch (e) {
      setEmpty(ul, `error: ${e.message}`);
      meta.textContent = "";
      aggEl.textContent = "ERR";
      aggEl.className = "fa-aggregate fa-fail";
    }
  }

  /// MS011 Z-2: render the inference-backend probe state. Shows
  /// llama.cpp / vllm / bitnet.cpp / unsloth installed-state +
  /// captured version. Operator can spot at a glance which backends
  /// are missing from this host vs the others in the fleet.
  async function refreshInferenceBackends() {
    const ul = document.getElementById("inference-backends-rows");
    const meta = document.getElementById("inference-backends-meta");
    const aggEl = document.getElementById("inference-backends-aggregate");
    try {
      const resp = await get("/v1/inference-backends");
      const backends = resp.backends || [];
      const installedCount = backends.filter(b => b.installed).length;
      const worst = resp.worst;
      const aggClass = worst === "green" ? "fa-ok"
                     : worst === "yellow" ? "fa-degraded"
                     : "fa-unknown";
      ul.innerHTML = backends.map(b => {
        const css = b.state === "green" ? "fa-ok"
                  : b.state === "yellow" ? "fa-degraded"
                  : "fa-unknown";
        const label = b.installed
          ? (b.version ? b.version.slice(0, 24) : "INSTALLED")
          : "MISSING";
        return `<li class="fa-row">
          <span class="fa-aggregate ${css}">${label}</span>
          <code>${b.name}</code>
          <small>binary: ${b.binary} · state: ${b.state}</small>
        </li>`;
      }).join("");
      meta.textContent = `${installedCount}/${backends.length} installed · worst = ${worst.toUpperCase()}`;
      aggEl.textContent = `${installedCount}/${backends.length}`;
      aggEl.className = "fa-aggregate " + aggClass;
    } catch (e) {
      setEmpty(ul, `error: ${e.message}`);
      meta.textContent = "";
      aggEl.textContent = "ERR";
      aggEl.className = "fa-aggregate fa-fail";
    }
  }

  /// MS009: render per-watchdog audit-chain integrity. Each row
  /// shows watchdog name + events_verified count + error detail
  /// when the chain broke. Operator-actionable: the error string
  /// carries the line number where the chain broke (use the matching
  /// info-hub *-audit-log-corruption.md runbook to recover).
  async function refreshAuditChains() {
    const ul = document.getElementById("audit-chains-rows");
    const meta = document.getElementById("audit-chains-meta");
    const aggEl = document.getElementById("audit-chains-aggregate");
    try {
      const resp = await get("/v1/audit-chains");
      const worst = resp.worst;
      const aggClass = worst === "ok" ? "fa-ok"
                     : worst === "critical" ? "fa-fail"
                     : "fa-unknown";
      const lis = resp.chains.map(c => {
        const css = c.ok ? "fa-ok" : "fa-fail";
        const label = c.ok ? "OK" : "BROKEN";
        const detail = c.ok
          ? `${c.events_verified} events verified · ${c.path}`
          : `${c.error || "chain broken"} · ${c.path}`;
        return `<li class="fa-row">
          <span class="fa-aggregate ${css}">${label}</span>
          <code>${c.watchdog}</code>
          <small>${detail}</small>
        </li>`;
      });
      ul.innerHTML = lis.join("");
      meta.textContent = `${resp.chains.length} chain(s) · worst = ${worst.toUpperCase()}`;
      aggEl.textContent = worst.toUpperCase();
      aggEl.className = "fa-aggregate " + aggClass;
    } catch (e) {
      setEmpty(ul, `error: ${e.message}`);
      meta.textContent = "";
      aggEl.textContent = "ERR";
      aggEl.className = "fa-aggregate fa-fail";
    }
  }

  /// MS011 Z-6: render the composite health aggregate at the top
  /// of the dashboard. Single panel for "is everything OK?".
  async function refreshHealth() {
    const ul = document.getElementById("health-rows");
    const meta = document.getElementById("health-meta");
    const aggEl = document.getElementById("health-aggregate");
    try {
      const resp = await get("/v1/health");
      const worst = resp.worst;
      const aggClass = worst === "ok" ? "fa-ok"
                     : worst === "warn" ? "fa-degraded"
                     : worst === "critical" ? "fa-fail"
                     : "fa-unknown";
      const lis = resp.components.map(c => {
        const css = c.state === "ok" ? "fa-ok"
                  : c.state === "warn" ? "fa-degraded"
                  : c.state === "critical" ? "fa-fail"
                  : "fa-unknown";
        return `<li class="fa-row">
          <span class="fa-aggregate ${css}">${c.state.toUpperCase()}</span>
          <code>${c.name}</code>
          <small>${c.detail}</small>
        </li>`;
      });
      ul.innerHTML = lis.join("");
      meta.textContent = `${resp.components.length} components · worst = ${worst.toUpperCase()}`;
      aggEl.textContent = worst.toUpperCase();
      aggEl.className = "fa-aggregate " + aggClass;
    } catch (e) {
      setEmpty(ul, `error: ${e.message}`);
      meta.textContent = "";
      aggEl.textContent = "ERR";
      aggEl.className = "fa-aggregate fa-fail";
    }
  }

  async function refreshStatus() {
    const conn = document.getElementById("conn");
    try {
      const s = await get("/status");
      document.querySelector(".host").textContent = s.host_tag;
      document.getElementById("event-count").textContent = s.event_count.toLocaleString();
      document.getElementById("crate-version").textContent = s.crate_version;
      document.getElementById("schema-version").textContent = s.schema_version;
      conn.textContent = "online";
      conn.classList.add("online");
    } catch (e) {
      conn.textContent = `offline: ${e.message}`;
      conn.classList.remove("online");
    }
  }

  // Live tail. EventSource doesn't support custom headers natively, so
  // the bearer-token path uses ?token= in the URL when present. UNIX-
  // socket deployments don't need a token at all.
  let stream = null;
  function startStream() {
    if (stream) return;
    const qs = token ? `?token=${encodeURIComponent(token)}` : "";
    stream = new EventSource(`${apiBase}/events/stream${qs}`);
    stream.onmessage = (e) => {
      try {
        const ev = JSON.parse(e.data);
        const ul = document.getElementById("events");
        if (ul.firstElementChild && ul.firstElementChild.classList.contains("empty")) {
          ul.innerHTML = "";
        }
        ul.prepend(renderEvent(ev));
        // Keep the list bounded so the page doesn't grow without limit.
        while (ul.children.length > 200) {
          ul.removeChild(ul.lastChild);
        }
      } catch (err) {
        console.warn("sse parse failed", err);
      }
    };
    stream.onerror = () => {
      // EventSource auto-reconnects; we just surface the visual state.
      document.getElementById("toggle-stream").textContent = "start live stream";
    };
    document.getElementById("toggle-stream").textContent = "stop live stream";
  }

  function stopStream() {
    if (stream) {
      stream.close();
      stream = null;
    }
    document.getElementById("toggle-stream").textContent = "start live stream";
  }

  // -------------------- Control section

  function setResult(text, kind = "info") {
    const el = document.getElementById("control-result");
    if (!el) return;
    el.textContent = text;
    el.dataset.kind = kind;
  }

  async function refreshActionList() {
    const select = document.getElementById("action-name");
    if (!select) return;
    try {
      const res = await get("/actions");
      const actions = Array.isArray(res?.actions) ? res.actions : [];
      // Preserve any currently-selected value across refreshes.
      const prev = select.value;
      select.innerHTML = "";
      if (actions.length === 0) {
        const opt = document.createElement("option");
        opt.value = "";
        opt.textContent = "(none registered)";
        opt.disabled = true;
        select.appendChild(opt);
        return;
      }
      for (const name of actions) {
        const opt = document.createElement("option");
        opt.value = name;
        opt.textContent = name;
        select.appendChild(opt);
      }
      if (actions.includes(prev)) select.value = prev;
    } catch (e) {
      const opt = document.createElement("option");
      opt.value = "";
      opt.textContent = `error: ${e.message}`;
      opt.disabled = true;
      select.innerHTML = "";
      select.appendChild(opt);
    }
  }

  async function reloadRules() {
    setResult("calling /rules/reload …");
    try {
      const r = await post("/rules/reload");
      setResult(`rules reloaded: ${r.rules_loaded}`, "ok");
    } catch (e) {
      setResult(e.message, "error");
    }
  }

  async function firePanic() {
    const confirmEl = document.getElementById("panic-confirm");
    const confirm = (confirmEl?.value || "").trim();
    if (!confirm) {
      setResult("panic requires the host tag in the confirm box", "error");
      return;
    }
    if (!window.confirm(`Engage panic mode on '${confirm}'?`)) {
      return;
    }
    setResult("calling /panic …");
    try {
      const r = await post("/panic", { confirm });
      setResult(
        `panic dispatched on ${r.host_tag} (dispatched=${r.dispatched})`,
        "ok",
      );
    } catch (e) {
      setResult(e.message, "error");
    }
  }

  async function runAction() {
    const select = document.getElementById("action-name");
    const idEl = document.getElementById("action-event-id");
    const name = select?.value || "";
    if (!name) {
      setResult("pick an action first", "error");
      return;
    }

    let eventId = (idEl?.value || "").trim();
    // Convenience: when the operator doesn't type an id, run against
    // the most recent finding from /findings.
    if (!eventId) {
      try {
        const recent = await get("/findings?n=1");
        if (!Array.isArray(recent) || recent.length === 0) {
          setResult("no recent finding to run against; specify an event id", "error");
          return;
        }
        eventId = recent[0].id;
        if (idEl) idEl.value = eventId;
      } catch (e) {
        setResult(`could not look up latest finding: ${e.message}`, "error");
        return;
      }
    }
    setResult(`calling /actions/${name}/run for ${eventId} …`);
    try {
      const r = await post(`/actions/${encodeURIComponent(name)}/run`, {
        event_id: eventId,
      });
      setResult(`${r.action}: ${r.status} — ${r.notes}`, "ok");
    } catch (e) {
      setResult(e.message, "error");
    }
  }

  document.addEventListener("click", (e) => {
    const r = e.target.closest("[data-refresh]");
    if (r) {
      e.preventDefault();
      refresh(r.dataset.refresh);
      return;
    }
    switch (e.target.id) {
      case "toggle-stream":
        e.preventDefault();
        if (stream) stopStream();
        else startStream();
        break;
      case "btn-reload":
        e.preventDefault();
        reloadRules();
        break;
      case "btn-panic":
        e.preventDefault();
        firePanic();
        break;
      case "btn-action":
        e.preventDefault();
        runAction();
        break;
      default:
        break;
    }
  });

  // MS035 / SDD-044 — IPS capability-token doctrine panel. Read-only
  // schema-discovery surface (issue/revoke stay MS003-signed CLI-only per
  // SDD-044 D-3/D-4); renders the 5 CheckVerdict variants, the token shape
  // and the refusal rules so the operator can see WHAT the IPS enforces.
  async function refreshCapabilityTokens() {
    const ul = document.getElementById("capability-tokens-rows");
    const aggEl = document.getElementById("captok-aggregate");
    const metaEl = document.getElementById("capability-tokens-meta");
    try {
      const body = await get("/v1/capability-tokens");
      const verdicts = body.verdicts || [];
      const tokenShape = body.token_shape || [];
      const refusals = body.refusal_rules || [];
      aggEl.textContent = "DOCTRINE";
      aggEl.className = "fa-aggregate fa-ok";
      metaEl.textContent =
        `${verdicts.length} verdict(s) · token shape ${tokenShape.length} field(s) · ` +
        `${refusals.length} refusal rule(s) · issue/revoke = MS003-signed CLI only`;
      ul.innerHTML = "";
      for (const v of verdicts) {
        const li = document.createElement("li");
        const ok = v.variant === "Ok";
        li.className = ok ? "fa-green" : "fa-yellow";
        const label = document.createElement("span");
        label.className = "fa-gate-label";
        label.textContent = v.variant;
        const badge = document.createElement("span");
        badge.className = `fa-badge fa-${ok ? "green" : "yellow"}`;
        badge.textContent = ok ? "GRANT" : "REFUSE";
        const detail = document.createElement("span");
        detail.className = "fa-detail";
        detail.textContent = v.semantics;
        li.append(label, badge, detail);
        ul.appendChild(li);
      }
      for (const f of tokenShape) {
        const li = document.createElement("li");
        li.className = "fa-gray";
        const label = document.createElement("span");
        label.className = "fa-gate-label";
        label.textContent = "token";
        const detail = document.createElement("span");
        detail.className = "fa-detail";
        detail.textContent = f;
        li.append(label, detail);
        ul.appendChild(li);
      }
      for (const r of refusals) {
        const li = document.createElement("li");
        li.className = "fa-yellow";
        const label = document.createElement("span");
        label.className = "fa-gate-label";
        label.textContent = "refuse-rule";
        const badge = document.createElement("span");
        badge.className = "fa-badge fa-yellow";
        badge.textContent = "RULE";
        const detail = document.createElement("span");
        detail.className = "fa-detail";
        detail.textContent = r;
        li.append(label, badge, detail);
        ul.appendChild(li);
      }
      if (!ul.children.length) {
        ul.innerHTML = '<li class="empty">no capability-token doctrine returned</li>';
      }
    } catch (e) {
      aggEl.textContent = "OFFLINE";
      aggEl.className = "fa-aggregate fa-unknown";
      metaEl.textContent = "daemon offline — " + (e && e.message ? e.message : "fetch failed");
      ul.innerHTML = '<li class="empty">/v1/capability-tokens unavailable</li>';
    }
  }

  // MS042 / SDD-050 — IPS tool-authority gate-pipeline doctrine panel.
  // Read-only schema (the declared-vs-observed tool-policy pipeline contract);
  // renders the ordered gate pipeline + tool ids + refusal rules.
  async function refreshToolAuthority() {
    const ul = document.getElementById("tool-authority-rows");
    const aggEl = document.getElementById("ta-aggregate");
    const metaEl = document.getElementById("tool-authority-meta");
    try {
      const body = await get("/v1/tool-authority");
      const gates = body.gate_pipeline || [];
      const tools = body.tool_ids || [];
      const refusals = body.refusal_rules || [];
      aggEl.textContent = "DOCTRINE";
      aggEl.className = "fa-aggregate fa-ok";
      metaEl.textContent =
        `${gates.length}-stage gate pipeline · ${tools.length} tool id(s) · ` +
        `${(body.execution_modes || []).length} execution mode(s) · ` +
        `${refusals.length} refusal rule(s)`;
      ul.innerHTML = "";
      for (const g of gates) {
        const li = document.createElement("li");
        li.className = "fa-green";
        const label = document.createElement("span");
        label.className = "fa-gate-label";
        label.textContent = `${g.order}. ${g.name}`;
        const badge = document.createElement("span");
        badge.className = "fa-badge fa-green";
        badge.textContent = "GATE";
        const detail = document.createElement("span");
        detail.className = "fa-detail";
        detail.textContent = `${g.crate_name} · ${g.vocabulary}`;
        li.append(label, badge, detail);
        ul.appendChild(li);
      }
      for (const t of tools) {
        const li = document.createElement("li");
        li.className = "fa-gray";
        const label = document.createElement("span");
        label.className = "fa-gate-label";
        label.textContent = t.id;
        const detail = document.createElement("span");
        detail.className = "fa-detail";
        detail.textContent = t.description;
        li.append(label, detail);
        ul.appendChild(li);
      }
      for (const r of refusals) {
        const li = document.createElement("li");
        li.className = "fa-yellow";
        const label = document.createElement("span");
        label.className = "fa-gate-label";
        label.textContent = "refuse-rule";
        const badge = document.createElement("span");
        badge.className = "fa-badge fa-yellow";
        badge.textContent = "RULE";
        const detail = document.createElement("span");
        detail.className = "fa-detail";
        detail.textContent = r;
        li.append(label, badge, detail);
        ul.appendChild(li);
      }
      if (!ul.children.length) {
        ul.innerHTML = '<li class="empty">no tool-authority doctrine returned</li>';
      }
    } catch (e) {
      aggEl.textContent = "OFFLINE";
      aggEl.className = "fa-aggregate fa-unknown";
      metaEl.textContent = "daemon offline — " + (e && e.message ? e.message : "fetch failed");
      ul.innerHTML = '<li class="empty">/v1/tool-authority unavailable</li>';
    }
  }

  // MS041 / SDD-043 — IPS commit-authority durable-change envelope doctrine.
  // Read-only schema; renders the mandatory commit-envelope fields, policy
  // outcomes, high-risk classifier rules and refusal rules.
  async function refreshCommitAuthority() {
    const ul = document.getElementById("commit-authority-rows");
    const aggEl = document.getElementById("ca-aggregate");
    const metaEl = document.getElementById("commit-authority-meta");
    try {
      const body = await get("/v1/commit-authority");
      const fields = body.mandatory_fields || [];
      const outcomes = body.policy_outcomes || [];
      const hiRisk = body.high_risk_classifier_rules || [];
      const refusals = body.refusal_rules || [];
      aggEl.textContent = "DOCTRINE";
      aggEl.className = "fa-aggregate fa-ok";
      metaEl.textContent =
        `${fields.length} mandatory field(s) · ${outcomes.length} policy outcome(s) · ` +
        `${hiRisk.length} high-risk rule(s) · ${refusals.length} refusal rule(s)` +
        (body.doctrine_phrase ? ` · “${body.doctrine_phrase}”` : "");
      ul.innerHTML = "";
      for (const f of fields) {
        const li = document.createElement("li");
        li.className = "fa-green";
        const label = document.createElement("span");
        label.className = "fa-gate-label";
        label.textContent = f.name;
        const badge = document.createElement("span");
        badge.className = "fa-badge fa-green";
        badge.textContent = f.r_row || "FIELD";
        const detail = document.createElement("span");
        detail.className = "fa-detail";
        detail.textContent = f.description;
        li.append(label, badge, detail);
        ul.appendChild(li);
      }
      for (const h of hiRisk) {
        const li = document.createElement("li");
        li.className = "fa-yellow";
        const label = document.createElement("span");
        label.className = "fa-gate-label";
        label.textContent = "high-risk";
        const badge = document.createElement("span");
        badge.className = "fa-badge fa-yellow";
        badge.textContent = "GATE";
        const detail = document.createElement("span");
        detail.className = "fa-detail";
        detail.textContent = h;
        li.append(label, badge, detail);
        ul.appendChild(li);
      }
      for (const r of refusals) {
        const li = document.createElement("li");
        li.className = "fa-yellow";
        const label = document.createElement("span");
        label.className = "fa-gate-label";
        label.textContent = "refuse-rule";
        const badge = document.createElement("span");
        badge.className = "fa-badge fa-yellow";
        badge.textContent = "RULE";
        const detail = document.createElement("span");
        detail.className = "fa-detail";
        detail.textContent = r;
        li.append(label, badge, detail);
        ul.appendChild(li);
      }
      if (!ul.children.length) {
        ul.innerHTML = '<li class="empty">no commit-authority doctrine returned</li>';
      }
    } catch (e) {
      aggEl.textContent = "OFFLINE";
      aggEl.className = "fa-aggregate fa-unknown";
      metaEl.textContent = "daemon offline — " + (e && e.message ? e.message : "fetch failed");
      ul.innerHTML = '<li class="empty">/v1/commit-authority unavailable</li>';
    }
  }

  // MS032 / SDD-047 — IPS sandbox tier ladder doctrine. Read-only schema;
  // renders each tier with its capability allocation (subprocess / network /
  // persistence / host-fs) + the promotion gates.
  async function refreshSandboxTiers() {
    const ul = document.getElementById("sandbox-tiers-rows");
    const aggEl = document.getElementById("st-aggregate");
    const metaEl = document.getElementById("sandbox-tiers-meta");
    const yn = (b) => (b ? "yes" : "no");
    try {
      const body = await get("/v1/sandbox-tiers");
      const tiers = body.tiers || [];
      const gates = body.promotion_gates || [];
      aggEl.textContent = "DOCTRINE";
      aggEl.className = "fa-aggregate fa-ok";
      metaEl.textContent =
        `${tiers.length} tier(s) · ${gates.length} promotion gate(s) · ` +
        `${(body.companion_crates || []).length} companion crate(s)`;
      ul.innerHTML = "";
      for (const t of tiers) {
        const li = document.createElement("li");
        // More capability allowed = higher risk surface → warn; locked-down → green.
        const permissive = t.subprocess_allowed || t.network_allowed;
        li.className = permissive ? "fa-yellow" : "fa-green";
        const label = document.createElement("span");
        label.className = "fa-gate-label";
        label.textContent = `tier ${t.name}`;
        const badge = document.createElement("span");
        badge.className = `fa-badge fa-${permissive ? "yellow" : "green"}`;
        badge.textContent = permissive ? "OPEN" : "LOCKED";
        const detail = document.createElement("span");
        detail.className = "fa-detail";
        detail.textContent =
          `${t.scope} · subprocess:${yn(t.subprocess_allowed)} ` +
          `network:${yn(t.network_allowed)} persistent:${yn(t.persistent_allowed)} ` +
          `host-fs-read:${yn(t.host_fs_readable)}`;
        li.append(label, badge, detail);
        ul.appendChild(li);
      }
      for (const g of gates) {
        const li = document.createElement("li");
        li.className = "fa-gray";
        const label = document.createElement("span");
        label.className = "fa-gate-label";
        label.textContent = "promote";
        const detail = document.createElement("span");
        detail.className = "fa-detail";
        detail.textContent = `${g.name}: ${g.semantics}`;
        li.append(label, detail);
        ul.appendChild(li);
      }
      if (!ul.children.length) {
        ul.innerHTML = '<li class="empty">no sandbox-tier doctrine returned</li>';
      }
    } catch (e) {
      aggEl.textContent = "OFFLINE";
      aggEl.className = "fa-aggregate fa-unknown";
      metaEl.textContent = "daemon offline — " + (e && e.message ? e.message : "fetch failed");
      ul.innerHTML = '<li class="empty">/v1/sandbox-tiers unavailable</li>';
    }
  }

  // MS037 / SDD-045 — IPS explicit-exchange filesystem-boundary doctrine.
  // Read-only schema; renders the exchange directories (path/direction/source),
  // the import pipeline, and the application predicates.
  async function refreshFilesystemBoundary() {
    const ul = document.getElementById("filesystem-boundary-rows");
    const aggEl = document.getElementById("fsb-aggregate");
    const metaEl = document.getElementById("filesystem-boundary-meta");
    try {
      const body = await get("/v1/filesystem-boundary");
      const dirs = body.exchange_dirs || [];
      const pipeline = body.import_pipeline || [];
      const predicates = body.application_predicates || [];
      aggEl.textContent = "DOCTRINE";
      aggEl.className = "fa-aggregate fa-ok";
      metaEl.textContent =
        `${dirs.length} exchange dir(s) · ${pipeline.length}-step import pipeline · ` +
        `${predicates.length} application predicate(s) · ` +
        `${(body.patch_schema_fields || []).length} patch field(s)`;
      ul.innerHTML = "";
      for (const d of dirs) {
        const li = document.createElement("li");
        li.className = "fa-green";
        const label = document.createElement("span");
        label.className = "fa-gate-label";
        label.textContent = "dir";
        const badge = document.createElement("span");
        badge.className = "fa-badge fa-green";
        badge.textContent = (d.direction || "").toUpperCase() || "DIR";
        const detail = document.createElement("span");
        detail.className = "fa-detail";
        detail.textContent = `${d.path} · src=${d.source_id}`;
        li.append(label, badge, detail);
        ul.appendChild(li);
      }
      let i = 1;
      for (const step of pipeline) {
        const li = document.createElement("li");
        li.className = "fa-gray";
        const label = document.createElement("span");
        label.className = "fa-gate-label";
        label.textContent = `step ${i++}`;
        const detail = document.createElement("span");
        detail.className = "fa-detail";
        detail.textContent = step;
        li.append(label, detail);
        ul.appendChild(li);
      }
      for (const p of predicates) {
        const li = document.createElement("li");
        li.className = "fa-yellow";
        const label = document.createElement("span");
        label.className = "fa-gate-label";
        label.textContent = "predicate";
        const badge = document.createElement("span");
        badge.className = "fa-badge fa-yellow";
        badge.textContent = "GATE";
        const detail = document.createElement("span");
        detail.className = "fa-detail";
        detail.textContent = p;
        li.append(label, badge, detail);
        ul.appendChild(li);
      }
      if (!ul.children.length) {
        ul.innerHTML = '<li class="empty">no filesystem-boundary doctrine returned</li>';
      }
    } catch (e) {
      aggEl.textContent = "OFFLINE";
      aggEl.className = "fa-aggregate fa-unknown";
      metaEl.textContent = "daemon offline — " + (e && e.message ? e.message : "fetch failed");
      ul.innerHTML = '<li class="empty">/v1/filesystem-boundary unavailable</li>';
    }
  }

  // MS038 / SDD-046 — IPS network-egress boundary profile ladder doctrine.
  // Read-only schema; renders each network profile (scope + bits) + the
  // cross-cycle bindings.
  async function refreshNetworkBoundary() {
    const ul = document.getElementById("network-boundary-rows");
    const aggEl = document.getElementById("nb-aggregate");
    const metaEl = document.getElementById("network-boundary-meta");
    try {
      const body = await get("/v1/network-boundary");
      const profiles = body.profiles || [];
      const bindings = body.cross_cycle_bindings || [];
      aggEl.textContent = "DOCTRINE";
      aggEl.className = "fa-aggregate fa-ok";
      metaEl.textContent =
        `${profiles.length} egress profile(s) · ${bindings.length} cross-cycle binding(s)`;
      ul.innerHTML = "";
      for (const p of profiles) {
        const li = document.createElement("li");
        // Wider scope = more egress allowed = higher risk surface.
        const open = /all|any|unrestricted|full/i.test(p.scope || "");
        li.className = open ? "fa-yellow" : "fa-green";
        const label = document.createElement("span");
        label.className = "fa-gate-label";
        label.textContent = p.name;
        const badge = document.createElement("span");
        badge.className = `fa-badge fa-${open ? "yellow" : "green"}`;
        badge.textContent = `bits ${p.bits}`;
        const detail = document.createElement("span");
        detail.className = "fa-detail";
        detail.textContent = p.scope;
        li.append(label, badge, detail);
        ul.appendChild(li);
      }
      for (const b of bindings) {
        const li = document.createElement("li");
        li.className = "fa-gray";
        const label = document.createElement("span");
        label.className = "fa-gate-label";
        label.textContent = "binding";
        const detail = document.createElement("span");
        detail.className = "fa-detail";
        detail.textContent = b;
        li.append(label, detail);
        ul.appendChild(li);
      }
      if (!ul.children.length) {
        ul.innerHTML = '<li class="empty">no network-boundary doctrine returned</li>';
      }
    } catch (e) {
      aggEl.textContent = "OFFLINE";
      aggEl.className = "fa-aggregate fa-unknown";
      metaEl.textContent = "daemon offline — " + (e && e.message ? e.message : "fetch failed");
      ul.innerHTML = '<li class="empty">/v1/network-boundary unavailable</li>';
    }
  }

  // MS034 / SDD-048 — IPS inter-agent communication-boundary doctrine.
  // Read-only schema; renders the transports, the message types
  // (kind/direction/content) and the proposal→commit pipeline.
  async function refreshCommunicationBoundary() {
    const ul = document.getElementById("communication-boundary-rows");
    const aggEl = document.getElementById("cb-aggregate");
    const metaEl = document.getElementById("communication-boundary-meta");
    try {
      const body = await get("/v1/communication-boundary");
      const transports = body.transports || [];
      const messages = body.message_types || [];
      const flow = body.proposal_to_commit || [];
      aggEl.textContent = "DOCTRINE";
      aggEl.className = "fa-aggregate fa-ok";
      metaEl.textContent =
        `${transports.length} transport(s) · ${messages.length} message type(s) · ` +
        `${flow.length}-step proposal→commit · ${(body.doctrines || []).length} doctrine(s)`;
      ul.innerHTML = "";
      for (const t of transports) {
        const li = document.createElement("li");
        li.className = "fa-green";
        const label = document.createElement("span");
        label.className = "fa-gate-label";
        label.textContent = t.name;
        const badge = document.createElement("span");
        badge.className = "fa-badge fa-green";
        badge.textContent = "TRANSPORT";
        const detail = document.createElement("span");
        detail.className = "fa-detail";
        detail.textContent = t.scope;
        li.append(label, badge, detail);
        ul.appendChild(li);
      }
      for (const m of messages) {
        const li = document.createElement("li");
        li.className = "fa-gray";
        const label = document.createElement("span");
        label.className = "fa-gate-label";
        label.textContent = m.kind;
        const badge = document.createElement("span");
        badge.className = "fa-badge fa-gray";
        badge.textContent = (m.direction || "").toUpperCase() || "MSG";
        const detail = document.createElement("span");
        detail.className = "fa-detail";
        detail.textContent = m.content;
        li.append(label, badge, detail);
        ul.appendChild(li);
      }
      let i = 1;
      for (const step of flow) {
        const li = document.createElement("li");
        li.className = "fa-green";
        const label = document.createElement("span");
        label.className = "fa-gate-label";
        label.textContent = `flow ${i++}`;
        const detail = document.createElement("span");
        detail.className = "fa-detail";
        detail.textContent = step;
        li.append(label, detail);
        ul.appendChild(li);
      }
      if (!ul.children.length) {
        ul.innerHTML = '<li class="empty">no communication-boundary doctrine returned</li>';
      }
    } catch (e) {
      aggEl.textContent = "OFFLINE";
      aggEl.className = "fa-aggregate fa-unknown";
      metaEl.textContent = "daemon offline — " + (e && e.message ? e.message : "fetch failed");
      ul.innerHTML = '<li class="empty">/v1/communication-boundary unavailable</li>';
    }
  }

  // MS039 + MS040 / SDD-049 — IPS authority-model doctrine (the capstone of
  // the authority group). Read-only schema; renders the L-levels, the trust
  // Rings (with level caps), the per-profile authority envelopes, and the
  // transition gates.
  async function refreshAuthority() {
    const ul = document.getElementById("authority-rows");
    const aggEl = document.getElementById("auth-aggregate");
    const metaEl = document.getElementById("authority-meta");
    try {
      const body = await get("/v1/authority");
      const levels = body.authority_levels || [];
      const rings = body.trust_rings || [];
      const envelopes = body.profile_envelopes || [];
      const gates = body.transition_gates || [];
      aggEl.textContent = "DOCTRINE";
      aggEl.className = "fa-aggregate fa-ok";
      metaEl.textContent =
        `${levels.length} authority level(s) · ${rings.length} trust ring(s) · ` +
        `${envelopes.length} profile envelope(s) · ${gates.length} transition gate(s)`;
      ul.innerHTML = "";
      for (const l of levels) {
        const li = document.createElement("li");
        li.className = "fa-green";
        const label = document.createElement("span");
        label.className = "fa-gate-label";
        label.textContent = l.level;
        const badge = document.createElement("span");
        badge.className = "fa-badge fa-green";
        badge.textContent = "LEVEL";
        const detail = document.createElement("span");
        detail.className = "fa-detail";
        detail.textContent = l.scope;
        li.append(label, badge, detail);
        ul.appendChild(li);
      }
      for (const r of rings) {
        const li = document.createElement("li");
        li.className = "fa-green";
        const label = document.createElement("span");
        label.className = "fa-gate-label";
        label.textContent = `ring ${r.ring}`;
        const badge = document.createElement("span");
        badge.className = "fa-badge fa-green";
        badge.textContent = `≤ ${r.level_cap}`;
        const detail = document.createElement("span");
        detail.className = "fa-detail";
        detail.textContent = r.scope;
        li.append(label, badge, detail);
        ul.appendChild(li);
      }
      for (const e of envelopes) {
        const li = document.createElement("li");
        li.className = "fa-yellow";
        const label = document.createElement("span");
        label.className = "fa-gate-label";
        label.textContent = e.profile;
        const badge = document.createElement("span");
        badge.className = "fa-badge fa-yellow";
        badge.textContent = `max ${e.max_level}`;
        const detail = document.createElement("span");
        detail.className = "fa-detail";
        detail.textContent =
          `ring≤${e.ring_cap} · sandbox=${e.sandbox_requirement} · gate=${e.gate}`;
        li.append(label, badge, detail);
        ul.appendChild(li);
      }
      for (const g of gates) {
        const li = document.createElement("li");
        li.className = "fa-gray";
        const label = document.createElement("span");
        label.className = "fa-gate-label";
        label.textContent = "transition";
        const detail = document.createElement("span");
        detail.className = "fa-detail";
        detail.textContent = `${g.name}: ${g.semantics}`;
        li.append(label, detail);
        ul.appendChild(li);
      }
      if (!ul.children.length) {
        ul.innerHTML = '<li class="empty">no authority doctrine returned</li>';
      }
    } catch (e) {
      aggEl.textContent = "OFFLINE";
      aggEl.className = "fa-aggregate fa-unknown";
      metaEl.textContent = "daemon offline — " + (e && e.message ? e.message : "fetch failed");
      ul.innerHTML = '<li class="empty">/v1/authority unavailable</li>';
    }
  }

  // MS033 / SDD-051 — IPS policy-bus dispatch fabric doctrine. Read-only
  // schema; renders the subsystem clusters and the crates wired under each.
  async function refreshPolicy() {
    const ul = document.getElementById("policy-rows");
    const aggEl = document.getElementById("pol-aggregate");
    const metaEl = document.getElementById("policy-meta");
    try {
      const body = await get("/v1/policy");
      const clusters = body.clusters || [];
      aggEl.textContent = "DOCTRINE";
      aggEl.className = "fa-aggregate fa-ok";
      const crateTotal = clusters.reduce((n, c) => n + (c.crates || []).length, 0);
      metaEl.textContent = `${clusters.length} subsystem cluster(s) · ${crateTotal} crate(s) wired`;
      ul.innerHTML = "";
      for (const c of clusters) {
        const li = document.createElement("li");
        li.className = "fa-green";
        const label = document.createElement("span");
        label.className = "fa-gate-label";
        label.textContent = c.name;
        const badge = document.createElement("span");
        badge.className = "fa-badge fa-green";
        badge.textContent = `${(c.crates || []).length} crate(s)`;
        const detail = document.createElement("span");
        detail.className = "fa-detail";
        detail.textContent = (c.crates || []).join(", ");
        li.append(label, badge, detail);
        ul.appendChild(li);
      }
      if (!ul.children.length) {
        ul.innerHTML = '<li class="empty">no policy-bus doctrine returned</li>';
      }
    } catch (e) {
      aggEl.textContent = "OFFLINE";
      aggEl.className = "fa-aggregate fa-unknown";
      metaEl.textContent = "daemon offline — " + (e && e.message ? e.message : "fetch failed");
      ul.innerHTML = '<li class="empty">/v1/policy unavailable</li>';
    }
  }

  // Initial render + periodic poll for status.
  refreshStatus();
  refresh("findings");
  refresh("events");
  refreshFrictionAudit();
  refreshPerimeter();
  refreshGuardian();
  refreshScheduler();
  refreshModules();
  refreshAlerts();
  refreshHardware();
  refreshNetwork();
  refreshStorage();
  refreshRaid();
  refreshGpu();
  refreshCpu();
  refreshFlexProfile();
  refreshInferenceBackends();
  refreshHealth();
  refreshAuditChains();
  refreshCapabilityTokens();
  refreshToolAuthority();
  refreshCommitAuthority();
  refreshSandboxTiers();
  refreshFilesystemBoundary();
  refreshNetworkBoundary();
  refreshCommunicationBoundary();
  refreshAuthority();
  refreshPolicy();
  refreshActionList();

  /// SDD-056 step 4 — gated refresh wrapper. Calls `fn` only when
  /// the named section is NOT tab-hidden AND the operator hasn't
  /// paused refresh globally. Saves probe cost (nvidia-smi / df /
  /// ping / mdstat / etc.) when the operator is looking at a
  /// different tab. `sectionId === null` = always-fire (used for
  /// status header + always-visible-strip panels).
  ///
  /// MS043 UX extension — `gatedInterval` is now a self-rescheduling
  /// setTimeout chain instead of setInterval, so the operator-
  /// selected REFRESH_RATE_FACTOR (Fast/Normal/Slow/Paused) applies
  /// on the NEXT cycle of every panel without needing to clear+
  /// re-arm any handles.
  const REFRESH_RATE_KEY = "selfdef.refreshRate";
  const REFRESH_RATE_FACTORS = {
    fast:    0.25,            // 4x more frequent
    normal:  1.0,             // baseline (default)
    slow:    4.0,             // 4x less frequent
    paused:  Number.POSITIVE_INFINITY, // skip until rate flips back
  };
  function readRefreshRate() {
    const v = localStorage.getItem(REFRESH_RATE_KEY);
    return REFRESH_RATE_FACTORS[v] !== undefined ? v : "normal";
  }
  function writeRefreshRate(name) {
    try { localStorage.setItem(REFRESH_RATE_KEY, name); } catch (_) { /* private mode */ }
    schedulePrefsSync();
  }
  function refreshFactor() {
    return REFRESH_RATE_FACTORS[readRefreshRate()];
  }
  function gatedInterval(fn, baseMs, sectionId) {
    function schedule() {
      const factor = refreshFactor();
      if (factor === Number.POSITIVE_INFINITY) {
        // Paused — re-check in 5 seconds so resume is responsive.
        setTimeout(schedule, 5000);
        return;
      }
      const ms = Math.max(500, Math.round(baseMs * factor));
      setTimeout(() => {
        if (sectionId !== null) {
          const sec = document.getElementById(sectionId);
          if (sec && (sec.classList.contains("tab-hidden")
                   || sec.classList.contains("operator-hidden"))) {
            schedule();
            return;
          }
        }
        try { fn(); } catch (_) { /* never break the chain */ }
        schedule();
      }, ms);
    }
    schedule();
  }

  // status header is part of the always-visible chrome — always fires.
  gatedInterval(refreshStatus, 5000, null);

  // Always-visible strip (composite health + 4 watchdogs + alerts):
  // these refresh regardless of active tab. SDD-056 § Always-visible
  // strip.
  gatedInterval(refreshFrictionAudit, 30000, "friction-audit-section");
  gatedInterval(refreshPerimeter, 15000, "perimeter-section");
  gatedInterval(refreshGuardian, 30000, "guardian-section");
  gatedInterval(refreshScheduler, 10000, "scheduler-section");
  gatedInterval(refreshAlerts, 15000, "alerts-section");
  gatedInterval(refreshHealth, 30000, "health-section");

  // Tab-owned panels — pause when their tab isn't active.
  gatedInterval(refreshModules, 60000, "modules-section");
  gatedInterval(refreshAuditChains, 60000, "audit-chains-section");
  gatedInterval(refreshHardware, 300000, "hardware-section");
  gatedInterval(refreshNetwork, 30000, "network-section");
  gatedInterval(refreshStorage, 60000, "storage-section");
  gatedInterval(refreshRaid, 60000, "raid-section");
  gatedInterval(refreshGpu, 10000, "gpu-section");
  gatedInterval(refreshCpu, 60000, "cpu-section");
  gatedInterval(refreshFlexProfile, 60000, "flex-profile-section");
  gatedInterval(refreshInferenceBackends, 120000, "inference-backends-section");
  // Capability-token doctrine is a static schema surface — slow refresh.
  gatedInterval(refreshCapabilityTokens, 300000, "capability-tokens-section");
  gatedInterval(refreshToolAuthority, 300000, "tool-authority-section");
  gatedInterval(refreshCommitAuthority, 300000, "commit-authority-section");
  gatedInterval(refreshSandboxTiers, 300000, "sandbox-tiers-section");
  gatedInterval(refreshFilesystemBoundary, 300000, "filesystem-boundary-section");
  gatedInterval(refreshNetworkBoundary, 300000, "network-boundary-section");
  gatedInterval(refreshCommunicationBoundary, 300000, "communication-boundary-section");
  gatedInterval(refreshAuthority, 300000, "authority-section");
  gatedInterval(refreshPolicy, 300000, "policy-section");

  // SDD-056 step 3 — tab switching JS + URL hash router.
  //
  // 17-panel → 8-tab mapping per SDD-056 § 8-tab specification.
  // Each tab carries the section ids that belong under it. The
  // "all" pseudo-tab is the operator-toggleable "show all (legacy)"
  // mode per SDD-056 D-2 — when no tab anchor selected (or
  // #tab=all), every section is visible (today's default).
  const TAB_PANELS = {
    models:   ["inference-backends-section"],
    modules:  ["modules-section", "audit-chains-section"],
    profiles: ["flex-profile-section"],
    hardware: ["hardware-section", "gpu-section", "cpu-section", "raid-section"],
    network:  ["network-section"],
    logs:     ["findings"], // findings panel id is on the <ul>; we walk to its <section>
    mcp:      [], // placeholder per SDD-056 D-3
    repl:     [], // placeholder per SDD-056 D-3
    authority: ["capability-tokens-section", "tool-authority-section", "commit-authority-section", "sandbox-tiers-section", "filesystem-boundary-section", "network-boundary-section", "communication-boundary-section", "authority-section", "policy-section"], // 9 IPS authority/boundary surfaces complete (MS032/033/034/035/037/038/039/040/041/042) IPS authority surfaces (grows: commit-authority, boundaries, sandbox-tiers)
  };
  // Sections that stay visible regardless of which tab is active
  // (always-visible strip per SDD-056 § Always-visible strip).
  const ALWAYS_VISIBLE = new Set([
    "health-section",
    "friction-audit-section",
    "perimeter-section",
    "guardian-section",
    "scheduler-section",
    "alerts-section",
  ]);
  // Sections owned by tabs (used to compute the hide-set quickly).
  const TAB_OWNED = new Set();
  for (const ids of Object.values(TAB_PANELS)) {
    for (const id of ids) TAB_OWNED.add(id);
  }

  // SDD-056 D-2 — "show all" mode preference. localStorage key
  // lets the operator's choice survive page reload. Default is
  // "all" (today's behavior) so existing operators see no change.
  const TAB_MODE_KEY = "selfdef.tabMode";  // "tabbed" | "all"
  function readTabMode() {
    return localStorage.getItem(TAB_MODE_KEY) || "all";
  }
  function writeTabMode(mode) {
    try { localStorage.setItem(TAB_MODE_KEY, mode); } catch (_) { /* private mode */ }
  }

  function parseTab() {
    // URL hash like "#tab=hardware" or "#preset=security&tab=logs".
    // Returns the tab name (one of the 8 + "all") or null. Hash
    // takes precedence over the localStorage preference for the
    // current page load.
    const hash = window.location.hash || "";
    // Accept both single-param (#tab=foo) and multi-param
    // (#preset=security&tab=logs) hash shapes.
    const tabMatch = hash.match(/[#&]tab=([a-z]+)(?:&|$)/);
    if (tabMatch) return tabMatch[1];
    // Fallback: operator preference. "all" → null (no tab active);
    // "tabbed" → "models" (first tab per SDD-056 § 8-tab spec).
    return readTabMode() === "tabbed" ? "models" : null;
  }

  // MS043 UX — URL-hash deep-link support for presets.
  // `#preset=security` (with optional &tab=foo extension) loads
  // the dashboard with that preset already applied. Operator can
  // bookmark distinct URLs per operator-named view — interim
  // toward the verbatim "20 dashboards" requirement before each
  // gets its own URL path + service worker shell.
  function parsePresetFromHash() {
    const hash = window.location.hash || "";
    const m = hash.match(/[#&]preset=([a-z]+)(?:&|$)/);
    if (!m) return null;
    return PRESETS[m[1]] !== undefined ? m[1] : null;
  }

  function switchTab(name) {
    const tabNav = document.getElementById("tab-nav");
    if (!tabNav) return;
    // The "all" pseudo-tab is the operator-toggleable "show all"
    // mode — treat it as "no tab active" for the section
    // show/hide logic but still mark the anchor active so the
    // operator sees the visual confirmation.
    const isAll = name === "all";
    const effective = isAll ? null : name;
    // Flip data-state so CSS re-styles the strip.
    tabNav.dataset.state = effective ? "active" : (isAll ? "active" : "inert");
    // Toggle .active on the anchor.
    for (const a of tabNav.querySelectorAll("a")) {
      if (a.dataset.tab === name) {
        a.classList.add("active");
      } else {
        a.classList.remove("active");
      }
    }
    // Show/hide sections.
    const visibleIds = new Set(ALWAYS_VISIBLE);
    if (effective && TAB_PANELS[effective]) {
      for (const id of TAB_PANELS[effective]) visibleIds.add(id);
    }
    // Walk every <section> in <main>. If the section's id is in
    // the always-visible set OR in the active tab's set, show.
    // If the section is a tab-owned panel NOT in the active set,
    // hide. Other sections (control panel, modules placeholder,
    // etc.) stay visible — they're not under the tab system.
    for (const sec of document.querySelectorAll("main > section")) {
      const id = sec.id || "";
      if (effective && id && TAB_OWNED.has(id) && !visibleIds.has(id)) {
        sec.classList.add("tab-hidden");
      } else {
        sec.classList.remove("tab-hidden");
      }
    }
    // Update the toggle button label to reflect current mode.
    const toggle = document.getElementById("tab-mode-toggle");
    if (toggle) {
      toggle.textContent = effective ? "Show all" : "Show tabbed";
    }
  }

  function onHashChange() {
    const name = parseTab();
    switchTab(name);
  }

  // Wire up anchor clicks (don't replace the default — let the
  // hash change fire, then our listener picks it up). Wire up
  // hash-change event for back/forward navigation + deep-link.
  window.addEventListener("hashchange", onHashChange);
  // Wire the "Show all" / "Show tabbed" toggle button (SDD-056
  // step 5). Flips the persisted preference + navigates to the
  // first-tab-or-all hash so switchTab observes the new state.
  const toggleBtn = document.getElementById("tab-mode-toggle");
  if (toggleBtn) {
    toggleBtn.addEventListener("click", () => {
      const current = readTabMode();
      const next = current === "tabbed" ? "all" : "tabbed";
      writeTabMode(next);
      window.location.hash = next === "tabbed" ? "tab=models" : "tab=all";
    });
  }
  // ----------------------------------------------------------------
  // MS043 UX — daemon-side dashboard-prefs sync.
  //
  // GET /v1/dashboard-prefs on load (server preferences win over
  // localStorage when server has a newer updated_at_ms OR localStorage
  // has nothing). PUT on every preference change (debounced 400ms
  // so a burst of checkbox toggles becomes ONE round-trip). Falls
  // back silently to localStorage when the network is gone — the
  // dashboard remains fully usable offline.
  let prefsSyncTimer = null;
  let prefsSyncInflight = false;
  function prefsBodyFromLocalStorage() {
    return {
      schema_version: "1.0.0",
      hidden_panels: [...readHiddenPanels()],
      refresh_rate: readRefreshRate(),
      active_preset: readPreset(),
    };
  }
  function schedulePrefsSync() {
    if (prefsSyncTimer) clearTimeout(prefsSyncTimer);
    prefsSyncTimer = setTimeout(syncPrefsToServer, 400);
  }
  async function syncPrefsToServer() {
    if (prefsSyncInflight) {
      schedulePrefsSync();  // re-queue while in-flight
      return;
    }
    prefsSyncInflight = true;
    try {
      const body = prefsBodyFromLocalStorage();
      const res = await fetch("/v1/dashboard-prefs", {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
      });
      if (!res.ok) {
        // 400/409 → operator is on a stale build OR sent an unknown
        // enum; log + don't retry. 5xx → silent (localStorage stays
        // authoritative).
        if (res.status >= 400 && res.status < 500) {
          console.warn(`dashboard-prefs PUT rejected: ${res.status}`);
        }
      }
    } catch (_) {
      // Offline; localStorage is the fallback. Resume on next change.
    } finally {
      prefsSyncInflight = false;
    }
  }
  async function fetchPrefsFromServer() {
    try {
      const res = await fetch("/v1/dashboard-prefs");
      if (!res.ok) return;
      const body = await res.json();
      // Adopt server-side preferences. We do NOT do timestamp
      // arbitration on the client — server is source of truth for
      // operator-visible preferences. The dashboard's local changes
      // are PUT immediately on each interaction, so divergence
      // windows are sub-second.
      if (Array.isArray(body.hidden_panels)) {
        const set = new Set(body.hidden_panels);
        try { localStorage.setItem(PANEL_HIDDEN_KEY, JSON.stringify([...set])); } catch (_) {}
      }
      if (typeof body.refresh_rate === "string"
          && REFRESH_RATE_FACTORS[body.refresh_rate] !== undefined) {
        try { localStorage.setItem(REFRESH_RATE_KEY, body.refresh_rate); } catch (_) {}
        const sel = document.getElementById("refresh-rate-select");
        if (sel) sel.value = body.refresh_rate;
      }
      if (typeof body.active_preset === "string"
          && PRESETS[body.active_preset] !== undefined) {
        try { localStorage.setItem(PRESET_KEY, body.active_preset); } catch (_) {}
        const sel = document.getElementById("preset-select");
        if (sel) sel.value = body.active_preset;
      }
      applyHiddenPanels();
    } catch (_) {
      // Offline; localStorage stays authoritative.
    }
  }
  // ----------------------------------------------------------------
  // MS043 UX — operator-facing per-panel visibility menu.
  //
  // Operator verbatim: "everything can be turned on and off". The
  // 8-tab nav groups panels logically; this menu lets the operator
  // permanently hide a panel they don't care about (e.g. an
  // operator on a host without RAID hides the RAID panel). The
  // hidden set is ANDed against the tab-driven hide-set in
  // switchTab() so hidden panels stay hidden across tabs.
  //
  // Persistence: localStorage key `selfdef.hiddenPanels` = JSON
  // array of section IDs. Missing/malformed = no panels hidden.
  const PANEL_HIDDEN_KEY = "selfdef.hiddenPanels";
  const ALL_PANEL_SECTIONS = [
    ["health-section",             "Composite health"],
    ["friction-audit-section",     "Friction audit"],
    ["perimeter-section",          "Perimeter"],
    ["guardian-section",           "Guardian"],
    ["scheduler-section",          "Scheduler"],
    ["modules-section",            "Modules"],
    ["audit-chains-section",       "Audit chains"],
    ["alerts-section",             "Alerts"],
    ["hardware-section",           "Hardware"],
    ["network-section",            "Network"],
    ["storage-section",            "Storage"],
    ["raid-section",               "Software RAID"],
    ["gpu-section",                "GPU watts"],
    ["cpu-section",                "CPU mode"],
    ["flex-profile-section",       "Flex profile"],
    ["inference-backends-section", "Inference backends"],
    ["capability-tokens-section",  "Capability tokens"],
    ["tool-authority-section",     "Tool authority"],
    ["commit-authority-section",   "Commit authority"],
    ["sandbox-tiers-section",      "Sandbox tiers"],
    ["filesystem-boundary-section","Filesystem boundary"],
    ["network-boundary-section",   "Network boundary"],
    ["communication-boundary-section","Communication boundary"],
    ["authority-section",          "Authority model"],
    ["policy-section",             "Policy bus"],
  ];
  function readHiddenPanels() {
    try {
      const raw = localStorage.getItem(PANEL_HIDDEN_KEY);
      if (!raw) return new Set();
      const arr = JSON.parse(raw);
      return new Set(Array.isArray(arr) ? arr : []);
    } catch (_) {
      return new Set();
    }
  }
  function writeHiddenPanels(set) {
    try {
      localStorage.setItem(PANEL_HIDDEN_KEY, JSON.stringify([...set]));
    } catch (_) { /* private mode */ }
    schedulePrefsSync();
  }
  function applyHiddenPanels() {
    const hidden = readHiddenPanels();
    for (const [id] of ALL_PANEL_SECTIONS) {
      const sec = document.getElementById(id);
      if (!sec) continue;
      if (hidden.has(id)) {
        sec.classList.add("operator-hidden");
      } else {
        sec.classList.remove("operator-hidden");
      }
    }
  }
  function buildPanelVisibilityMenu() {
    const menu = document.getElementById("panel-visibility-menu");
    if (!menu) return;
    const hidden = readHiddenPanels();
    const visibleCount = ALL_PANEL_SECTIONS.length - hidden.size;
    menu.innerHTML = "";
    const header = document.createElement("div");
    header.className = "panel-vis-header";
    header.textContent = `${visibleCount}/${ALL_PANEL_SECTIONS.length} panels visible`;
    menu.appendChild(header);
    for (const [id, label] of ALL_PANEL_SECTIONS) {
      const row = document.createElement("label");
      row.className = "panel-vis-row";
      const cb = document.createElement("input");
      cb.type = "checkbox";
      cb.checked = !hidden.has(id);
      cb.dataset.sectionId = id;
      cb.addEventListener("change", (ev) => {
        const sectionId = ev.target.dataset.sectionId;
        const set = readHiddenPanels();
        if (ev.target.checked) {
          set.delete(sectionId);
        } else {
          set.add(sectionId);
        }
        writeHiddenPanels(set);
        applyHiddenPanels();
        // Rebuild to update the count.
        buildPanelVisibilityMenu();
      });
      const span = document.createElement("span");
      span.textContent = label;
      row.appendChild(cb);
      row.appendChild(span);
      menu.appendChild(row);
    }
    // "Show all" reset row.
    const reset = document.createElement("button");
    reset.type = "button";
    reset.className = "panel-vis-reset";
    reset.textContent = "Show all panels";
    reset.addEventListener("click", () => {
      writeHiddenPanels(new Set());
      applyHiddenPanels();
      buildPanelVisibilityMenu();
    });
    menu.appendChild(reset);
  }
  const visBtn = document.getElementById("panel-visibility-btn");
  const visMenu = document.getElementById("panel-visibility-menu");
  if (visBtn && visMenu) {
    visBtn.addEventListener("click", (ev) => {
      ev.stopPropagation();
      const open = !visMenu.hidden;
      if (open) {
        visMenu.hidden = true;
        visBtn.setAttribute("aria-expanded", "false");
      } else {
        buildPanelVisibilityMenu();
        visMenu.hidden = false;
        visBtn.setAttribute("aria-expanded", "true");
      }
    });
    // Close on outside click.
    document.addEventListener("click", (ev) => {
      if (visMenu.hidden) return;
      if (visMenu.contains(ev.target) || ev.target === visBtn) return;
      visMenu.hidden = true;
      visBtn.setAttribute("aria-expanded", "false");
    });
  }
  // Apply hidden set on initial load — before switchTab() so the
  // first tab render reflects operator preferences.
  applyHiddenPanels();

  // MS043 UX — refresh-rate selector wiring. Sync the <select> with
  // the persisted preference, then listen for changes and persist.
  const refreshSelect = document.getElementById("refresh-rate-select");
  if (refreshSelect) {
    refreshSelect.value = readRefreshRate();
    refreshSelect.addEventListener("change", (ev) => {
      writeRefreshRate(ev.target.value);
    });
  }

  // ----------------------------------------------------------------
  // MS043 UX — operator-named view presets.
  //
  // Verbatim operator direction: "there is over 20 dashboards".
  // Distinct dashboard URL paths (each with its own service worker
  // shell) is a larger Stage-2 arc; the tractable interim is
  // operator-named view PRESETS that snap the existing dashboard's
  // {hiddenPanels, activeTab, refreshRate} triple to a meaningful
  // configuration in one click.
  //
  // 20 shipped presets (5 original + 15 batch-17 expansion fulfilling
  // the operator's verbatim "over 20 dashboards" target):
  //   default              — all 16 panels visible, no tab, normal refresh
  //   security             — watchdogs+alerts+audit; "logs" tab
  //   performance          — hardware+network+storage+raid+gpu+cpu
  //   inference            — health+inference-backends+gpu+flex
  //   compact              — always-visible strip + alerts only
  //   audit-trail          — audit chains + alerts; slow forensic
  //   cpu-bound            — CPU + hardware + composite-health
  //   gpu-monitor          — GPU + CPU + flex + composite-health
  //   health-only          — composite-health alone (smallest)
  //   incident-response    — 4 watchdogs + alerts + audit + logs (fast)
  //   inference-throughput — inference + GPU + flex + CPU (fast)
  //   mcp-debug            — MCP tab + alerts + logs
  //   mcp-tools            — MCP + modules + alerts
  //   models-lab           — models tab + inference + GPU
  //   module-status        — modules + profiles + composite-health
  //   network-ops          — network + storage + RAID + health
  //   paused-snapshot      — all 16 BUT paused (one-shot inspection)
  //   repl-session         — REPL tab + composite-health + alerts
  //   storage-ops          — storage + RAID + composite-health
  //   watchdog-deep        — 4 watchdogs + health (fast)
  //
  // Source-of-truth is selfdef-api/src/dashboards.rs (DASHBOARDS
  // const). This table MUST stay byte-identical on names + tabs +
  // refreshRate to that source — daemon's PUT /v1/dashboard-prefs
  // VALID_PRESETS validator rejects any other value.
  //
  // Persistence: localStorage selfdef.activePreset = preset name.
  // Switching a preset writes its triple atomically (hiddenPanels +
  // refreshRate + tab hash). Operator's manual overrides AFTER
  // a preset are kept (the preset is just the snap-to point).
  const PRESET_KEY = "selfdef.activePreset";
  const ALL_SECTION_IDS = ALL_PANEL_SECTIONS.map(([id]) => id);
  function setMinus(all, keep) {
    const set = new Set(all);
    for (const k of keep) set.delete(k);
    return set;
  }
  const PRESETS = {
    "audit-trail": {
      label: "Audit trail",
      hidden: setMinus(ALL_SECTION_IDS, [
        "audit-chains-section",
        "alerts-section",
        "health-section",
      ]),
      refreshRate: "slow",
      tab: "logs",
    },
    compact: {
      label: "Compact",
      hidden: setMinus(ALL_SECTION_IDS, [
        "health-section",
        "friction-audit-section",
        "perimeter-section",
        "guardian-section",
        "scheduler-section",
        "alerts-section",
      ]),
      refreshRate: "slow",
      tab: "all",
    },
    "cpu-bound": {
      label: "CPU bound",
      hidden: setMinus(ALL_SECTION_IDS, [
        "health-section",
        "hardware-section",
        "cpu-section",
      ]),
      refreshRate: "fast",
      tab: "hardware",
    },
    default: {
      label: "Default — all panels",
      hidden: new Set(),
      refreshRate: "normal",
      tab: "all",
    },
    "gpu-monitor": {
      label: "GPU monitor",
      hidden: setMinus(ALL_SECTION_IDS, [
        "health-section",
        "gpu-section",
        "cpu-section",
        "flex-profile-section",
      ]),
      refreshRate: "fast",
      tab: "hardware",
    },
    "health-only": {
      label: "Health only",
      hidden: setMinus(ALL_SECTION_IDS, [
        "health-section",
      ]),
      refreshRate: "slow",
      tab: "all",
    },
    "incident-response": {
      label: "Incident response",
      hidden: setMinus(ALL_SECTION_IDS, [
        "health-section",
        "friction-audit-section",
        "perimeter-section",
        "guardian-section",
        "scheduler-section",
        "alerts-section",
        "audit-chains-section",
      ]),
      refreshRate: "fast",
      tab: "logs",
    },
    inference: {
      label: "Inference",
      hidden: setMinus(ALL_SECTION_IDS, [
        "health-section",
        "inference-backends-section",
        "gpu-section",
        "flex-profile-section",
      ]),
      refreshRate: "normal",
      tab: "models",
    },
    "inference-throughput": {
      label: "Inference throughput",
      hidden: setMinus(ALL_SECTION_IDS, [
        "health-section",
        "inference-backends-section",
        "gpu-section",
        "flex-profile-section",
        "cpu-section",
      ]),
      refreshRate: "fast",
      tab: "models",
    },
    "mcp-debug": {
      label: "MCP debug",
      hidden: setMinus(ALL_SECTION_IDS, [
        "alerts-section",
        "health-section",
        "modules-section",
      ]),
      refreshRate: "normal",
      tab: "mcp",
    },
    "mcp-tools": {
      label: "MCP tools",
      hidden: setMinus(ALL_SECTION_IDS, [
        "modules-section",
        "alerts-section",
        "health-section",
      ]),
      refreshRate: "normal",
      tab: "mcp",
    },
    "models-lab": {
      label: "Models lab",
      hidden: setMinus(ALL_SECTION_IDS, [
        "inference-backends-section",
        "gpu-section",
        "health-section",
      ]),
      refreshRate: "normal",
      tab: "models",
    },
    "module-status": {
      label: "Module status",
      hidden: setMinus(ALL_SECTION_IDS, [
        "modules-section",
        "health-section",
      ]),
      refreshRate: "slow",
      tab: "modules",
    },
    "network-ops": {
      label: "Network ops",
      hidden: setMinus(ALL_SECTION_IDS, [
        "health-section",
        "network-section",
        "storage-section",
        "raid-section",
      ]),
      refreshRate: "normal",
      tab: "network",
    },
    "paused-snapshot": {
      label: "Paused snapshot",
      hidden: new Set(),
      refreshRate: "paused",
      tab: "all",
    },
    performance: {
      label: "Performance",
      hidden: setMinus(ALL_SECTION_IDS, [
        "health-section",
        "hardware-section",
        "network-section",
        "storage-section",
        "raid-section",
        "gpu-section",
        "cpu-section",
      ]),
      refreshRate: "fast",
      tab: "hardware",
    },
    "repl-session": {
      label: "REPL session",
      hidden: setMinus(ALL_SECTION_IDS, [
        "health-section",
        "alerts-section",
      ]),
      refreshRate: "normal",
      tab: "repl",
    },
    security: {
      label: "Security",
      hidden: setMinus(ALL_SECTION_IDS, [
        "health-section",
        "friction-audit-section",
        "perimeter-section",
        "guardian-section",
        "scheduler-section",
        "alerts-section",
        "audit-chains-section",
      ]),
      refreshRate: "normal",
      tab: "logs",
    },
    "storage-ops": {
      label: "Storage ops",
      hidden: setMinus(ALL_SECTION_IDS, [
        "health-section",
        "storage-section",
        "raid-section",
      ]),
      refreshRate: "normal",
      tab: "all",
    },
    "watchdog-deep": {
      label: "Watchdog deep",
      hidden: setMinus(ALL_SECTION_IDS, [
        "health-section",
        "friction-audit-section",
        "perimeter-section",
        "guardian-section",
        "scheduler-section",
      ]),
      refreshRate: "fast",
      tab: "all",
    },
  };
  function readPreset() {
    const v = localStorage.getItem(PRESET_KEY);
    return PRESETS[v] !== undefined ? v : "default";
  }
  function writePreset(name) {
    try { localStorage.setItem(PRESET_KEY, name); } catch (_) { /* private mode */ }
    schedulePrefsSync();
  }
  function applyPreset(name) {
    const p = PRESETS[name];
    if (!p) return;
    writePreset(name);
    writeHiddenPanels(new Set(p.hidden));
    applyHiddenPanels();
    writeRefreshRate(p.refreshRate);
    if (refreshSelect) refreshSelect.value = p.refreshRate;
    // Snap both preset + tab into the URL hash so the operator
    // can copy the address bar contents as a shareable / bookmarkable
    // deep-link. switchTab + the hashchange listener pick this up.
    window.location.hash = `preset=${name}&tab=${p.tab}`;
  }
  const presetSelect = document.getElementById("preset-select");
  if (presetSelect) {
    presetSelect.value = readPreset();
    presetSelect.addEventListener("change", (ev) => {
      applyPreset(ev.target.value);
    });
  }

  // Apply initial state from URL hash (deep-link support).
  // If `#preset=<name>` is in the URL, snap to that preset first
  // (which writes its own hash including tab). Otherwise fall
  // back to the existing tab-only deep-link path.
  const initialPreset = parsePresetFromHash();
  if (initialPreset) {
    applyPreset(initialPreset);
    if (presetSelect) presetSelect.value = initialPreset;
  } else {
    switchTab(parseTab());
  }

  // MS043 UX — fire-and-forget initial fetch of server-side
  // preferences. Server wins over localStorage when reachable; if
  // offline (file:// or daemon down) localStorage stays authoritative.
  fetchPrefsFromServer();

  // Offline-shell registration. Best effort — skipped over file://.
  if ("serviceWorker" in navigator && location.protocol.startsWith("http")) {
    navigator.serviceWorker.register("service-worker.js").catch(() => {
      /* PWA install is optional; ignore. */
    });
  }
})();
