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
  refreshActionList();

  /// SDD-056 step 4 — gated setInterval wrapper. Calls `fn` only
  /// when the named section is NOT tab-hidden. Saves probe cost
  /// (nvidia-smi / df / ping / mdstat / etc.) when the operator is
  /// looking at a different tab. `sectionId === null` = always-fire
  /// (used for status header + always-visible-strip panels).
  function gatedInterval(fn, ms, sectionId) {
    return setInterval(() => {
      if (sectionId !== null) {
        const sec = document.getElementById(sectionId);
        if (sec && sec.classList.contains("tab-hidden")) return;
      }
      fn();
    }, ms);
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
    // URL hash like "#tab=hardware". Returns the tab name (one of
    // the 8 + "all") or null. Hash takes precedence over the
    // localStorage preference for the current page load.
    const hash = window.location.hash || "";
    const m = hash.match(/^#tab=([a-z]+)$/);
    if (m) return m[1];
    // Fallback: operator preference. "all" → null (no tab active);
    // "tabbed" → "models" (first tab per SDD-056 § 8-tab spec).
    return readTabMode() === "tabbed" ? "models" : null;
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
  // Apply initial state from URL hash (deep-link support).
  switchTab(parseTab());

  // Offline-shell registration. Best effort — skipped over file://.
  if ("serviceWorker" in navigator && location.protocol.startsWith("http")) {
    navigator.serviceWorker.register("service-worker.js").catch(() => {
      /* PWA install is optional; ignore. */
    });
  }
})();
