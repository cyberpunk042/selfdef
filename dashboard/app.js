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
      const body = await get("/v1/modules");
      const modules = body.modules || [];
      const activeCount = modules.filter((m) => m.active).length;
      countEl.textContent = `${activeCount}/${modules.length}`;
      countEl.className =
        "fa-aggregate " + (modules.length === 0 ? "fa-unknown" : "fa-ok");
      metaEl.textContent = `${activeCount} active / ${modules.length} shipped · dir: ${body.modules_dir || "(missing)"}`;
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
        detail.textContent = `v${m.version || "?"} · [${cat}] · ${m.summary || ""} · ${deps} dep · ${prov} prov`;

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
  refreshActionList();
  setInterval(refreshStatus, 5000);
  // Four-watchdog set panels refresh less often than status — gate
  // state is rare-change (boot + operator overrides). 30s for the
  // hardware frame (friction-audit) and supervisor (guardian); 15s for
  // the perimeter since execve events can land between refreshes; 10s
  // for the scheduler since routing decisions are high-frequency.
  setInterval(refreshFrictionAudit, 30000);
  setInterval(refreshPerimeter, 15000);
  setInterval(refreshGuardian, 30000);
  setInterval(refreshScheduler, 10000);
  // Modules list is rare-change (only changes on package upgrade or
  // operator-driven `modules apply`); 60s is plenty.
  setInterval(refreshModules, 60000);
  // Alerts overview is the chain-integrity + cumulative-counter
  // mirror of the Prometheus alert rules — fast refresh keeps
  // chain-broken signals operator-visible within seconds.
  setInterval(refreshAlerts, 15000);
  // Hardware panel reflects MS010 / SDD-018 — hardware doesn't
  // hot-swap so 5 minutes is plenty (the server caches the probe
  // anyway via OnceLock).
  setInterval(refreshHardware, 300000);

  // Offline-shell registration. Best effort — skipped over file://.
  if ("serviceWorker" in navigator && location.protocol.startsWith("http")) {
    navigator.serviceWorker.register("service-worker.js").catch(() => {
      /* PWA install is optional; ignore. */
    });
  }
})();
