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
    // Special-case the friction-audit panel — different endpoint shape.
    if (kind === "friction-audit") {
      return refreshFrictionAudit();
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
  refreshActionList();
  setInterval(refreshStatus, 5000);
  // Friction-audit panel refreshes less often than status; gate state
  // is rare-change (boot + operator replay). 30s keeps the panel
  // fresh enough to reflect operator overrides without burning HTTP.
  setInterval(refreshFrictionAudit, 30000);

  // Offline-shell registration. Best effort — skipped over file://.
  if ("serviceWorker" in navigator && location.protocol.startsWith("http")) {
    navigator.serviceWorker.register("service-worker.js").catch(() => {
      /* PWA install is optional; ignore. */
    });
  }
})();
