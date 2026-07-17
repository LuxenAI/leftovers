"use strict";

const POLL_INTERVAL_MS = 5000;
const REQUEST_TIMEOUT_MS = 4000;
const numberFormatter = new Intl.NumberFormat(undefined, { maximumFractionDigits: 0 });
const stageGroups = {
  scheduled: "prepare",
  budget_check: "prepare",
  discovering: "prepare",
  scoring: "prepare",
  selected: "prepare",
  preflight: "prepare",
  sandbox_ready: "prepare",
  planning: "work",
  implementing: "work",
  verifying: "verify",
  reviewing: "verify",
  approved: "verify",
  awaiting_approval: "verify",
  publishing: "publish",
  pr_open: "publish",
  cleaning: "clean",
  complete: "clean"
};
const groupOrder = ["prepare", "work", "verify", "publish", "clean"];
const terminalStages = new Set([
  "complete",
  "deferred",
  "skipped",
  "failed",
  "aborted",
  "cleanup_pending"
]);

let lastEtag = null;
let lastSnapshot = null;
let polling = false;
let pollTimer = null;
let lastConnectionState = null;

function element(id) {
  return document.getElementById(id);
}

function isKnownNumber(value) {
  return typeof value === "number" && Number.isFinite(value) && value >= 0;
}

function tokenText(value) {
  return isKnownNumber(value) ? `${numberFormatter.format(value)} tokens` : "Unknown";
}

function shortTokenText(value) {
  if (!isKnownNumber(value)) {
    return "Unknown";
  }
  if (value >= 1000000000) {
    return `${(value / 1000000000).toFixed(value >= 10000000000 ? 0 : 1)}B`;
  }
  if (value >= 1000000) {
    return `${(value / 1000000).toFixed(value >= 10000000 ? 0 : 1)}M`;
  }
  if (value >= 1000) {
    return `${(value / 1000).toFixed(value >= 10000 ? 0 : 1)}K`;
  }
  return numberFormatter.format(value);
}

function humanize(value) {
  if (typeof value !== "string" || value === "unknown") {
    return "Unknown";
  }
  return value
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function timestampText(value) {
  if (typeof value !== "string") {
    return "Unknown time";
  }
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return "Unknown time";
  }
  return parsed.toLocaleString(undefined, {
    dateStyle: "medium",
    timeStyle: "short"
  });
}

function setMetric(id, value) {
  const target = element(id);
  target.textContent = shortTokenText(value);
  target.title = tokenText(value);
  target.classList.toggle("is-unknown", !isKnownNumber(value));
}

function setChip(target, text, status) {
  target.textContent = text;
  target.className = "status-chip";
  const allowed = new Set([
    "neutral",
    "ok",
    "production",
    "training",
    "warning",
    "degraded",
    "stale",
    "error",
    "unavailable",
    "offline"
  ]);
  target.classList.add(allowed.has(status) ? status : "neutral");
}

function renderBudget(budget) {
  const safeBudget = budget && typeof budget === "object" ? budget : {};
  const windowValue = safeBudget.window && typeof safeBudget.window === "object"
    ? safeBudget.window
    : {};
  const coverage = safeBudget.coverage && typeof safeBudget.coverage === "object"
    ? safeBudget.coverage
    : {};

  setMetric("metric-maximum", safeBudget.maximum_tokens);
  setMetric("metric-remaining", safeBudget.remaining_tokens);
  setMetric("metric-reserve", safeBudget.reserve_tokens);
  setMetric("metric-reserved", safeBudget.reserved_tokens);
  setMetric("metric-used", safeBudget.known_used_tokens);

  const qualified = windowValue.qualified;
  let qualificationText = "Qualification unknown";
  if (qualified === true) {
    qualificationText = "Qualified provider window";
  } else if (qualified === false) {
    qualificationText = "Window not qualified";
  }
  if (!isKnownNumber(safeBudget.maximum_tokens) && isKnownNumber(safeBudget.run_cap_tokens)) {
    qualificationText += ` · Tracked run caps ${tokenText(safeBudget.run_cap_tokens)}`;
  }
  if (safeBudget.authority === "non_authoritative_projection") {
    qualificationText += " · Monitoring projection";
  }
  element("metric-maximum-note").textContent = qualificationText;

  const windowKind = windowValue.kind === "daily" || windowValue.kind === "weekly"
    ? `${humanize(windowValue.kind)} window`
    : "Unknown window";
  setChip(element("window-kind"), windowKind, qualified === true ? "ok" : "neutral");
  element("window-reset").textContent = windowValue.resets_at
    ? `Resets ${timestampText(windowValue.resets_at)}`
    : "Reset unknown";

  const coveragePercent = coverage.percent;
  const coverageKnown = isKnownNumber(coveragePercent) && coveragePercent <= 100;
  const coverageTarget = element("metric-coverage");
  coverageTarget.textContent = coverageKnown ? `${numberFormatter.format(coveragePercent)}%` : "Unknown";
  coverageTarget.classList.toggle("is-unknown", !coverageKnown);
  const invocationCoverage = isKnownNumber(coverage.exact_invocations) && isKnownNumber(coverage.finished_invocations)
    ? `${numberFormatter.format(coverage.exact_invocations)} of ${numberFormatter.format(coverage.finished_invocations)} invocations`
    : "Invocation receipt count unknown";
  const exactness = coverage.exact === true ? "exact" : coverage.exact === false ? "mixed" : "unknown exactness";
  element("metric-coverage-note").textContent = `${humanize(coverage.status)} · ${invocationCoverage} · ${exactness}`;

  element("spendable-value").textContent = isKnownNumber(safeBudget.spendable_tokens)
    ? `Spendable ${tokenText(safeBudget.spendable_tokens)}`
    : "Spendable unknown";

  const maximum = safeBudget.maximum_tokens;
  const used = safeBudget.known_used_tokens;
  const progress = element("usage-progress");
  if (isKnownNumber(maximum) && maximum > 0 && isKnownNumber(used)) {
    progress.max = maximum;
    progress.value = Math.min(used, maximum);
    progress.classList.remove("is-unknown");
    progress.setAttribute("aria-valuetext", `${tokenText(used)} known used of ${tokenText(maximum)}`);
  } else {
    progress.max = 1;
    progress.removeAttribute("value");
    progress.classList.add("is-unknown");
    progress.setAttribute("aria-valuetext", "Unknown");
  }
}

function renderActiveRun(run) {
  const stageTarget = element("active-stage");
  const detailTarget = element("active-run-detail");
  const kindTarget = element("active-kind");
  const railItems = Array.from(element("stage-rail").querySelectorAll("li"));
  railItems.forEach((item) => item.classList.remove("is-active", "is-complete"));

  if (!run || typeof run !== "object") {
    stageTarget.textContent = "No confirmed active run";
    detailTarget.textContent = "Run and issue unknown";
    setChip(kindTarget, "Unknown", "neutral");
    return;
  }

  stageTarget.textContent = humanize(run.stage);
  const id = typeof run.run_id === "string" ? run.run_id.slice(0, 12) : "unknown";
  const issue = typeof run.issue_ref === "string" ? run.issue_ref : "issue unknown";
  detailTarget.textContent = `Run ${id} · ${issue}`;
  setChip(
    kindTarget,
    humanize(run.kind),
    run.kind === "production" ? "production" : run.kind === "training" ? "training" : "neutral"
  );

  const activeGroup = stageGroups[run.stage];
  const activeIndex = groupOrder.indexOf(activeGroup);
  railItems.forEach((item) => {
    const index = groupOrder.indexOf(item.dataset.stageGroup);
    if (index >= 0 && index < activeIndex) {
      item.classList.add("is-complete");
    } else if (index === activeIndex) {
      item.classList.add("is-active");
    }
  });
}

function renderHealth(health) {
  const safeHealth = health && typeof health === "object" ? health : {};
  const status = typeof safeHealth.status === "string" ? safeHealth.status : "unknown";
  const chipStatus = status === "ok" ? "ok" : status === "degraded" ? "degraded" : status === "unavailable" ? "unavailable" : "neutral";
  setChip(element("health-status"), humanize(status), chipStatus);
  element("health-summary").textContent = safeHealth.checked_at
    ? `Last control-plane assessment: ${timestampText(safeHealth.checked_at)}.`
    : "Health assessment time is unknown.";

  const list = element("health-components");
  list.replaceChildren();
  const components = Array.isArray(safeHealth.components) ? safeHealth.components : [];
  components.forEach((component) => {
    if (!component || typeof component !== "object") {
      return;
    }
    const item = document.createElement("li");
    const name = document.createElement("span");
    const state = document.createElement("span");
    name.textContent = typeof component.name === "string" ? component.name : "Unknown component";
    state.textContent = humanize(component.status);
    item.append(name, state);
    list.append(item);
  });
}

function modelStatus(model) {
  if (model.identity_status === "mismatch") {
    return ["Identity mismatch", "degraded"];
  }
  if (model.state === "succeeded") {
    return ["Succeeded", "ok"];
  }
  if (model.state === "failed") {
    return ["Failed", "degraded"];
  }
  if (model.state === "timed_out") {
    return ["Timed out", "degraded"];
  }
  if (model.state === "cancelled") {
    return ["Cancelled", "neutral"];
  }
  if (model.freshness === "stale") {
    return ["Stale", "stale"];
  }
  if (model.status === "offline" || model.status === "unavailable") {
    return [humanize(model.status), model.status];
  }
  if (model.status === "degraded") {
    return ["Degraded", "degraded"];
  }
  if (model.freshness === "fresh" || model.status === "ok" || model.status === "available") {
    return ["Fresh", "ok"];
  }
  return ["Unknown", "neutral"];
}

function renderModels(models) {
  const values = Array.isArray(models) ? models : [];
  const list = element("models-list");
  list.replaceChildren();
  element("models-empty").hidden = values.length > 0;
  element("model-count").textContent = `${numberFormatter.format(values.length)} invocation${values.length === 1 ? "" : "s"}`;

  values.forEach((model) => {
    if (!model || typeof model !== "object") {
      return;
    }
    const card = document.createElement("article");
    card.className = "model-card";
    const identity = document.createElement("div");
    identity.className = "model-identity";
    const provider = document.createElement("span");
    provider.className = "provider-name";
    provider.textContent = typeof model.observed_provider === "string"
      ? model.observed_provider
      : typeof model.expected_provider === "string"
        ? `${model.expected_provider} expected`
        : "Unknown provider";
    const name = document.createElement("p");
    name.className = "model-name";
    name.textContent = typeof model.observed_model === "string"
      ? model.observed_model
      : typeof model.expected_model === "string"
        ? model.expected_model
        : "Unknown model";
    identity.append(provider, name);

    const chip = document.createElement("span");
    const [label, status] = modelStatus(model);
    setChip(chip, label, status);

    const meta = document.createElement("p");
    meta.className = "model-meta";
    const expectedIdentity = typeof model.expected_provider === "string" && typeof model.expected_model === "string"
      ? `Expected ${model.expected_provider}/${model.expected_model}`
      : "Expected identity unknown";
    const observedIdentity = typeof model.observed_provider === "string" && typeof model.observed_model === "string"
      ? `Observed ${model.observed_provider}/${model.observed_model}`
      : "Observed identity unknown";
    const stage = typeof model.stage === "string" ? humanize(model.stage) : "Stage unknown";
    const state = typeof model.state === "string" ? humanize(model.state) : "State unknown";
    const usage = model.usage && typeof model.usage === "object"
      ? tokenText(model.usage.total_tokens)
      : "Usage unknown";
    const checkin = model.checked_in_at ? `Checked in ${timestampText(model.checked_in_at)}` : "Check-in time unknown";
    const heartbeat = model.heartbeat_at ? `Heartbeat ${timestampText(model.heartbeat_at)}` : "heartbeat unknown";
    meta.textContent = `${observedIdentity} · ${expectedIdentity} · ${stage} · ${state} · ${usage} · ${checkin} · ${heartbeat}`;
    card.append(identity, chip, meta);
    list.append(card);
  });
}

function createRunCard(run) {
  const item = document.createElement("li");
  item.className = "run-card";
  const topline = document.createElement("div");
  topline.className = "run-topline";
  const id = document.createElement("p");
  id.className = "run-id";
  const rawId = typeof run.run_id === "string" ? run.run_id : "unknown";
  id.textContent = rawId.slice(0, 12);
  id.title = rawId;
  const stage = document.createElement("span");
  const stageValue = typeof run.stage === "string" ? run.stage : "unknown";
  const stageStatus = stageValue === "complete" ? "ok" : terminalStages.has(stageValue) ? "warning" : "neutral";
  setChip(stage, humanize(stageValue), stageStatus);
  topline.append(id, stage);

  const meta = document.createElement("p");
  meta.className = "run-meta";
  const issue = typeof run.issue_ref === "string" ? run.issue_ref : "Issue unknown";
  const updated = timestampText(run.updated_at || run.finished_at || run.started_at);
  const usage = run.usage && typeof run.usage === "object" ? tokenText(run.usage.total_tokens) : "Unknown usage";
  meta.textContent = `${issue} · ${updated} · ${usage}`;
  item.append(topline, meta);
  return item;
}

function renderRunGroup(kind, runs) {
  const values = Array.isArray(runs) ? runs : [];
  const list = element(`${kind}-runs`);
  list.replaceChildren();
  values.forEach((run) => {
    if (run && typeof run === "object") {
      list.append(createRunCard(run));
    }
  });
  setChip(
    element(`${kind}-count`),
    numberFormatter.format(values.length),
    kind === "production" ? "production" : kind === "training" ? "training" : "warning"
  );
  const empty = element(`${kind}-empty`);
  if (empty) {
    empty.hidden = values.length > 0;
  }
}

function renderRuns(runs) {
  const groups = runs && typeof runs === "object" ? runs : {};
  renderRunGroup("production", groups.production);
  renderRunGroup("training", groups.training);
  const unclassified = Array.isArray(groups.unclassified) ? groups.unclassified : [];
  element("unclassified-section").hidden = unclassified.length === 0;
  renderRunGroup("unclassified", unclassified);
}

function setConnection(state, text) {
  const dot = element("connection-dot");
  dot.className = "status-dot";
  dot.classList.add(
    state === "ok" ? "status-ok" : state === "degraded" ? "status-degraded" : state === "error" ? "status-error" : "status-unknown"
  );
  element("connection-status").textContent = text;
  if (state !== lastConnectionState) {
    element("announcement").textContent = `Dashboard connection ${text.toLowerCase()}.`;
    lastConnectionState = state;
  }
}

function renderSnapshot(snapshot) {
  if (!snapshot || typeof snapshot !== "object" || snapshot.version !== 1) {
    throw new Error("Unsupported dashboard snapshot");
  }
  renderBudget(snapshot.budget);
  renderActiveRun(snapshot.active_run);
  renderHealth(snapshot.health);
  renderModels(snapshot.models);
  renderRuns(snapshot.runs);
  const healthStatus = snapshot.health && snapshot.health.status;
  if (healthStatus === "degraded") {
    setConnection("degraded", "Degraded");
  } else if (healthStatus === "unavailable") {
    setConnection("error", "Unavailable");
  } else {
    setConnection("ok", "Live");
  }
  element("last-updated").textContent = `Updated ${new Date().toLocaleTimeString(undefined, {
    hour: "numeric",
    minute: "2-digit",
    second: "2-digit"
  })}`;
}

async function poll() {
  if (polling || document.hidden) {
    schedulePoll();
    return;
  }
  polling = true;
  element("refresh-button").disabled = true;
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    const headers = { Accept: "application/json" };
    if (lastEtag) {
      headers["If-None-Match"] = lastEtag;
    }
    const response = await fetch("/api/v1/snapshot?limit=24", {
      method: "GET",
      headers,
      credentials: "omit",
      cache: "no-store",
      redirect: "error",
      signal: controller.signal
    });
    if (response.status === 304 && lastSnapshot) {
      renderSnapshot(lastSnapshot);
      return;
    }
    if (!response.ok) {
      throw new Error(`Dashboard unavailable (${response.status})`);
    }
    const contentType = response.headers.get("Content-Type") || "";
    if (!contentType.toLowerCase().startsWith("application/json")) {
      throw new Error("Dashboard returned an unexpected content type");
    }
    const snapshot = await response.json();
    renderSnapshot(snapshot);
    lastSnapshot = snapshot;
    lastEtag = response.headers.get("ETag");
  } catch (error) {
    setConnection("error", "Unavailable");
    if (!lastSnapshot) {
      element("last-updated").textContent = "No verified snapshot";
    }
  } finally {
    window.clearTimeout(timeout);
    polling = false;
    element("refresh-button").disabled = false;
    schedulePoll();
  }
}

function schedulePoll() {
  if (pollTimer !== null) {
    window.clearTimeout(pollTimer);
  }
  pollTimer = window.setTimeout(poll, POLL_INTERVAL_MS);
}

element("refresh-button").addEventListener("click", () => {
  if (pollTimer !== null) {
    window.clearTimeout(pollTimer);
  }
  poll();
});

document.addEventListener("visibilitychange", () => {
  if (!document.hidden) {
    poll();
  }
});

poll();
