"use strict";

// The last configuration received from the server. Edits are applied to this
// object and the whole thing is sent back, so it must be kept fresh.
let config = null;
let statusTimer = null;
let eventsTimer = null;
let saveTimer = null;

const $ = (id) => document.getElementById(id);

// ------------------------------------------------------------------ helpers

async function api(path, options) {
  const response = await fetch(path, options);
  if (!response.ok) {
    let detail = response.statusText;
    try {
      const body = await response.json();
      if (body && body.error) detail = body.error;
    } catch (_) {
      /* the body was not JSON; the status text will do */
    }
    throw new Error(detail);
  }
  return response.status === 204 ? null : response.json();
}

function getPath(object, path) {
  return path.split(".").reduce((value, key) => (value == null ? value : value[key]), object);
}

function setPath(object, path, value) {
  const keys = path.split(".");
  const last = keys.pop();
  const parent = keys.reduce((value, key) => value[key], object);
  parent[last] = value;
}

function formatBytes(bytes) {
  if (!bytes) return "\u2013";
  const units = ["B", "KB", "MB", "GB"];
  let index = 0;
  let value = bytes;
  while (value >= 1024 && index < units.length - 1) {
    value /= 1024;
    index += 1;
  }
  return `${value < 10 && index > 0 ? value.toFixed(1) : Math.round(value)} ${units[index]}`;
}

function formatWhen(timestamp) {
  if (!timestamp) return "never";
  const date = new Date(timestamp);
  return Number.isNaN(date.getTime()) ? "unknown" : date.toLocaleString();
}

function formatDuration(seconds) {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  if (days) return `up ${days}d ${hours}h`;
  if (hours) return `up ${hours}h ${minutes}m`;
  return `up ${minutes}m`;
}

function percent(part, total) {
  return total ? `${((part / total) * 100).toFixed(1)}% of traffic` : "";
}

function setSaveState(text, className) {
  const element = $("save-state");
  element.textContent = text;
  element.className = `save-state ${className || ""}`;
}

// --------------------------------------------------------------- persistence

/** Sends the whole config, debounced so rapid edits cause one rebuild. */
function saveConfig({ immediate = false } = {}) {
  clearTimeout(saveTimer);
  const delay = immediate ? 0 : 500;

  return new Promise((resolve) => {
    saveTimer = setTimeout(async () => {
      setSaveState("Saving\u2026", "saving");
      try {
        const result = await api("/api/config", {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(config),
        });
        setSaveState(result.restart_required ? "Saved (restart needed)" : "Saved", "saved");
        await refreshStatus();
      } catch (error) {
        setSaveState(`Save failed: ${error.message}`, "failed");
      }
      resolve();
    }, delay);
  });
}

/** Copies every `data-config` control into `config`, then saves. */
function collectAndSave() {
  if (!config) return;

  for (const element of document.querySelectorAll("[data-config]")) {
    const path = element.dataset.config;
    const current = getPath(config, path);

    if (element.type === "checkbox") {
      setPath(config, path, element.checked);
    } else if (Array.isArray(current)) {
      const lines = element.value
        .split("\n")
        .map((line) => line.trim())
        .filter((line) => line.length > 0);
      setPath(config, path, lines);
    } else {
      setPath(config, path, element.value.trim());
    }
  }

  saveConfig();
}

/** Fills every `data-config` control from `config`. */
function applyConfigToForm() {
  for (const element of document.querySelectorAll("[data-config]")) {
    // Never overwrite the field the user is currently typing in.
    if (element === document.activeElement) continue;

    const value = getPath(config, element.dataset.config);
    if (element.type === "checkbox") {
      element.checked = Boolean(value);
    } else if (Array.isArray(value)) {
      element.value = value.join("\n");
    } else {
      element.value = value == null ? "" : String(value);
    }
  }
}

// -------------------------------------------------------------------- status

async function refreshStatus() {
  let status;
  try {
    status = await api("/api/status");
  } catch (error) {
    setSaveState(`Offline: ${error.message}`, "failed");
    return;
  }

  config = status.config;

  $("version").textContent = `v${status.version}`;
  $("uptime").textContent = formatDuration(status.uptime_seconds);

  const counters = status.counters;
  $("stat-dns-queries").textContent = counters.dns_queries.toLocaleString();
  $("stat-dns-blocked").textContent = counters.dns_blocked.toLocaleString();
  $("stat-dns-rate").textContent = percent(counters.dns_blocked, counters.dns_queries);
  $("stat-http-requests").textContent = counters.http_requests.toLocaleString();
  $("stat-http-blocked").textContent = counters.http_blocked.toLocaleString();
  $("stat-http-rate").textContent = percent(counters.http_blocked, counters.http_requests);

  $("fact-blocked-domains").textContent = status.blocked_domains.toLocaleString();
  $("fact-allowed-domains").textContent = status.allowed_domains.toLocaleString();
  $("fact-filter-sources").textContent = status.filter_sources.length
    ? status.filter_sources.join(", ")
    : "none loaded";
  $("fact-ca-hosts").textContent = status.ca_cached_hosts.toLocaleString();

  $("fact-proxy").textContent = config.proxy.enabled
    ? `${config.proxy.listen} (${config.proxy.mitm_enabled ? "intercepting" : "tunnel only"})`
    : "disabled";
  $("fact-dns").textContent = config.dns.enabled ? config.dns.listen : "disabled";
  $("fact-admin").textContent = config.admin.listen;

  $("ca-fingerprint").textContent = status.ca_fingerprint;

  applyConfigToForm();
  renderDomains();
  renderLists("dns-lists", status.dns_lists, "dns");
  renderLists("filter-lists", status.filter_lists, "filtering");
}

// ------------------------------------------------------------------ domains

function renderDomains() {
  renderDomainList("blocked-domains", config.dns.blocked_domains, "blocked");
  renderDomainList("allowed-domains", config.dns.allowed_domains, "allowed");
}

function renderDomainList(elementId, domains, list) {
  const container = $(elementId);
  container.textContent = "";

  if (!domains.length) {
    const empty = document.createElement("li");
    empty.textContent = "none";
    empty.style.opacity = "0.5";
    container.append(empty);
    return;
  }

  for (const domain of domains) {
    const item = document.createElement("li");
    const label = document.createElement("span");
    label.textContent = domain;

    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "link";
    remove.textContent = "\u00d7";
    remove.title = `Remove ${domain}`;
    remove.addEventListener("click", () => editDomain(list, "remove", domain));

    item.append(label, remove);
    container.append(item);
  }
}

async function editDomain(list, action, domain) {
  setSaveState("Saving\u2026", "saving");
  try {
    await api("/api/domains", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ list, action, domain }),
    });
    setSaveState("Saved", "saved");
    await refreshStatus();
  } catch (error) {
    setSaveState(`Save failed: ${error.message}`, "failed");
  }
}

// -------------------------------------------------------------------- lists

/** `section` is the config key holding the list array: "dns" or "filtering". */
function renderLists(elementId, statuses, section) {
  const body = $(elementId);
  body.textContent = "";

  const sources = section === "dns" ? config.dns.blocklists : config.filtering.lists;

  statuses.forEach((status, index) => {
    const row = document.createElement("tr");

    const toggleCell = document.createElement("td");
    const toggle = document.createElement("input");
    toggle.type = "checkbox";
    toggle.checked = status.enabled;
    toggle.title = status.enabled ? "Disable this list" : "Enable this list";
    toggle.addEventListener("change", () => {
      sources[index].enabled = toggle.checked;
      saveConfig({ immediate: true });
    });
    toggleCell.append(toggle);

    const nameCell = document.createElement("td");
    nameCell.textContent = status.name;

    const urlCell = document.createElement("td");
    urlCell.className = "url";
    urlCell.textContent = status.url;
    if (status.error) {
      const error = document.createElement("div");
      error.className = "error-text";
      error.textContent = status.error;
      urlCell.append(error);
    }

    const sizeCell = document.createElement("td");
    sizeCell.className = "numeric";
    sizeCell.textContent = formatBytes(status.bytes);

    const updatedCell = document.createElement("td");
    updatedCell.className = "numeric";
    updatedCell.textContent = formatWhen(status.updated);

    const removeCell = document.createElement("td");
    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "link";
    remove.textContent = "\u00d7";
    remove.title = `Remove ${status.name}`;
    remove.addEventListener("click", () => {
      sources.splice(index, 1);
      saveConfig({ immediate: true });
    });
    removeCell.append(remove);

    row.append(toggleCell, nameCell, urlCell, sizeCell, updatedCell, removeCell);
    body.append(row);
  });
}

function wireAddList(formId, nameId, urlId, section) {
  $(formId).addEventListener("submit", (event) => {
    event.preventDefault();
    const name = $(nameId).value.trim();
    const url = $(urlId).value.trim();
    if (!url) return;

    const sources = section === "dns" ? config.dns.blocklists : config.filtering.lists;
    sources.push({ name: name || url, url, enabled: true });
    $(nameId).value = "";
    $(urlId).value = "";

    // The list is empty until it has been downloaded at least once.
    saveConfig({ immediate: true }).then(() => refreshLists());
  });
}

// -------------------------------------------------------------------- events

async function refreshEvents() {
  let events;
  try {
    events = await api("/api/events?limit=200");
  } catch (_) {
    return;
  }

  const body = $("events-body");
  body.textContent = "";
  $("events-empty").style.display = events.length ? "none" : "block";

  for (const event of events) {
    const row = document.createElement("tr");

    const time = document.createElement("td");
    time.className = "numeric";
    time.textContent = new Date(event.time).toLocaleTimeString();

    const source = document.createElement("td");
    const tag = document.createElement("span");
    tag.className = "tag";
    tag.textContent = event.source;
    source.append(tag);

    const client = document.createElement("td");
    client.className = "numeric";
    client.textContent = event.client;

    const target = document.createElement("td");
    target.className = "url";
    target.textContent = event.target;

    const reason = document.createElement("td");
    reason.className = "url";
    reason.textContent = event.reason;

    row.append(time, source, client, target, reason);
    body.append(row);
  }
}

// ------------------------------------------------------------------ actions

async function refreshLists() {
  const button = $("refresh-lists");
  button.disabled = true;
  const original = button.textContent;
  button.textContent = "Updating\u2026";
  setSaveState("Downloading lists\u2026", "saving");

  try {
    await api("/api/lists/refresh", { method: "POST" });
    setSaveState("Lists updated", "saved");
  } catch (error) {
    setSaveState(`Update failed: ${error.message}`, "failed");
  } finally {
    button.disabled = false;
    button.textContent = original;
    await refreshStatus();
  }
}

// --------------------------------------------------------------------- init

function wireTabs() {
  for (const tab of document.querySelectorAll(".tab")) {
    tab.addEventListener("click", () => {
      for (const other of document.querySelectorAll(".tab")) {
        other.classList.toggle("active", other === tab);
      }
      for (const panel of document.querySelectorAll(".panel")) {
        panel.classList.toggle("active", panel.id === tab.dataset.panel);
      }
    });
  }
}

function wireConfigFields() {
  for (const element of document.querySelectorAll("[data-config]")) {
    // `change` rather than `input`: text fields save on blur, so a rebuild is
    // not triggered on every keystroke.
    element.addEventListener("change", collectAndSave);
  }
}

function wireDomainForms() {
  $("add-blocked").addEventListener("submit", (event) => {
    event.preventDefault();
    const input = $("add-blocked-input");
    if (input.value.trim()) {
      editDomain("blocked", "add", input.value.trim());
      input.value = "";
    }
  });

  $("add-allowed").addEventListener("submit", (event) => {
    event.preventDefault();
    const input = $("add-allowed-input");
    if (input.value.trim()) {
      editDomain("allowed", "add", input.value.trim());
      input.value = "";
    }
  });
}

function wireActions() {
  $("refresh-lists").addEventListener("click", refreshLists);

  $("reload-engines").addEventListener("click", async () => {
    setSaveState("Reloading\u2026", "saving");
    try {
      await api("/api/reload", { method: "POST" });
      setSaveState("Reloaded", "saved");
    } catch (error) {
      setSaveState(`Reload failed: ${error.message}`, "failed");
    }
    await refreshStatus();
  });

  $("clear-events").addEventListener("click", async () => {
    await api("/api/events", { method: "DELETE" });
    await refreshEvents();
  });

  $("events-autorefresh").addEventListener("change", (event) => {
    clearInterval(eventsTimer);
    if (event.target.checked) {
      eventsTimer = setInterval(refreshEvents, 3000);
    }
  });
}

async function init() {
  wireTabs();
  wireConfigFields();
  wireDomainForms();
  wireActions();
  wireAddList("add-dns-list", "add-dns-list-name", "add-dns-list-url", "dns");
  wireAddList("add-filter-list", "add-filter-list-name", "add-filter-list-url", "filtering");

  await refreshStatus();
  await refreshEvents();

  statusTimer = setInterval(refreshStatus, 5000);
  eventsTimer = setInterval(refreshEvents, 3000);
}

document.addEventListener("DOMContentLoaded", init);
