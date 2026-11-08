"use strict";

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
