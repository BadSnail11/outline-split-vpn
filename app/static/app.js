const headline = document.querySelector("#headline");
const detail = document.querySelector("#detail");
const warnings = document.querySelector("#warnings");
const summary = document.querySelector("#summary");
const form = document.querySelector("#form");
const keyInput = document.querySelector("#key");
const showKey = document.querySelector("#show-key");
const ipInput = document.querySelector("#ip");
const addButton = document.querySelector("#add");
const ipList = document.querySelector("#ip-list");
const domainInput = document.querySelector("#domain");
const addDomainButton = document.querySelector("#add-domain");
const domainList = document.querySelector("#domain-list");
const appSearch = document.querySelector("#app-search");
const addAppButton = document.querySelector("#add-app");
const appResults = document.querySelector("#app-results");
const appList = document.querySelector("#app-list");
const formError = document.querySelector("#form-error");
const stopButton = document.querySelector("#stop");

let ips = [];
let domains = [];
let apps = [];
let catalog = [];
let busy = false;
let lastStatus = null;

showKey.addEventListener("change", () => {
  keyInput.classList.toggle("revealed", showKey.checked);
});

addButton.addEventListener("click", addIp);
addDomainButton.addEventListener("click", addDomain);
domainInput.addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    event.preventDefault();
    addDomain();
  }
});
ipInput.addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    event.preventDefault();
    addIp();
  }
});
addAppButton.addEventListener("click", addAppFromSearch);
appSearch.addEventListener("input", renderResults);
appSearch.addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    event.preventDefault();
    addAppFromSearch();
  }
});
form.addEventListener("submit", (event) => {
  event.preventDefault();
  apply();
});
stopButton.addEventListener("click", () => {
  post("/api/stop", {});
});

function addIp() {
  const value = ipInput.value.trim();
  if (!value) return;
  if (!ips.includes(value)) ips.push(value);
  ipInput.value = "";
  formError.textContent = "";
  renderList();
}

function addDomain() {
  const value = domainInput.value.trim().toLowerCase().replace(/\.$/, "").replace(/^\*\./, "");
  if (!value) return;
  if (!domains.includes(value)) domains.push(value);
  domainInput.value = "";
  formError.textContent = "";
  renderDomains();
}

function renderDomains() {
  domainList.replaceChildren();
  if (!domains.length) {
    const empty = document.createElement("li");
    empty.className = "empty";
    empty.textContent = "No domains yet.";
    domainList.append(empty);
    return;
  }
  for (const name of domains) {
    const item = document.createElement("li");
    const code = document.createElement("code");
    code.textContent = name;
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = "Remove";
    button.addEventListener("click", () => {
      domains = domains.filter((entry) => entry !== name);
      renderDomains();
    });
    item.append(code, button);
    domainList.append(item);
  }
}

function renderList() {
  ipList.replaceChildren();
  if (!ips.length) {
    const empty = document.createElement("li");
    empty.className = "empty";
    empty.textContent = "No destinations yet.";
    ipList.append(empty);
    return;
  }
  for (const ip of ips) {
    const item = document.createElement("li");
    const code = document.createElement("code");
    code.textContent = ip;
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = "Remove";
    button.addEventListener("click", () => {
      ips = ips.filter((entry) => entry !== ip);
      renderList();
    });
    item.append(code, button);
    ipList.append(item);
  }
}

function sameApp(left, right) {
  return left.exec === right.exec && left.match === right.match;
}

function addProgram(program) {
  if (apps.some((entry) => sameApp(entry, program))) return;
  apps.push(program);
  appSearch.value = "";
  formError.textContent = "";
  renderApps();
  renderResults();
}

function addAppFromSearch() {
  const query = appSearch.value.trim();
  if (!query) return;
  if (query.startsWith("/")) {
    addProgram({ name: query.split("/").pop(), exec: query, match: "exe" });
    return;
  }
  const matches = filterCatalog(query);
  if (matches.length === 1 || (matches[0] && matches[0].name.toLowerCase() === query.toLowerCase())) {
    addProgram(matches[0]);
    return;
  }
  formError.textContent = "Choose an application from the list, or type an absolute path.";
  renderResults();
}

function filterCatalog(query) {
  const needle = query.trim().toLowerCase();
  if (!needle) return [];
  return catalog.filter((item) => {
    return item.name.toLowerCase().includes(needle) || item.exec.toLowerCase().includes(needle);
  }).slice(0, 8);
}

function renderResults() {
  const matches = filterCatalog(appSearch.value);
  appResults.replaceChildren();
  appResults.hidden = matches.length === 0;
  for (const program of matches) {
    const item = document.createElement("li");
    const button = document.createElement("button");
    button.type = "button";
    const title = document.createElement("span");
    title.textContent = program.name;
    const path = document.createElement("small");
    path.textContent = program.exec;
    button.append(title, path);
    button.addEventListener("click", () => addProgram(program));
    item.append(button);
    appResults.append(item);
  }
}

function renderApps() {
  appList.replaceChildren();
  if (!apps.length) {
    const empty = document.createElement("li");
    empty.className = "empty";
    empty.textContent = "No applications yet.";
    appList.append(empty);
    return;
  }
  for (const program of apps) {
    const item = document.createElement("li");
    const text = document.createElement("p");
    const title = document.createElement("span");
    title.textContent = program.name;
    const path = document.createElement("code");
    path.textContent = program.exec;
    text.append(title, path);
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = "Remove";
    button.addEventListener("click", () => {
      apps = apps.filter((entry) => !sameApp(entry, program));
      renderApps();
    });
    item.append(text, button);
    appList.append(item);
  }
}

function renderStatus(data) {
  lastStatus = data;
  headline.textContent = data.headline;
  headline.dataset.state = data.state;
  detail.textContent = data.detail || "";
  warnings.replaceChildren();
  for (const note of data.warnings || []) {
    const item = document.createElement("li");
    item.textContent = note;
    warnings.append(item);
  }
  if (!data.summary) {
    summary.textContent = "No key saved.";
  } else {
    const parts = [data.summary.server, data.summary.method, data.summary.prefix ? "prefix on" : "no prefix"];
    if (data.summary.name) parts.push(data.summary.name);
    summary.textContent = parts.join(" · ");
  }
  stopButton.disabled = busy || (!data.enabled && !data.running);
}

function isDefaultRoute(value) {
  const bits = value.split("/")[1];
  return bits === "0";
}

async function apply() {
  if (ips.some(isDefaultRoute)) {
    const agreed = window.confirm(
      "This list includes a default route. All matching traffic will go through the tunnel. Apply it?"
    );
    if (!agreed) return;
  }
  const ok = await post("/api/apply", { key: keyInput.value, ips, domains, apps });
  if (ok) keyInput.value = "";
}

async function post(url, body) {
  formError.textContent = "";
  setBusy(true);
  try {
    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    let data = {};
    try {
      data = await response.json();
    } catch (_err) {
      data = {};
    }
    if (!response.ok) {
      formError.textContent = data.error || "Request failed";
      return false;
    }
    ips = (data.ips || []).slice();
    domains = (data.domains || []).slice();
    apps = (data.apps || []).slice();
    renderList();
    renderDomains();
    renderApps();
    renderStatus(data);
    return true;
  } catch (_err) {
    formError.textContent = "The app is not reachable.";
    return false;
  } finally {
    setBusy(false);
  }
}

function setBusy(value) {
  busy = value;
  for (const button of form.querySelectorAll("button")) {
    if (button !== stopButton) button.disabled = value;
  }
  appSearch.disabled = value;
  ipInput.disabled = value;
  domainInput.disabled = value;
  if (lastStatus) renderStatus(lastStatus);
  else stopButton.disabled = value;
}

async function refresh() {
  if (busy) return;
  try {
    const response = await fetch("/api/state");
    if (!response.ok) return;
    renderStatus(await response.json());
  } catch (_err) {
    return;
  }
}

async function loadCatalog() {
  try {
    const response = await fetch("/api/catalog");
    if (!response.ok) return;
    const data = await response.json();
    catalog = data.applications || [];
  } catch (_err) {
    catalog = [];
  }
}

async function load() {
  try {
    const response = await fetch("/api/state");
    const data = await response.json();
    ips = (data.ips || []).slice();
    domains = (data.domains || []).slice();
    apps = (data.apps || []).slice();
    renderList();
    renderDomains();
    renderApps();
    renderStatus(data);
  } catch (_err) {
    headline.textContent = "Not routing";
    headline.dataset.state = "down";
    formError.textContent = "The app is not reachable.";
    renderList();
    renderDomains();
    renderApps();
  }
}

load();
loadCatalog();
window.setInterval(refresh, 3000);
