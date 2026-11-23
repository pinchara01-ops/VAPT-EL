const svg = document.querySelector("#graph");
const detailPanel = document.querySelector("#detail-panel");
const emptyState = document.querySelector("#empty-state");
const statusBar = document.querySelector("#status-bar");
const findingsSection = document.querySelector("#findings-section");
const findingsBadge = document.querySelector("#findings-badge");
const findingsList = document.querySelector("#findings-list");

const NS = "http://www.w3.org/2000/svg";
let currentReport = null;

// Design system palette: Navy, Steel, Amber, Oxblood, Cream
const colors = {
  role: "#2E3A5C",
  permission: "#B87A00",
  endpoint: "#1A2645",
  object: "#4A5878",
  finding: "#721121",
};

function element(name, attrs = {}) {
  const node = document.createElementNS(NS, name);
  for (const [key, value] of Object.entries(attrs)) node.setAttribute(key, value);
  return node;
}

function setText(selector, value) {
  const el = document.querySelector(selector);
  if (el) el.textContent = String(value);
}

function loadReport(report) {
  currentReport = report;
  setText("#endpoint-count", report.summary.endpoint_count ?? "—");
  setText("#hidden-count", report.summary.undocumented_count ?? "—");
  setText("#tested-count", report.summary.tested_count ?? "—");
  setText("#finding-count", report.summary.finding_count ?? "0");
  
  if (report.metadata) {
    setText("#target-url", report.metadata.target ?? "—");
    setText("#generated-at", (report.metadata.generated_at ?? "").split(".")[0].replace("T", " ") || "—");
  }

  if (statusBar) {
    statusBar.textContent = `TARGET: ${report.metadata?.target || "LOCAL"} // STATUS: COMPLETE`;
  }

  if (emptyState) emptyState.style.display = "none";
  if (svg) svg.style.display = "block";
  drawGraph(report.graph);
  renderFindings(report.findings || []);
}

function drawGraph(graph) {
  if (!svg || !graph) return;
  svg.replaceChildren();

  const order = ["role", "permission", "endpoint", "object"];
  const xByKind = { role: 120, permission: 340, endpoint: 650, object: 960 };
  const grouped = Object.fromEntries(order.map((kind) => [kind, (graph.nodes || []).filter((n) => n.kind === kind)]));
  const maxRows = Math.max(...order.map((kind) => grouped[kind].length), 1);
  const height = Math.max(620, maxRows * 110 + 90);
  svg.setAttribute("viewBox", `0 0 1150 ${height}`);

  const positions = new Map();
  for (const kind of order) {
    const nodes = grouped[kind];
    const step = height / (nodes.length + 1);
    nodes.forEach((node, index) => positions.set(node.id, { x: xByKind[kind], y: step * (index + 1) }));
  }

  // Draw straight, uncurved orthogonal lines (manhattan / sharp architectural lines)
  for (const edge of graph.edges || []) {
    const source = positions.get(edge.source);
    const target = positions.get(edge.target);
    if (!source || !target) continue;

    const isFinding = edge.kind === "observed-allow" && edge.source.includes("anonymous") === false && edge.target.includes("audit");
    const strokeColor = edge.kind === "observed-allow" 
      ? "#0A1128" 
      : edge.kind === "observed-deny" 
        ? "#4A5878" 
        : "#2E3A5C";

    // Crisp straight line connecting nodes
    const line = element("line", {
      x1: source.x,
      y1: source.y,
      x2: target.x,
      y2: target.y,
      stroke: strokeColor,
      "stroke-width": edge.kind.startsWith("observed") ? "1.5" : "1",
      "stroke-dasharray": edge.kind === "observed-deny" ? "4,4" : "none",
      opacity: edge.kind === "observed-deny" ? "0.45" : "0.85",
    });
    svg.append(line);
  }

  // Draw sharp rectangular / diamond nodes (Zero border radius)
  for (const node of graph.nodes || []) {
    const position = positions.get(node.id);
    if (!position) continue;

    const group = element("g", { tabindex: "0", role: "button", "aria-label": node.label });
    group.style.cursor = node.kind === "endpoint" ? "pointer" : "default";

    const width = node.kind === "endpoint" ? 250 : 150;
    const heightNode = 46;
    const x = position.x - width / 2;
    const y = position.y - heightNode / 2;

    const isFailed = node.has_finding;
    const strokeColor = isFailed ? "#721121" : colors[node.kind] || "#0A1128";
    const strokeWidth = isFailed ? "3" : "1.5";
    const fill = isFailed ? "#F7F7F4" : "#F7F7F4";

    // Sharp rectangle node - NO rx, NO ry
    const rect = element("rect", {
      x,
      y,
      width,
      height: heightNode,
      fill: fill,
      stroke: strokeColor,
      "stroke-width": strokeWidth,
    });

    // If finding, add brutalist hard offset shadow rectangle behind or outline accent
    if (isFailed) {
      const shadow = element("rect", {
        x: x + 3,
        y: y + 3,
        width,
        height: heightNode,
        fill: "#721121",
        stroke: "none",
      });
      group.append(shadow);
    }

    group.append(rect);

    // Node header / indicator accent (architectural schematic touch)
    const headerLine = element("line", {
      x1: x,
      y1: y + 8,
      x2: x + width,
      y2: y + 8,
      stroke: strokeColor,
      "stroke-width": "1",
      opacity: "0.4",
    });
    group.append(headerLine);

    const label = element("text", {
      x: position.x,
      y: position.y + 7,
      fill: isFailed ? "#721121" : "#0A1128",
      "text-anchor": "middle",
      "font-size": node.kind === "endpoint" ? "12" : "11",
      "font-family": "JetBrains Mono, monospace",
      "font-weight": isFailed ? "700" : "600",
    });
    label.textContent = node.label.length > 28 ? `${node.label.slice(0, 26)}…` : node.label;
    group.append(label);

    if (node.kind === "endpoint") {
      group.addEventListener("click", () => showEndpoint(node.label));
      group.addEventListener("keydown", (event) => {
        if (event.key === "Enter" || event.key === " ") showEndpoint(node.label);
      });
    }
    svg.append(group);
  }
}

function htmlNode(name, text, className) {
  const node = document.createElement(name);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function showEndpoint(key) {
  if (!currentReport) return;
  const endpoint = currentReport.endpoints.find((item) => item.key === key);
  if (!endpoint) return;

  const detailBody = detailPanel.querySelector(".detail-body");
  if (!detailBody) return;
  detailBody.replaceChildren();

  // Route status banner
  const isUndoc = endpoint.undocumented;
  const statusBanner = htmlNode(
    "div",
    isUndoc ? "⚠️ UNDOCUMENTED ROUTE (MISSING FROM OPENAPI)" : "✓ DOCUMENTED IN SPECIFICATION",
    `route-status ${isUndoc ? "undocumented" : "documented"}`
  );
  detailBody.append(statusBanner);

  // Key
  detailBody.append(htmlNode("div", endpoint.key, "detail-key"));

  // Source tags
  const tags = htmlNode("div", undefined, "tags");
  (endpoint.sources || []).forEach((src) => {
    tags.append(htmlNode("span", src, "tag"));
  });
  if (isUndoc) tags.append(htmlNode("span", "HIDDEN", "tag hidden"));
  detailBody.append(tags);

  // Policy block (Technical datasheet format)
  const policyBlock = htmlNode("div", undefined, "policy-block");
  const pHeader = htmlNode("div", "POLICY SPECIFICATION", "policy-block-header");
  const pBody = htmlNode("div", undefined, "policy-block-body");

  if (endpoint.policy) {
    const pObj = htmlNode("div", undefined, "policy-row");
    pObj.append(htmlNode("span", "OBJECT", "policy-key"));
    pObj.append(htmlNode("span", endpoint.policy.object, "policy-val mono"));
    pBody.append(pObj);

    const pPerm = htmlNode("div", undefined, "policy-row");
    pPerm.append(htmlNode("span", "PERM", "policy-key"));
    pPerm.append(htmlNode("span", endpoint.policy.permission, "policy-val mono"));
    pBody.append(pPerm);

    const pAllow = htmlNode("div", undefined, "policy-row");
    pAllow.append(htmlNode("span", "ALLOWED", "policy-key"));
    pAllow.append(htmlNode("span", (endpoint.policy.allowed_identities || []).join(", "), "policy-val mono"));
    pBody.append(pAllow);

    if (endpoint.policy.owasp) {
      const owasp = htmlNode("div", endpoint.policy.owasp, "owasp-tag");
      pBody.append(owasp);
    }
  } else {
    pBody.append(htmlNode("p", "No manual policy specified. Endpoint correlation only.", "mono"));
  }

  policyBlock.append(pHeader, pBody);
  detailBody.append(policyBlock);

  // Observations
  const obsTitle = htmlNode("div", "OBSERVED RESPONSES", "policy-block-header");
  obsTitle.style.marginBottom = "0.75rem";
  detailBody.append(obsTitle);

  (endpoint.observations || []).forEach((obs) => {
    const unexpected = obs.expected === "deny" && obs.granted;
    const card = htmlNode("div", undefined, `obs-card ${unexpected ? "unexpected" : ""}`);

    const header = htmlNode("div", undefined, "obs-header");
    header.append(htmlNode("span", `${obs.identity} [${obs.role}]`, "obs-identity"));
    header.append(htmlNode("span", `HTTP ${obs.status ?? "ERR"} · EXP: ${obs.expected.toUpperCase()}`, "obs-status"));
    card.append(header);

    if (unexpected) {
      card.append(htmlNode("div", "CRITICAL BOLA/BFLA VIOLATION: Access granted to unauthorized identity", "obs-alert"));
    }

    const bodyBlock = htmlNode("div", undefined, "obs-body-block");
    bodyBlock.append(htmlNode("div", "RESPONSE BODY (SENSITIVE FIELDS REDACTED)", "obs-body-label"));

    const pre = document.createElement("pre");
    const jsonStr = JSON.stringify(obs.body ?? obs.error ?? {}, null, 2);
    
    // Highlight <redacted> inside code blocks
    if (jsonStr.includes("<redacted>")) {
      const parts = jsonStr.split("<redacted>");
      parts.forEach((part, idx) => {
        pre.appendChild(document.createTextNode(part));
        if (idx < parts.length - 1) {
          const mark = document.createElement("span");
          mark.className = "redacted-mark";
          mark.textContent = "<redacted>";
          pre.appendChild(mark);
        }
      });
    } else {
      pre.textContent = jsonStr;
    }

    bodyBlock.append(pre);
    card.append(bodyBlock);
    detailBody.append(card);
  });
}

function renderFindings(findings) {
  if (!findingsSection || !findingsList) return;
  if (!findings || findings.length === 0) {
    findingsSection.style.display = "none";
    return;
  }

  findingsSection.style.display = "block";
  if (findingsBadge) findingsBadge.textContent = `${findings.length} DETECTED`;
  findingsList.replaceChildren();

  // Header row
  const hRow = htmlNode("div", undefined, "finding-row header-row");
  hRow.append(htmlNode("div", "FINDING ID", "finding-cell"));
  hRow.append(htmlNode("div", "TITLE & TARGET", "finding-cell"));
  hRow.append(htmlNode("div", "SEVERITY", "finding-cell"));
  hRow.append(htmlNode("div", "UNAUTHORIZED IDENTITIES", "finding-cell"));
  findingsList.append(hRow);

  findings.forEach((f) => {
    const row = htmlNode("div", undefined, "finding-row");
    row.append(htmlNode("div", f.id, "finding-cell finding-id"));

    const info = htmlNode("div", undefined, "finding-cell");
    info.append(htmlNode("div", f.title, "finding-title"));
    info.append(htmlNode("div", `${f.category} — ${f.endpoint}`, "finding-endpoint"));
    row.append(info);

    const sevCell = htmlNode("div", undefined, "finding-cell");
    const sevBadge = htmlNode("span", (f.severity || "MEDIUM").toUpperCase(), `sev-badge sev-${(f.severity || "medium").toLowerCase()}`);
    sevCell.append(sevBadge);
    row.append(sevCell);

    const idCell = htmlNode("div", undefined, "finding-cell finding-identities");
    idCell.textContent = (f.unexpected_identities || []).join(", ") || "—";
    row.append(idCell);

    findingsList.append(row);
  });
}

// File loading
const reportFileInput = document.querySelector("#report-file");
if (reportFileInput) {
  reportFileInput.addEventListener("change", async (event) => {
    const [file] = event.target.files;
    if (!file) return;
    try {
      const text = await file.text();
      loadReport(JSON.parse(text));
    } catch (err) {
      if (statusBar) statusBar.textContent = "ERR: INVALID JSON REPORT";
    }
  });
}

// Auto-load demo report if served
fetch("../artifacts/demo-report.json")
  .then((response) => {
    if (!response.ok) throw new Error("No generated report yet");
    return response.json();
  })
  .then(loadReport)
  .catch(() => {});
