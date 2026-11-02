const svg = document.querySelector("#graph");
const detailPanel = document.querySelector("#detail-panel");
const emptyState = document.querySelector("#empty-state");
const NS = "http://www.w3.org/2000/svg";
let currentReport = null;

const colors = {
  role: "#52e0a4",
  permission: "#ffbf69",
  endpoint: "#65b8ff",
  object: "#c899ff",
};

function element(name, attrs = {}) {
  const node = document.createElementNS(NS, name);
  for (const [key, value] of Object.entries(attrs)) node.setAttribute(key, value);
  return node;
}

function setText(selector, value) {
  document.querySelector(selector).textContent = String(value);
}

function loadReport(report) {
  currentReport = report;
  setText("#endpoint-count", report.summary.endpoint_count);
  setText("#hidden-count", report.summary.undocumented_count);
  setText("#tested-count", report.summary.tested_count);
  setText("#finding-count", report.summary.finding_count);
  emptyState.style.display = "none";
  svg.style.display = "block";
  drawGraph(report.graph);
}

function drawGraph(graph) {
  svg.replaceChildren();
  const order = ["role", "permission", "endpoint", "object"];
  const xByKind = { role: 100, permission: 330, endpoint: 620, object: 960 };
  const grouped = Object.fromEntries(order.map((kind) => [kind, graph.nodes.filter((n) => n.kind === kind)]));
  const maxRows = Math.max(...order.map((kind) => grouped[kind].length), 1);
  const height = Math.max(620, maxRows * 115 + 80);
  svg.setAttribute("viewBox", `0 0 1100 ${height}`);

  const positions = new Map();
  for (const kind of order) {
    const nodes = grouped[kind];
    const step = height / (nodes.length + 1);
    nodes.forEach((node, index) => positions.set(node.id, { x: xByKind[kind], y: step * (index + 1) }));
  }

  for (const edge of graph.edges) {
    const source = positions.get(edge.source);
    const target = positions.get(edge.target);
    if (!source || !target) continue;
    const path = element("path", {
      d: `M ${source.x} ${source.y} C ${(source.x + target.x) / 2} ${source.y}, ${(source.x + target.x) / 2} ${target.y}, ${target.x} ${target.y}`,
      fill: "none",
      stroke: edge.kind === "observed-allow" ? "#315d4d" : "#263b35",
      "stroke-width": edge.kind.startsWith("observed") ? 1.5 : 1,
      opacity: ".75",
    });
    svg.append(path);
  }

  for (const node of graph.nodes) {
    const position = positions.get(node.id);
    if (!position) continue;
    const group = element("g", { tabindex: "0", role: "button", "aria-label": node.label });
    group.style.cursor = node.kind === "endpoint" ? "pointer" : "default";
    const width = node.kind === "endpoint" ? 250 : 150;
    const rect = element("rect", {
      x: position.x - width / 2,
      y: position.y - 26,
      width,
      height: 52,
      rx: 10,
      fill: "#10211d",
      stroke: node.has_finding ? "#ff6b6b" : colors[node.kind],
      "stroke-width": node.has_finding ? 3 : 1.5,
    });
    const label = element("text", {
      x: position.x,
      y: position.y + 4,
      fill: "#edf7f3",
      "text-anchor": "middle",
      "font-size": node.kind === "endpoint" ? 13 : 12,
      "font-family": "ui-monospace, monospace",
    });
    label.textContent = node.label.length > 32 ? `${node.label.slice(0, 30)}…` : node.label;
    group.append(rect, label);
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
  const endpoint = currentReport.endpoints.find((item) => item.key === key);
  detailPanel.replaceChildren();
  detailPanel.append(htmlNode("p", endpoint.undocumented ? "UNDOCUMENTED ROUTE" : "DOCUMENTED ROUTE", "eyebrow"));
  detailPanel.append(htmlNode("h2", endpoint.key));
  const tags = document.createElement("div");
  endpoint.sources.forEach((source) => tags.append(htmlNode("span", source, "tag")));
  if (endpoint.undocumented) tags.append(htmlNode("span", "hidden from OpenAPI", "tag hidden"));
  detailPanel.append(tags);

  if (endpoint.policy) {
    const policy = document.createElement("div");
    policy.className = "policy";
    policy.append(htmlNode("strong", "Expected policy"));
    policy.append(htmlNode("p", `${endpoint.policy.permission} on ${endpoint.policy.object}`));
    policy.append(htmlNode("small", `Allowed: ${endpoint.policy.allowed_identities.join(", ")}`));
    detailPanel.append(policy);
  } else {
    detailPanel.append(htmlNode("p", "No policy is configured, so this endpoint was discovered but not tested."));
  }

  endpoint.observations.forEach((observation) => {
    const unexpected = observation.expected === "deny" && observation.granted;
    const card = document.createElement("section");
    card.className = `observation${unexpected ? " unexpected" : ""}`;
    const heading = document.createElement("header");
    heading.append(htmlNode("strong", `${observation.identity} · ${observation.role}`));
    heading.append(htmlNode("span", `${observation.status ?? "ERR"} · expected ${observation.expected}`, "status"));
    card.append(heading);
    if (unexpected) card.append(htmlNode("p", "Policy failure: this identity was expected to be denied."));
    const body = htmlNode("pre", JSON.stringify(observation.body ?? observation.error, null, 2));
    card.append(body);
    detailPanel.append(card);
  });
}

document.querySelector("#report-file").addEventListener("change", async (event) => {
  const [file] = event.target.files;
  if (!file) return;
  loadReport(JSON.parse(await file.text()));
});

fetch("../artifacts/demo-report.json")
  .then((response) => {
    if (!response.ok) throw new Error("No generated report yet");
    return response.json();
  })
  .then(loadReport)
  .catch(() => {});

