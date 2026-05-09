import { analyzeCapture } from "./analyzer.js";

const api = globalThis.browser || globalThis.chrome;

const elements = {
  targetUrl: document.querySelector("#targetUrl"),
  permissionState: document.querySelector("#permissionState"),
  grantButton: document.querySelector("#grantButton"),
  refreshButton: document.querySelector("#refreshButton"),
  copyButton: document.querySelector("#copyButton"),
  exportButton: document.querySelector("#exportButton"),
  clearButton: document.querySelector("#clearButton"),
  scoreValue: document.querySelector("#scoreValue"),
  gradeValue: document.querySelector("#gradeValue"),
  status: document.querySelector("#status"),
  findings: document.querySelector("#findings"),
  headersList: document.querySelector("#headersList")
};

let latestContext = null;
let latestAnalysis = null;

function setStatus(message, type = "ok") {
  elements.status.textContent = message;
  elements.status.classList.toggle("error", type === "error");
}

function enableExport(enabled) {
  elements.copyButton.disabled = !enabled;
  elements.exportButton.disabled = !enabled;
}

function renderFinding(finding) {
  const node = document.createElement("article");
  node.className = `finding ${finding.status}`;
  const title = document.createElement("h2");
  title.textContent = `${finding.header}: ${finding.message}`;
  const detail = document.createElement("p");
  detail.textContent = finding.detail || "";
  node.append(title, detail);
  return node;
}

function renderHeaders(headers) {
  elements.headersList.replaceChildren();
  if (!headers?.length) {
    const term = document.createElement("dt");
    term.textContent = "No security headers";
    const detail = document.createElement("dd");
    detail.textContent = "Reload the page after granting origin permission.";
    elements.headersList.append(term, detail);
    return;
  }
  for (const header of headers) {
    const term = document.createElement("dt");
    term.textContent = header.name;
    const detail = document.createElement("dd");
    detail.textContent = header.value;
    elements.headersList.append(term, detail);
  }
}

function renderContext(context) {
  latestContext = context;
  const tabUrl = context?.tab?.url || "";
  elements.targetUrl.textContent = tabUrl || "No active HTTP(S) page.";
  elements.permissionState.textContent = context?.granted ? "Origin permission granted" : "Origin permission not granted";
  elements.permissionState.style.color = context?.granted ? "var(--good)" : "var(--warn)";

  if (!context?.capture) {
    latestAnalysis = null;
    elements.scoreValue.textContent = "0";
    elements.gradeValue.textContent = "No capture";
    elements.findings.replaceChildren();
    renderHeaders([]);
    enableExport(false);
    setStatus(context?.granted
      ? "No headers captured yet. Reload the tab, then refresh the lens."
      : "Grant this origin, reload the tab, then refresh the lens."
    );
    return;
  }

  latestAnalysis = analyzeCapture(context.capture);
  elements.scoreValue.textContent = String(latestAnalysis.score);
  elements.gradeValue.textContent = latestAnalysis.grade;
  elements.findings.replaceChildren();
  for (const finding of latestAnalysis.findings) {
    elements.findings.append(renderFinding(finding));
  }
  renderHeaders(latestAnalysis.securityHeaders);
  enableExport(true);
  setStatus(`Captured ${context.capture.statusCode} ${context.capture.type} headers at ${context.capture.capturedAt}.`);
}

async function refreshContext() {
  try {
    const context = await api.runtime.sendMessage({ type: "get-active-context" });
    renderContext(context);
  } catch (error) {
    setStatus(error.message || String(error), "error");
  }
}

async function grantOrigin() {
  try {
    const result = await api.runtime.sendMessage({ type: "request-origin-permission" });
    if (!result?.granted) {
      setStatus("Origin permission was not granted.", "error");
      return;
    }
    await refreshContext();
    setStatus(`Granted ${result.pattern}. Reload the tab to capture fresh headers.`);
  } catch (error) {
    setStatus(error.message || String(error), "error");
  }
}

function exportJson() {
  if (!latestContext?.capture || !latestAnalysis) {
    return;
  }
  const host = latestContext.capture.host || "headers";
  const stamp = latestContext.capture.capturedAt.replace(/[:.]/g, "-");
  const filename = `vega-security-headers-${host}-${stamp}.json`;
  const payload = {
    capture: latestContext.capture,
    analysis: latestAnalysis
  };
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
  setStatus("Exported JSON report.");
}

async function copyMarkdown() {
  if (!latestContext?.capture || !latestAnalysis) {
    return;
  }
  const lines = [
    `# Security Header Lens: ${latestContext.capture.host}`,
    "",
    `- URL: ${latestContext.capture.url}`,
    `- Captured: ${latestContext.capture.capturedAt}`,
    `- Status: ${latestContext.capture.statusCode}`,
    `- Score: ${latestAnalysis.score} (${latestAnalysis.grade})`,
    "",
    "## Findings",
    ...latestAnalysis.findings.map((finding) =>
      `- [${finding.status}] ${finding.header}: ${finding.message}${finding.detail ? ` - ${finding.detail}` : ""}`
    ),
    "",
    "## Observed Security Headers",
    ...latestAnalysis.securityHeaders.map((header) => `- ${header.name}: \`${header.value}\``)
  ];
  try {
    await navigator.clipboard.writeText(lines.join("\n"));
    setStatus("Copied Markdown report.");
  } catch (error) {
    setStatus(`Clipboard failed: ${error.message}`, "error");
  }
}

async function clearCaptures() {
  try {
    await api.runtime.sendMessage({ type: "clear-captures" });
    await refreshContext();
    setStatus("Local header captures cleared.");
  } catch (error) {
    setStatus(error.message || String(error), "error");
  }
}

elements.grantButton.addEventListener("click", grantOrigin);
elements.refreshButton.addEventListener("click", refreshContext);
elements.exportButton.addEventListener("click", exportJson);
elements.copyButton.addEventListener("click", copyMarkdown);
elements.clearButton.addEventListener("click", clearCaptures);
refreshContext();
