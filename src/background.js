const api = globalThis.browser || globalThis.chrome;

const CAPTURES_KEY = "vegaHeaderLens:captures";
const MAX_CAPTURES = 120;

let captures = [];

function isHttpUrl(url) {
  try {
    return ["http:", "https:"].includes(new URL(url).protocol);
  } catch {
    return false;
  }
}

function normalizeHeaders(headers = []) {
  const normalized = {};
  for (const header of headers) {
    const name = String(header.name || "").toLowerCase();
    const value = String(header.value || "").trim();
    if (!name || !value) {
      continue;
    }
    normalized[name] = normalized[name] ? `${normalized[name]}, ${value}` : value;
  }
  return normalized;
}

function publicCapture(details) {
  const url = new URL(details.url);
  return {
    id: `${Date.now()}-${Math.random().toString(16).slice(2)}`,
    capturedAt: new Date().toISOString(),
    tabId: details.tabId,
    frameId: details.frameId,
    parentFrameId: details.parentFrameId,
    requestId: details.requestId,
    type: details.type,
    method: details.method,
    statusCode: details.statusCode,
    url: details.url,
    origin: url.origin,
    host: url.host,
    path: url.pathname,
    headers: normalizeHeaders(details.responseHeaders)
  };
}

async function persistCaptures() {
  await api.storage.local.set({ [CAPTURES_KEY]: captures.slice(0, MAX_CAPTURES) });
}

async function loadCaptures() {
  const data = await api.storage.local.get(CAPTURES_KEY);
  captures = Array.isArray(data?.[CAPTURES_KEY]) ? data[CAPTURES_KEY].slice(0, MAX_CAPTURES) : [];
}

function rememberCapture(details) {
  if (details.tabId < 0 || !isHttpUrl(details.url)) {
    return;
  }
  captures.unshift(publicCapture(details));
  captures = captures.slice(0, MAX_CAPTURES);
  persistCaptures().catch(() => {});
}

function currentOriginPattern(url) {
  try {
    const parsed = new URL(url);
    if (!["http:", "https:"].includes(parsed.protocol)) {
      return null;
    }
    return `${parsed.protocol}//${parsed.host}/*`;
  } catch {
    return null;
  }
}

async function getActiveTab() {
  const tabs = await api.tabs.query({ active: true, currentWindow: true });
  return tabs?.[0] || null;
}

async function getCaptureForTab(tab) {
  if (!tab?.id || !tab?.url) {
    return null;
  }
  const exactMainFrame = captures.find((capture) =>
    capture.tabId === tab.id &&
    capture.type === "main_frame" &&
    capture.url === tab.url
  );
  if (exactMainFrame) {
    return exactMainFrame;
  }
  const sameOriginMainFrame = captures.find((capture) =>
    capture.tabId === tab.id &&
    capture.type === "main_frame" &&
    currentOriginPattern(capture.url) === currentOriginPattern(tab.url)
  );
  return sameOriginMainFrame || null;
}

async function hasOriginPermission(pattern) {
  if (!pattern) {
    return false;
  }
  return api.permissions.contains({ origins: [pattern] });
}

async function requestOriginPermission(pattern) {
  if (!pattern) {
    return false;
  }
  return api.permissions.request({ origins: [pattern] });
}

api.webRequest.onHeadersReceived.addListener(
  rememberCapture,
  {
    urls: ["http://*/*", "https://*/*"],
    types: ["main_frame", "sub_frame"]
  },
  ["responseHeaders"]
);

api.runtime.onMessage.addListener((message) => {
  if (!message || typeof message.type !== "string") {
    return undefined;
  }

  if (message.type === "get-active-context") {
    return (async () => {
      const tab = await getActiveTab();
      const pattern = currentOriginPattern(tab?.url || "");
      const granted = await hasOriginPermission(pattern);
      const capture = await getCaptureForTab(tab);
      return {
        tab: tab ? { id: tab.id, url: tab.url, title: tab.title || "" } : null,
        pattern,
        granted,
        capture
      };
    })();
  }

  if (message.type === "request-origin-permission") {
    return (async () => {
      const tab = await getActiveTab();
      const pattern = currentOriginPattern(tab?.url || "");
      const granted = await requestOriginPermission(pattern);
      return { pattern, granted };
    })();
  }

  if (message.type === "clear-captures") {
    return (async () => {
      captures = [];
      await persistCaptures();
      return { cleared: true };
    })();
  }

  return undefined;
});

loadCaptures().catch(() => {});
