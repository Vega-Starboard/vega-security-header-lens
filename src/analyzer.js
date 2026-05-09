export const SECURITY_HEADERS = [
  "content-security-policy",
  "content-security-policy-report-only",
  "strict-transport-security",
  "x-frame-options",
  "referrer-policy",
  "permissions-policy",
  "access-control-allow-origin",
  "access-control-allow-credentials",
  "access-control-allow-methods",
  "access-control-allow-headers",
  "x-content-type-options",
  "cross-origin-opener-policy",
  "cross-origin-embedder-policy",
  "cross-origin-resource-policy",
  "server",
  "x-powered-by"
];

const VALID_REFERRER_POLICIES = new Set([
  "no-referrer",
  "no-referrer-when-downgrade",
  "origin",
  "origin-when-cross-origin",
  "same-origin",
  "strict-origin",
  "strict-origin-when-cross-origin",
  "unsafe-url"
]);

function get(headers, name) {
  return headers[String(name).toLowerCase()];
}

function parseDirectives(value = "") {
  const directives = {};
  for (const part of value.split(";")) {
    const trimmed = part.trim();
    if (!trimmed) {
      continue;
    }
    const [name, ...tokens] = trimmed.split(/\s+/);
    directives[name.toLowerCase()] = tokens;
  }
  return directives;
}

function parseHsts(value = "") {
  const directives = {};
  for (const part of value.split(";")) {
    const [rawName, rawValue] = part.trim().split("=");
    if (!rawName) {
      continue;
    }
    directives[rawName.toLowerCase()] = rawValue === undefined ? true : rawValue;
  }
  return directives;
}

function addFinding(findings, status, header, message, detail = "") {
  findings.push({ status, header, message, detail });
}

function analyzeCsp(headers, findings) {
  const csp = get(headers, "content-security-policy");
  const reportOnly = get(headers, "content-security-policy-report-only");
  if (!csp && reportOnly) {
    addFinding(findings, "warn", "Content-Security-Policy", "CSP is report-only.", "Good for rollout, but it does not enforce restrictions.");
    return;
  }
  if (!csp) {
    addFinding(findings, "warn", "Content-Security-Policy", "Missing CSP.", "Consider an enforceable policy appropriate for this application.");
    return;
  }

  const directives = parseDirectives(csp);
  addFinding(findings, "good", "Content-Security-Policy", "CSP is present.", `${Object.keys(directives).length} directives detected.`);

  if (!directives["default-src"]) {
    addFinding(findings, "warn", "CSP default-src", "Missing default-src.", "default-src provides fallback behavior for many fetch directives.");
  }
  if (!directives["base-uri"]) {
    addFinding(findings, "info", "CSP base-uri", "Missing base-uri.", "base-uri can reduce risk from injected base tags.");
  }
  if (!directives["frame-ancestors"]) {
    addFinding(findings, "info", "CSP frame-ancestors", "Missing frame-ancestors.", "X-Frame-Options may still cover older patterns, but frame-ancestors is more flexible.");
  }
  const scriptTokens = directives["script-src"] || directives["default-src"] || [];
  if (scriptTokens.includes("'unsafe-inline'")) {
    addFinding(findings, "warn", "CSP script-src", "script-src allows unsafe-inline.", "Inline script allowance weakens XSS mitigation.");
  }
  if (scriptTokens.includes("'unsafe-eval'")) {
    addFinding(findings, "warn", "CSP script-src", "script-src allows unsafe-eval.", "Eval-like execution increases script injection risk.");
  }
  if (scriptTokens.includes("*")) {
    addFinding(findings, "warn", "CSP script-src", "script-src allows wildcard sources.", "Wildcards make script trust boundaries harder to reason about.");
  }
}

function analyzeHsts(headers, capture, findings) {
  const hsts = get(headers, "strict-transport-security");
  if (capture.url.startsWith("http://")) {
    addFinding(findings, "info", "Strict-Transport-Security", "Page was loaded over HTTP.", "Browsers ignore HSTS delivered over insecure HTTP.");
    return;
  }
  if (!hsts) {
    addFinding(findings, "warn", "Strict-Transport-Security", "Missing HSTS.", "HTTPS sites commonly send HSTS to require future HTTPS connections.");
    return;
  }
  const directives = parseHsts(hsts);
  const maxAge = Number(directives["max-age"]);
  if (!Number.isFinite(maxAge) || maxAge <= 0) {
    addFinding(findings, "warn", "Strict-Transport-Security", "HSTS max-age is missing or disabled.", hsts);
  } else if (maxAge < 15552000) {
    addFinding(findings, "warn", "Strict-Transport-Security", "HSTS max-age is short.", `${maxAge} seconds.`);
  } else {
    addFinding(findings, "good", "Strict-Transport-Security", "HSTS is present.", `${maxAge} seconds.`);
  }
  if (!directives.includesubdomains) {
    addFinding(findings, "info", "Strict-Transport-Security", "includeSubDomains is not set.", "This may be intentional for staged rollouts.");
  }
}

function analyzeFraming(headers, findings) {
  const xfo = get(headers, "x-frame-options");
  const csp = get(headers, "content-security-policy");
  const hasFrameAncestors = csp && Object.hasOwn(parseDirectives(csp), "frame-ancestors");
  if (!xfo && !hasFrameAncestors) {
    addFinding(findings, "warn", "Framing", "No X-Frame-Options or CSP frame-ancestors detected.", "Consider clickjacking protections where framing is not required.");
    return;
  }
  if (xfo) {
    const normalized = xfo.trim().toUpperCase();
    if (normalized === "DENY" || normalized === "SAMEORIGIN") {
      addFinding(findings, "good", "X-Frame-Options", `X-Frame-Options is ${normalized}.`);
    } else {
      addFinding(findings, "warn", "X-Frame-Options", "X-Frame-Options value is unusual or obsolete.", xfo);
    }
  }
  if (hasFrameAncestors) {
    addFinding(findings, "good", "CSP frame-ancestors", "CSP frame-ancestors is present.");
  }
}

function analyzeReferrer(headers, findings) {
  const value = get(headers, "referrer-policy");
  if (!value) {
    addFinding(findings, "info", "Referrer-Policy", "Missing Referrer-Policy.", "Browsers have defaults, but explicit policy improves reviewability.");
    return;
  }
  const tokens = value.split(",").map((item) => item.trim().toLowerCase()).filter(Boolean);
  const invalid = tokens.filter((token) => !VALID_REFERRER_POLICIES.has(token));
  if (invalid.length) {
    addFinding(findings, "warn", "Referrer-Policy", "Referrer-Policy contains unknown values.", invalid.join(", "));
  } else if (tokens.includes("unsafe-url")) {
    addFinding(findings, "warn", "Referrer-Policy", "Referrer-Policy includes unsafe-url.", "This can expose full URLs to destinations.");
  } else {
    addFinding(findings, "good", "Referrer-Policy", "Referrer-Policy is present.", value);
  }
}

function analyzePermissions(headers, findings) {
  const value = get(headers, "permissions-policy");
  if (!value) {
    addFinding(findings, "info", "Permissions-Policy", "Missing Permissions-Policy.", "This may be acceptable, but explicit browser feature policy helps reduce ambient capability.");
    return;
  }
  addFinding(findings, "good", "Permissions-Policy", "Permissions-Policy is present.", `${value.split(",").length} feature declarations detected.`);
}

function analyzeCors(headers, findings) {
  const acao = get(headers, "access-control-allow-origin");
  const acac = get(headers, "access-control-allow-credentials");
  if (!acao && !acac) {
    addFinding(findings, "info", "CORS", "No CORS response headers observed.", "This is common for ordinary HTML responses.");
    return;
  }
  if (acao === "*") {
    addFinding(findings, acac === "true" ? "warn" : "info", "Access-Control-Allow-Origin", "Wildcard ACAO detected.", "Confirm this is intentional for the resource type.");
  } else if (acao) {
    addFinding(findings, "info", "Access-Control-Allow-Origin", "Specific ACAO value observed.", acao);
  }
  if (acac === "true") {
    addFinding(findings, "info", "Access-Control-Allow-Credentials", "Credentialed CORS is enabled.", "Review together with ACAO and application authorization rules.");
  }
}

function analyzeSniffing(headers, findings) {
  const value = get(headers, "x-content-type-options");
  if (!value) {
    addFinding(findings, "info", "X-Content-Type-Options", "Missing X-Content-Type-Options.", "nosniff is commonly used to reduce MIME sniffing surprises.");
  } else if (value.trim().toLowerCase() === "nosniff") {
    addFinding(findings, "good", "X-Content-Type-Options", "X-Content-Type-Options is nosniff.");
  } else {
    addFinding(findings, "warn", "X-Content-Type-Options", "Unexpected X-Content-Type-Options value.", value);
  }
}

function analyzeIsolation(headers, findings) {
  const coop = get(headers, "cross-origin-opener-policy");
  const coep = get(headers, "cross-origin-embedder-policy");
  const corp = get(headers, "cross-origin-resource-policy");
  if (coop) {
    addFinding(findings, coop.includes("same-origin") ? "good" : "info", "Cross-Origin-Opener-Policy", "COOP is present.", coop);
  }
  if (coep) {
    addFinding(findings, coep.includes("require-corp") || coep.includes("credentialless") ? "good" : "info", "Cross-Origin-Embedder-Policy", "COEP is present.", coep);
  }
  if (corp) {
    addFinding(findings, "info", "Cross-Origin-Resource-Policy", "CORP is present.", corp);
  }
  if (!coop && !coep && !corp) {
    addFinding(findings, "info", "Cross-Origin Isolation", "No COOP, COEP, or CORP headers observed.", "This is not always required; review if the app needs cross-origin isolation.");
  }
}

function analyzeDisclosure(headers, findings) {
  if (get(headers, "server")) {
    addFinding(findings, "info", "Server", "Server header is present.", get(headers, "server"));
  }
  if (get(headers, "x-powered-by")) {
    addFinding(findings, "info", "X-Powered-By", "X-Powered-By header is present.", get(headers, "x-powered-by"));
  }
}

export function analyzeCapture(capture) {
  if (!capture?.headers) {
    return {
      score: 0,
      grade: "No capture",
      findings: [],
      securityHeaders: []
    };
  }

  const findings = [];
  const headers = capture.headers;
  analyzeCsp(headers, findings);
  analyzeHsts(headers, capture, findings);
  analyzeFraming(headers, findings);
  analyzeReferrer(headers, findings);
  analyzePermissions(headers, findings);
  analyzeCors(headers, findings);
  analyzeSniffing(headers, findings);
  analyzeIsolation(headers, findings);
  analyzeDisclosure(headers, findings);

  const warnCount = findings.filter((finding) => finding.status === "warn").length;
  const goodCount = findings.filter((finding) => finding.status === "good").length;
  const score = Math.max(0, Math.min(100, 60 + goodCount * 7 - warnCount * 12));
  const grade = score >= 90 ? "Strong" : score >= 75 ? "Good" : score >= 55 ? "Review" : "Weak";
  const securityHeaders = SECURITY_HEADERS
    .filter((name) => headers[name])
    .map((name) => ({ name, value: headers[name] }));

  return { score, grade, findings, securityHeaders };
}
