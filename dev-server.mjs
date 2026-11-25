import { createServer } from "node:http";
import { createHash, createHmac, randomBytes } from "node:crypto";
import { execSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { extname, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = resolve(fileURLToPath(new URL(".", import.meta.url)));
const DIST_DIR = resolve(__dirname, "dist");
const PORT = Number(process.env.PORT || 3000);
const HOST = "0.0.0.0";

if (!existsSync(join(DIST_DIR, "index.js"))) {
  execSync("npm run build", { cwd: __dirname, stdio: "inherit" });
}

const MIME_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".map": "application/json; charset=utf-8",
  ".d.ts": "text/plain; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".svg": "image/svg+xml",
};

// Track revoked mock tokens in memory so the interactive playground demonstrates live two-way sync
const revokedTokens = new Set();

function readJsonBody(req) {
  return new Promise((resolveBody) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => {
      try {
        resolveBody(JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}"));
      } catch {
        resolveBody({});
      }
    });
  });
}

function sendJson(res, statusCode, payload) {
  res.writeHead(statusCode, { "content-type": "application/json; charset=utf-8" });
  res.end(JSON.stringify(payload));
}

const HTML_PAGE = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>@xelorra/identity SDK Playground & Reference</title>
    <meta
      name="description"
      content="Interactive local playground for @xelorra/identity OAuth 2.0 + OIDC + PKCE S256 SDK, token introspection, and HMAC webhook verification."
    />
    <link rel="preconnect" href="https://fonts.googleapis.com" />
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
    <link
      href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600&family=IBM+Plex+Mono:wght@400;500&family=Plus+Jakarta+Sans:wght@600;700&display=swap"
      rel="stylesheet"
    />
    <style>
      :root {
        --canvas: #030811;
        --surface: #071426;
        --surface-hover: #0b1d36;
        --border: rgba(199, 203, 209, 0.14);
        --border-strong: rgba(199, 203, 209, 0.24);
        --text: #f8fafc;
        --text-secondary: #c7cbd1;
        --text-muted: #8b95a5;
        --accent: #2563eb;
        --accent-hover: #1d4ed8;
        --success: #22c55e;
        --error: #ef4444;
        --font-display: "Plus Jakarta Sans", system-ui, -apple-system, sans-serif;
        --font-sans: "DM Sans", system-ui, -apple-system, sans-serif;
        --font-mono: "IBM Plex Mono", ui-monospace, SFMono-Regular, monospace;
      }

      * {
        box-sizing: border-box;
      }

      html,
      body {
        margin: 0;
        min-height: 100%;
        background: var(--canvas);
        color: var(--text);
        font-family: var(--font-sans);
        -webkit-font-smoothing: antialiased;
      }

      h1,
      h2,
      h3 {
        font-family: var(--font-display);
        margin: 0;
        letter-spacing: -0.02em;
      }

      h2 {
        letter-spacing: -0.01em;
      }

      .app {
        display: grid;
        grid-template-columns: 260px 1fr;
        min-height: 100vh;
      }

      .sidebar {
        background: var(--surface);
        border-right: 1px solid var(--border);
        padding: 24px 16px;
        display: flex;
        flex-direction: column;
        gap: 28px;
      }

      .brand {
        display: flex;
        align-items: center;
        gap: 10px;
        padding: 0 8px;
      }

      .brand-mark {
        width: 28px;
        height: 28px;
        border-radius: 7px;
        background: var(--accent);
        display: grid;
        place-items: center;
        color: #ffffff;
        flex-shrink: 0;
      }

      .brand-title {
        font-family: var(--font-display);
        font-size: 15px;
        font-weight: 700;
        color: var(--text);
        white-space: nowrap;
      }

      .nav {
        display: flex;
        flex-direction: column;
        gap: 4px;
      }

      .nav-btn {
        display: flex;
        align-items: center;
        justify-content: space-between;
        width: 100%;
        padding: 10px 12px;
        border: 1px solid transparent;
        border-radius: 8px;
        background: transparent;
        color: var(--text-secondary);
        font-family: var(--font-sans);
        font-size: 14px;
        font-weight: 500;
        text-align: left;
        cursor: pointer;
        transition: background-color 140ms ease, color 140ms ease, border-color 140ms ease;
        white-space: nowrap;
      }

      .nav-btn:hover {
        background: var(--surface-hover);
        color: var(--text);
      }

      .nav-btn[aria-current="page"] {
        background: rgba(37, 99, 235, 0.14);
        border-color: rgba(37, 99, 235, 0.35);
        color: var(--text);
      }

      .sidebar-meta {
        margin-top: auto;
        padding: 16px 8px 0;
        border-top: 1px solid var(--border);
        font-size: 12px;
        color: var(--text-muted);
        line-height: 1.6;
      }

      .sidebar-meta code {
        font-family: var(--font-mono);
        color: var(--text-secondary);
      }

      .main-col {
        display: flex;
        flex-direction: column;
        min-width: 0;
      }

      .topbar {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 24px;
        padding: 16px 32px;
        border-bottom: 1px solid var(--border);
        background: var(--canvas);
      }

      .breadcrumbs {
        font-size: 13px;
        color: var(--text-muted);
        white-space: nowrap;
      }

      .breadcrumbs strong {
        color: var(--text);
        font-weight: 600;
      }

      .topbar-actions {
        display: flex;
        align-items: center;
        gap: 12px;
        flex-shrink: 0;
      }

      .btn {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        gap: 8px;
        min-height: 40px;
        padding: 8px 16px;
        border-radius: 8px;
        border: 1px solid var(--border-strong);
        background: var(--surface);
        color: var(--text);
        font-family: var(--font-sans);
        font-size: 13px;
        font-weight: 600;
        cursor: pointer;
        white-space: nowrap;
        flex-shrink: 0;
        transition: background-color 140ms ease, border-color 140ms ease, opacity 140ms ease;
      }

      .btn:hover:not(:disabled) {
        background: var(--surface-hover);
      }

      .btn:focus-visible,
      .nav-btn:focus-visible,
      input:focus-visible,
      textarea:focus-visible {
        outline: 2px solid var(--accent);
        outline-offset: 2px;
      }

      .btn-primary {
        background: var(--accent);
        border-color: var(--accent);
        color: #ffffff;
      }

      .btn-primary:hover:not(:disabled) {
        background: var(--accent-hover);
        border-color: var(--accent-hover);
      }

      .btn:disabled {
        opacity: 0.55;
        cursor: not-allowed;
      }

      .content {
        padding: 32px;
        max-width: 1120px;
        width: 100%;
      }

      .view {
        display: none;
      }

      .view.active {
        display: block;
      }

      .page-header {
        margin-bottom: 28px;
      }

      .page-header h1 {
        font-size: 28px;
        line-height: 1.2;
        text-wrap: balance;
      }

      .page-header p {
        margin: 8px 0 0;
        color: var(--text-secondary);
        font-size: 15px;
        line-height: 1.6;
        max-width: 68ch;
      }

      .meta-strip {
        display: flex;
        flex-wrap: wrap;
        gap: 8px;
        margin-top: 12px;
        font-size: 12px;
        color: var(--text-muted);
        font-family: var(--font-mono);
        font-variant-numeric: tabular-nums;
      }

      .grid-2 {
        display: grid;
        grid-template-columns: repeat(2, minmax(0, 1fr));
        gap: 24px;
        align-items: stretch;
      }

      .panel {
        background: var(--surface);
        border: 1px solid var(--border);
        border-radius: 12px;
        padding: 24px;
      }

      .panel h2 {
        font-size: 16px;
        margin-bottom: 16px;
      }

      .field {
        display: flex;
        flex-direction: column;
        gap: 6px;
        margin-bottom: 16px;
      }

      .field label {
        font-size: 13px;
        font-weight: 500;
        color: var(--text-secondary);
      }

      .field input,
      .field textarea {
        width: 100%;
        min-height: 40px;
        padding: 8px 12px;
        border-radius: 8px;
        border: 1px solid var(--border-strong);
        background: var(--canvas);
        color: var(--text);
        font-family: var(--font-mono);
        font-size: 12.5px;
      }

      .field textarea {
        min-height: 132px;
        resize: vertical;
        line-height: 1.5;
      }

      .scope-bar {
        display: flex;
        flex-wrap: wrap;
        gap: 8px;
        margin-top: 4px;
      }

      .scope-btn {
        min-height: 36px;
        padding: 6px 12px;
        border-radius: 6px;
        border: 1px solid var(--border-strong);
        background: var(--canvas);
        color: var(--text-secondary);
        font-family: var(--font-mono);
        font-size: 12px;
        cursor: pointer;
        transition: background-color 140ms ease, border-color 140ms ease, color 140ms ease;
      }

      .scope-btn[aria-pressed="true"] {
        background: rgba(37, 99, 235, 0.2);
        border-color: var(--accent);
        color: var(--text);
      }

      .actions-row {
        display: flex;
        flex-wrap: wrap;
        gap: 10px;
        margin-top: 20px;
      }

      .kv-list {
        display: flex;
        flex-direction: column;
        gap: 14px;
      }

      .kv-item {
        padding-bottom: 14px;
        border-bottom: 1px solid var(--border);
      }

      .kv-item:last-child {
        padding-bottom: 0;
        border-bottom: 0;
      }

      .kv-label {
        font-size: 12px;
        color: var(--text-muted);
        margin-bottom: 4px;
      }

      .kv-value {
        font-family: var(--font-mono);
        font-size: 12.5px;
        color: var(--text);
        word-break: break-all;
        line-height: 1.5;
        font-variant-numeric: tabular-nums;
      }

      .status-text {
        margin-top: 12px;
        font-size: 13px;
        color: var(--success);
        min-height: 20px;
      }

      .status-text.error {
        color: var(--error);
      }

      .metrics-row {
        display: grid;
        grid-template-columns: repeat(3, minmax(0, 1fr));
        gap: 16px;
        margin-bottom: 24px;
      }

      .metric {
        background: var(--surface);
        border: 1px solid var(--border);
        border-radius: 10px;
        padding: 16px 20px;
      }

      .metric-label {
        font-size: 12px;
        color: var(--text-muted);
        margin-bottom: 6px;
      }

      .metric-value {
        font-family: var(--font-mono);
        font-size: 20px;
        font-weight: 500;
        font-variant-numeric: tabular-nums;
        color: var(--text);
      }

      .data-table {
        width: 100%;
        border-collapse: collapse;
        font-size: 13.5px;
      }

      .data-table th {
        text-align: left;
        font-size: 12px;
        font-weight: 600;
        color: var(--text-muted);
        padding: 10px 12px;
        border-bottom: 1px solid var(--border-strong);
      }

      .data-table td {
        padding: 12px;
        border-bottom: 1px solid var(--border);
        color: var(--text-secondary);
        vertical-align: top;
      }

      .data-table td:first-child {
        font-family: var(--font-mono);
        color: var(--text);
        white-space: nowrap;
      }

      .code-block {
        margin: 0;
        padding: 16px;
        border-radius: 8px;
        background: var(--canvas);
        border: 1px solid var(--border);
        font-family: var(--font-mono);
        font-size: 12.5px;
        line-height: 1.6;
        color: var(--text-secondary);
        overflow-x: auto;
      }

      .preview-stage {
        margin-top: 16px;
        padding: 28px;
        border-radius: 10px;
        border: 1px solid var(--border);
        display: flex;
        align-items: center;
        justify-content: center;
        transition: background-color 140ms ease;
      }

      .segmented {
        display: inline-flex;
        gap: 4px;
        padding: 4px;
        border-radius: 8px;
        background: var(--canvas);
        border: 1px solid var(--border);
      }

      .segmented button {
        min-height: 32px;
        padding: 4px 12px;
        border: 0;
        border-radius: 6px;
        background: transparent;
        color: var(--text-secondary);
        font-family: var(--font-sans);
        font-size: 13px;
        font-weight: 500;
        cursor: pointer;
      }

      .segmented button[aria-pressed="true"] {
        background: var(--surface-hover);
        color: var(--text);
      }

      .control-row {
        display: flex;
        flex-wrap: wrap;
        gap: 16px;
        align-items: center;
      }

      @media (max-width: 960px) {
        .app {
          grid-template-columns: 1fr;
        }
        .sidebar {
          border-right: 0;
          border-bottom: 1px solid var(--border);
          padding: 16px;
          gap: 16px;
        }
        .nav {
          flex-direction: row;
          overflow-x: auto;
        }
        .sidebar-meta {
          display: none;
        }
        .topbar {
          padding: 14px 16px;
        }
        .content {
          padding: 20px 16px;
        }
        .grid-2,
        .metrics-row {
          grid-template-columns: 1fr;
        }
      }
    </style>
  </head>
  <body>
    <div class="app">
      <aside class="sidebar" aria-label="SDK Playground Navigation">
        <div class="brand">
          <div class="brand-mark" aria-hidden="true">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none">
              <path
                d="M4 4L10.5 12L4 20H7.8L12.4 14.1L17 20H20.8L14.3 12L20.8 4H17L12.4 9.9L7.8 4H4Z"
                fill="currentColor"
              />
            </svg>
          </div>
          <span class="brand-title">@xelorra/identity</span>
        </div>

        <nav class="nav">
          <button type="button" class="nav-btn" data-view="pkce" aria-current="page">
            PKCE &amp; Authorize Builder
          </button>
          <button type="button" class="nav-btn" data-view="flow">
            OAuth &amp; Disconnect Sync
          </button>
          <button type="button" class="nav-btn" data-view="webhooks">
            Webhook HMAC Verifier
          </button>
          <button type="button" class="nav-btn" data-view="exports">
            Exports &amp; Button Preview
          </button>
        </nav>

        <div class="sidebar-meta">
          <div>Package: <code>@xelorra/identity</code></div>
          <div>Default Issuer: <code>one.xelorra.app</code></div>
          <div>Protocol: <code>OAuth 2.0 + PKCE S256</code></div>
        </div>
      </aside>

      <div class="main-col">
        <header class="topbar">
          <div class="breadcrumbs">
            @xelorra/identity / <strong id="breadcrumb-label">PKCE &amp; Authorize Builder</strong>
          </div>
          <div class="topbar-actions">
            <button type="button" class="btn btn-primary" id="top-generate-btn">
              Generate PKCE Pair
            </button>
          </div>
        </header>

        <main class="content">
          <!-- View 1: PKCE & Authorize Builder -->
          <section class="view active" id="view-pkce" aria-labelledby="heading-pkce">
            <div class="page-header">
              <h1 id="heading-pkce">OAuth 2.0 + PKCE S256 Builder</h1>
              <p>
                Exercise the live compiled <code>XelorraClient</code> and <code>createPkcePair</code>
                modules directly from <code>dist/index.js</code>, including Sign Up
                (<code>prompt=create</code>) URL generation.
              </p>
              <div class="meta-strip">
                <span>Method: S256 (WebCrypto SHA-256)</span>
                <span aria-hidden="true">·</span>
                <span>Token Persistence: In-Memory Only</span>
                <span aria-hidden="true">·</span>
                <span>Sub-exports: core / react / express / next</span>
              </div>
            </div>

            <div class="grid-2">
              <div class="panel">
                <h2>Client Configuration</h2>
                <div class="field">
                  <label>Authorization Flow Mode</label>
                  <div class="segmented" role="group" aria-label="Authorization mode">
                    <button type="button" data-auth-mode="signin" aria-pressed="true">Sign In</button>
                    <button type="button" data-auth-mode="signup" aria-pressed="false">Sign Up (prompt=create)</button>
                  </div>
                </div>
                <div class="field">
                  <label for="input-client-id">Client ID</label>
                  <input id="input-client-id" type="text" value="acme-web-app" />
                </div>
                <div class="field">
                  <label for="input-redirect-uri">Redirect URI</label>
                  <input
                    id="input-redirect-uri"
                    type="url"
                    value="https://acme.example.com/auth/callback"
                  />
                </div>
                <div class="field">
                  <label for="input-issuer">Issuer (blank uses https://one.xelorra.app)</label>
                  <input id="input-issuer" type="url" placeholder="https://one.xelorra.app" value="" />
                </div>
                <div class="field">
                  <label>Requested Scopes</label>
                  <div class="scope-bar" id="scope-bar">
                    <button type="button" class="scope-btn" data-scope="profile.read" aria-pressed="true">
                      profile.read
                    </button>
                    <button type="button" class="scope-btn" data-scope="passport.read" aria-pressed="true">
                      passport.read
                    </button>
                    <button type="button" class="scope-btn" data-scope="email.read" aria-pressed="true">
                      email.read
                    </button>
                    <button type="button" class="scope-btn" data-scope="phone.read" aria-pressed="false">
                      phone.read
                    </button>
                    <button type="button" class="scope-btn" data-scope="kyc.assertion" aria-pressed="false">
                      kyc.assertion
                    </button>
                  </div>
                </div>
                <div class="actions-row">
                  <button type="button" class="btn btn-primary" id="btn-rebuild-pkce">
                    Generate New PKCE Pair
                  </button>
                  <button type="button" class="btn" id="btn-copy-url">Copy Authorize URL</button>
                </div>
                <div class="status-text" id="pkce-status" role="status" aria-live="polite"></div>
              </div>

              <div class="panel">
                <h2>Generated OAuth Output</h2>
                <div class="kv-list">
                  <div class="kv-item">
                    <div class="kv-label">Resolved Issuer</div>
                    <div class="kv-value" id="out-issuer">Pending</div>
                  </div>
                  <div class="kv-item">
                    <div class="kv-label">PKCE Code Challenge (S256)</div>
                    <div class="kv-value" id="out-challenge">Pending</div>
                  </div>
                  <div class="kv-item">
                    <div class="kv-label">PKCE Code Verifier (ephemeral)</div>
                    <div class="kv-value" id="out-verifier">Pending</div>
                  </div>
                  <div class="kv-item">
                    <div class="kv-label">OAuth State</div>
                    <div class="kv-value" id="out-state">Pending</div>
                  </div>
                  <div class="kv-item">
                    <div class="kv-label">Authorization URL</div>
                    <div class="kv-value" id="out-url">Pending</div>
                  </div>
                </div>
              </div>
            </div>
          </section>

          <!-- View 2: OAuth & Disconnect Sync -->
          <section class="view" id="view-flow" aria-labelledby="heading-flow">
            <div class="page-header">
              <h1 id="heading-flow">OAuth, Introspection &amp; Disconnect Sync</h1>
              <p>
                Run live <code>XelorraClient</code> code exchange, <code>introspectToken()</code>,
                <code>refreshTokens()</code>, <code>XelorraAccessRevokedError</code> detection, and
                <code>revokeToken()</code> against local sandbox endpoints.
              </p>
            </div>

            <div class="metrics-row">
              <div class="metric">
                <div class="metric-label">In-Memory Access Token</div>
                <div class="metric-value" id="metric-token-state">Signed out</div>
              </div>
              <div class="metric">
                <div class="metric-label">localStorage Token Keys</div>
                <div class="metric-value" id="metric-local-storage">0</div>
              </div>
              <div class="metric">
                <div class="metric-label">sessionStorage Token Keys</div>
                <div class="metric-value" id="metric-session-storage">0</div>
              </div>
            </div>

            <div class="grid-2">
              <div class="panel">
                <h2>Flow Controls</h2>
                <p style="margin: 0 0 16px; color: var(--text-secondary); font-size: 14px; line-height: 1.6;">
                  Exercises <code>exchangeCodeForTokens</code>, <code>getUserInfo</code>,
                  <code>introspectToken</code>, <code>createDisconnectGuard</code>, and
                  <code>revokeToken</code> directly in the browser.
                </p>
                <div class="actions-row" style="margin-top: 0;">
                  <button type="button" class="btn btn-primary" id="btn-run-flow">
                    Run Complete OAuth Flow
                  </button>
                  <button type="button" class="btn" id="btn-introspect-token" disabled>
                    Introspect Token
                  </button>
                  <button type="button" class="btn" id="btn-refresh-token" disabled>
                    Rotate Refresh Token
                  </button>
                  <button type="button" class="btn" id="btn-logout-flow" disabled>
                    Revoke &amp; Disconnect
                  </button>
                </div>
                <div class="status-text" id="flow-status" role="status" aria-live="polite"></div>
              </div>

              <div class="panel">
                <h2>Live Session State</h2>
                <div class="kv-list">
                  <div class="kv-item">
                    <div class="kv-label">Access Token (In-Memory Only)</div>
                    <div class="kv-value" id="flow-access-token">None</div>
                  </div>
                  <div class="kv-item">
                    <div class="kv-label">Pairwise User Claims</div>
                    <div class="kv-value" id="flow-user">Not authenticated</div>
                  </div>
                  <div class="kv-item">
                    <div class="kv-label">Introspection Status</div>
                    <div class="kv-value" id="flow-introspection">Not checked</div>
                  </div>
                  <div class="kv-item">
                    <div class="kv-label">Reusable KYC Assertion</div>
                    <div class="kv-value" id="flow-kyc">Not requested</div>
                  </div>
                </div>
              </div>
            </div>
          </section>

          <!-- View 3: Webhook HMAC Verifier -->
          <section class="view" id="view-webhooks" aria-labelledby="heading-webhooks">
            <div class="page-header">
              <h1 id="heading-webhooks">Webhook Signature Verification</h1>
              <p>
                Test timing-safe HMAC-SHA256 verification against <code>X-Xelorra-Signature</code>
                and typed <code>user.access_revoked</code> parsing using <code>parseWebhookEvent()</code>.
              </p>
            </div>

            <div class="grid-2">
              <div class="panel">
                <h2>Signed Event Input</h2>
                <div class="field">
                  <label for="wh-secret">Webhook Secret</label>
                  <input id="wh-secret" type="text" value="whsec_demo_xelorra_signing_key" />
                </div>
                <div class="field">
                  <label for="wh-signature">X-Xelorra-Signature Header</label>
                  <input id="wh-signature" type="text" value="" />
                </div>
                <div class="field">
                  <label for="wh-body">Raw JSON Body</label>
                  <textarea id="wh-body"></textarea>
                </div>
                <div class="actions-row">
                  <button type="button" class="btn btn-primary" id="btn-wh-sign">
                    Sign Payload
                  </button>
                  <button type="button" class="btn" id="btn-wh-verify">
                    Verify &amp; Parse
                  </button>
                  <button type="button" class="btn" id="btn-wh-tamper">
                    Tamper Body
                  </button>
                </div>
                <div class="status-text" id="wh-status" role="status" aria-live="polite"></div>
              </div>

              <div class="panel">
                <h2>Verification Result</h2>
                <div class="kv-list">
                  <div class="kv-item">
                    <div class="kv-label">Signature Check</div>
                    <div class="kv-value" id="wh-result-valid">Pending</div>
                  </div>
                  <div class="kv-item">
                    <div class="kv-label">Event Type</div>
                    <div class="kv-value" id="wh-result-type">None</div>
                  </div>
                  <div class="kv-item">
                    <div class="kv-label">Parsed Payload</div>
                    <div class="kv-value" id="wh-result-data">None</div>
                  </div>
                </div>
              </div>
            </div>
          </section>

          <!-- View 4: Exports & Button Preview -->
          <section class="view" id="view-exports" aria-labelledby="heading-exports">
            <div class="page-header">
              <h1 id="heading-exports">Package Exports &amp; Button Preview</h1>
              <p>
                Verify all modular entrypoints in <code>@xelorra/identity</code> and preview the
                built-in Sign In and Sign Up (<code>prompt=create</code>) button variants.
              </p>
            </div>

            <div class="grid-2">
              <div class="panel">
                <h2>Export Map</h2>
                <table class="data-table">
                  <thead>
                    <tr>
                      <th>Entrypoint</th>
                      <th>Runtime Exports</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr>
                      <td>@xelorra/identity</td>
                      <td>
                        <code>XelorraClient</code>, <code>XelorraAuth</code>,
                        <code>createPkcePair</code>, <code>buildAuthorizeUrl</code>,
                        <code>buildSignUpUrl</code>, <code>exchangeCodeForTokens</code>,
                        <code>refreshTokens</code>, <code>getUserInfo</code>,
                        <code>introspectToken</code>, <code>revokeToken</code>,
                        <code>verifyWebhookSignature</code>, <code>parseWebhookEvent</code>,
                        <code>createDisconnectGuard</code>
                      </td>
                    </tr>
                    <tr>
                      <td>@xelorra/identity/react</td>
                      <td>
                        <code>XelorraProvider</code>, <code>useXelorraAuth</code>,
                        <code>XelorraAuthButton</code>
                      </td>
                    </tr>
                    <tr>
                      <td>@xelorra/identity/express</td>
                      <td>
                        <code>createExpressCallbackHandler</code>,
                        <code>createExpressAuthMiddleware</code>,
                        <code>createExpressWebhookHandler</code>
                      </td>
                    </tr>
                    <tr>
                      <td>@xelorra/identity/next</td>
                      <td>
                        <code>createNextCallbackHandler</code>,
                        <code>createNextWebhookHandler</code>
                      </td>
                    </tr>
                  </tbody>
                </table>

                <h2 style="margin-top: 24px;">Quick Start</h2>
                <pre class="code-block">import { XelorraClient } from "@xelorra/identity";
import {
  XelorraProvider,
  XelorraAuthButton,
} from "@xelorra/identity/react";

const xelorra = new XelorraClient({
  clientId: "your-client-id",
  redirectUri: "https://your-app.com/auth/callback",
});</pre>
              </div>

              <div class="panel">
                <h2>XelorraAuthButton Appearance</h2>
                <div class="control-row">
                  <div>
                    <div class="kv-label">Mode</div>
                    <div class="segmented" role="group" aria-label="Button mode">
                      <button type="button" data-btn-mode="signin" aria-pressed="true">Sign In</button>
                      <button type="button" data-btn-mode="signup" aria-pressed="false">Sign Up</button>
                    </div>
                  </div>
                  <div>
                    <div class="kv-label">Theme</div>
                    <div class="segmented" role="group" aria-label="Button theme">
                      <button type="button" data-btn-theme="dark" aria-pressed="true">Dark</button>
                      <button type="button" data-btn-theme="light" aria-pressed="false">Light</button>
                    </div>
                  </div>
                  <div>
                    <div class="kv-label">Variant</div>
                    <div class="segmented" role="group" aria-label="Button variant">
                      <button type="button" data-btn-variant="solid" aria-pressed="true">Solid</button>
                      <button type="button" data-btn-variant="outline" aria-pressed="false">Outline</button>
                    </div>
                  </div>
                </div>

                <div class="preview-stage" id="button-preview-stage" style="background: #030811;">
                  <button type="button" id="preview-xelorra-btn">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                      <path
                        d="M4 4L10.5 12L4 20H7.8L12.4 14.1L17 20H20.8L14.3 12L20.8 4H17L12.4 9.9L7.8 4H4Z"
                        fill="currentColor"
                      />
                    </svg>
                    <span id="preview-xelorra-label">Continue with Xelorra</span>
                  </button>
                </div>
                <div class="status-text" id="preview-status" role="status" aria-live="polite"></div>
              </div>
            </div>
          </section>
        </main>
      </div>
    </div>

    <script type="module">
      import {
        XelorraClient,
        computeWebhookSignature,
        createDisconnectGuard,
        createPkcePair,
        parseWebhookEvent,
      } from "/dist/index.js";

      const navButtons = Array.from(document.querySelectorAll(".nav-btn"));
      const views = {
        pkce: document.getElementById("view-pkce"),
        flow: document.getElementById("view-flow"),
        webhooks: document.getElementById("view-webhooks"),
        exports: document.getElementById("view-exports"),
      };
      const breadcrumbLabel = document.getElementById("breadcrumb-label");
      const viewTitles = {
        pkce: "PKCE & Authorize Builder",
        flow: "OAuth & Disconnect Sync",
        webhooks: "Webhook HMAC Verifier",
        exports: "Exports & Button Preview",
      };

      function switchView(id) {
        for (const [key, section] of Object.entries(views)) {
          section.classList.toggle("active", key === id);
        }
        for (const btn of navButtons) {
          if (btn.dataset.view === id) {
            btn.setAttribute("aria-current", "page");
          } else {
            btn.removeAttribute("aria-current");
          }
        }
        breadcrumbLabel.textContent = viewTitles[id] || id;
      }

      for (const btn of navButtons) {
        btn.addEventListener("click", () => switchView(btn.dataset.view));
      }

      // View 1: PKCE & Authorize Builder
      let authMode = "signin";
      const inputClientId = document.getElementById("input-client-id");
      const inputRedirectUri = document.getElementById("input-redirect-uri");
      const inputIssuer = document.getElementById("input-issuer");
      const scopeButtons = Array.from(document.querySelectorAll(".scope-btn"));
      const outIssuer = document.getElementById("out-issuer");
      const outChallenge = document.getElementById("out-challenge");
      const outVerifier = document.getElementById("out-verifier");
      const outState = document.getElementById("out-state");
      const outUrl = document.getElementById("out-url");
      const pkceStatus = document.getElementById("pkce-status");

      let latestUrl = "";

      function getSelectedScopes() {
        return scopeButtons
          .filter((b) => b.getAttribute("aria-pressed") === "true")
          .map((b) => b.dataset.scope);
      }

      async function generatePkcePreview() {
        pkceStatus.classList.remove("error");
        try {
          const scopes = getSelectedScopes();
          const client = new XelorraClient({
            clientId: inputClientId.value.trim(),
            redirectUri: inputRedirectUri.value.trim(),
            issuer: inputIssuer.value.trim() || undefined,
            scopes: scopes.length ? scopes : undefined,
          });
          const { url, pkce } =
            authMode === "signup"
              ? await client.buildSignUpUrl()
              : await client.buildAuthorizeUrl();
          latestUrl = url;
          outIssuer.textContent = client.issuer;
          outChallenge.textContent = pkce.codeChallenge;
          outVerifier.textContent = pkce.codeVerifier;
          outState.textContent = pkce.state;
          outUrl.textContent = url;
          pkceStatus.textContent =
            authMode === "signup"
              ? "Sign-up URL (prompt=create) and PKCE S256 pair generated."
              : "Sign-in URL and PKCE S256 pair generated.";
        } catch (err) {
          pkceStatus.classList.add("error");
          pkceStatus.textContent = err instanceof Error ? err.message : "Failed to build URL.";
        }
      }

      for (const btn of document.querySelectorAll("[data-auth-mode]")) {
        btn.addEventListener("click", () => {
          authMode = btn.dataset.authMode;
          for (const el of document.querySelectorAll("[data-auth-mode]")) {
            el.setAttribute("aria-pressed", String(el === btn));
          }
          void generatePkcePreview();
        });
      }

      for (const btn of scopeButtons) {
        btn.addEventListener("click", () => {
          const next = btn.getAttribute("aria-pressed") !== "true";
          btn.setAttribute("aria-pressed", String(next));
          void generatePkcePreview();
        });
      }

      document.getElementById("btn-rebuild-pkce").addEventListener("click", () => {
        void generatePkcePreview();
      });

      document.getElementById("top-generate-btn").addEventListener("click", () => {
        switchView("pkce");
        void generatePkcePreview();
      });

      document.getElementById("btn-copy-url").addEventListener("click", async () => {
        if (!latestUrl) return;
        try {
          await navigator.clipboard.writeText(latestUrl);
          pkceStatus.classList.remove("error");
          pkceStatus.textContent = "Authorize URL copied to clipboard.";
        } catch {
          pkceStatus.textContent = "Authorize URL is ready to copy from the output panel.";
        }
      });

      for (const input of [inputClientId, inputRedirectUri, inputIssuer]) {
        input.addEventListener("change", () => void generatePkcePreview());
      }

      // View 2: OAuth, Introspection & Disconnect Sync
      const flowClient = new XelorraClient({
        clientId: "acme-web-app",
        redirectUri: window.location.origin + "/callback",
        issuer: window.location.origin + "/mock",
        scopes: ["profile.read", "passport.read", "kyc.assertion"],
      });

      const metricTokenState = document.getElementById("metric-token-state");
      const metricLocalStorage = document.getElementById("metric-local-storage");
      const metricSessionStorage = document.getElementById("metric-session-storage");
      const flowAccessToken = document.getElementById("flow-access-token");
      const flowUser = document.getElementById("flow-user");
      const flowIntrospection = document.getElementById("flow-introspection");
      const flowKyc = document.getElementById("flow-kyc");
      const flowStatus = document.getElementById("flow-status");
      const btnIntrospect = document.getElementById("btn-introspect-token");
      const btnRefresh = document.getElementById("btn-refresh-token");
      const btnLogout = document.getElementById("btn-logout-flow");

      const disconnectGuard = createDisconnectGuard({
        client: flowClient,
        getToken: () => flowClient.getAccessToken(),
        onRevoked: ({ reason }) => {
          metricTokenState.textContent = "Revoked";
          flowAccessToken.textContent = "None";
          flowUser.textContent = "Session cleared";
          flowIntrospection.textContent = "active=false, connected=false (" + reason + ")";
          btnIntrospect.disabled = true;
          btnRefresh.disabled = true;
          btnLogout.disabled = true;
        },
      });

      function updateStorageCounters() {
        let localTokens = 0;
        for (let i = 0; i < window.localStorage.length; i += 1) {
          const k = window.localStorage.key(i) || "";
          const v = window.localStorage.getItem(k) || "";
          if (/token|xelorra/i.test(k) || /xc_at_|xlr_rt_/i.test(v)) localTokens += 1;
        }
        let sessionTokens = 0;
        for (let i = 0; i < window.sessionStorage.length; i += 1) {
          const k = window.sessionStorage.key(i) || "";
          const v = window.sessionStorage.getItem(k) || "";
          if (/token/i.test(k) || /xc_at_|xlr_rt_/i.test(v)) sessionTokens += 1;
        }
        metricLocalStorage.textContent = String(localTokens);
        metricSessionStorage.textContent = String(sessionTokens);
      }

      document.getElementById("btn-run-flow").addEventListener("click", async () => {
        flowStatus.classList.remove("error");
        flowStatus.textContent = "Running PKCE S256 token exchange...";
        try {
          const pkce = await createPkcePair();
          const { tokens, user } = await flowClient.handleCallback({
            url: window.location.origin + "/callback?code=xc_demo_code&state=" + encodeURIComponent(pkce.state),
            codeVerifier: pkce.codeVerifier,
          });
          const check = await disconnectGuard.check();
          const assertion = await flowClient.getVerificationAssertion();
          metricTokenState.textContent = "Active (memory)";
          flowAccessToken.textContent = tokens.access_token;
          flowUser.textContent = user.name + " (" + user.sub + ")";
          flowIntrospection.textContent =
            "active=" + check.introspection.active + ", connected=" + check.introspection.connected;
          flowKyc.textContent =
            assertion.verification_status +
            " · " +
            assertion.verification_level +
            " · " +
            assertion.verification_reference;
          btnIntrospect.disabled = false;
          btnRefresh.disabled = false;
          btnLogout.disabled = false;
          updateStorageCounters();
          flowStatus.textContent = "Authenticated in memory with zero browser token storage.";
        } catch (err) {
          flowStatus.classList.add("error");
          flowStatus.textContent = err instanceof Error ? err.message : "OAuth flow failed.";
        }
      });

      btnIntrospect.addEventListener("click", async () => {
        flowStatus.classList.remove("error");
        try {
          const check = await disconnectGuard.check();
          if (check.active && check.introspection) {
            flowIntrospection.textContent =
              "active=true, connected=true, xid=" + check.introspection.xid;
            flowStatus.textContent = "Token is active and connected on Xelorra One.";
          }
        } catch (err) {
          flowStatus.classList.add("error");
          flowStatus.textContent = err instanceof Error ? err.message : "Introspection failed.";
        }
      });

      btnRefresh.addEventListener("click", async () => {
        flowStatus.classList.remove("error");
        try {
          const rotated = await flowClient.refreshTokens();
          flowAccessToken.textContent = rotated.access_token;
          updateStorageCounters();
          flowStatus.textContent = "Rotated access and refresh tokens in memory.";
        } catch (err) {
          flowStatus.classList.add("error");
          flowStatus.textContent = err instanceof Error ? err.message : "Refresh failed.";
        }
      });

      btnLogout.addEventListener("click", async () => {
        flowStatus.classList.remove("error");
        await flowClient.logout();
        metricTokenState.textContent = "Signed out";
        flowAccessToken.textContent = "None";
        flowUser.textContent = "Not authenticated";
        flowIntrospection.textContent = "Disconnected via POST /oauth/revoke";
        flowKyc.textContent = "Not requested";
        btnIntrospect.disabled = true;
        btnRefresh.disabled = true;
        btnLogout.disabled = true;
        updateStorageCounters();
        flowStatus.textContent = "Token revoked on Xelorra One and in-memory session cleared.";
      });

      // View 3: Webhook HMAC Verifier
      const whSecret = document.getElementById("wh-secret");
      const whSignature = document.getElementById("wh-signature");
      const whBody = document.getElementById("wh-body");
      const whStatus = document.getElementById("wh-status");
      const whResultValid = document.getElementById("wh-result-valid");
      const whResultType = document.getElementById("wh-result-type");
      const whResultData = document.getElementById("wh-result-data");

      const sampleWebhookPayload = JSON.stringify(
        {
          id: "evt_01JXYZ849201",
          type: "user.access_revoked",
          created_at: new Date().toISOString(),
          data: {
            sub: "xlr_app_7c91e4f02b8a",
            xid: "XLR-9284-1039",
            client_id: "acme-web-app",
            revoked_at: new Date().toISOString(),
            reason: "user_disconnected",
          },
        },
        null,
        2,
      );
      whBody.value = sampleWebhookPayload;

      async function verifyCurrentWebhook() {
        whStatus.classList.remove("error");
        try {
          const event = await parseWebhookEvent(
            whBody.value,
            whSignature.value,
            whSecret.value,
          );
          whResultValid.textContent = "Valid HMAC-SHA256 signature";
          whResultType.textContent = event.type;
          whResultData.textContent = JSON.stringify(event.data);
          whStatus.textContent = "Webhook verified and parsed cleanly.";
        } catch (err) {
          whResultValid.textContent = "Rejected (" + (err.code || "error") + ")";
          whResultType.textContent = "None";
          whResultData.textContent = "None";
          whStatus.classList.add("error");
          whStatus.textContent = err instanceof Error ? err.message : "Verification failed.";
        }
      }

      async function signCurrentWebhook() {
        const sig = await computeWebhookSignature(whBody.value, whSecret.value);
        whSignature.value = "sha256=" + sig;
        await verifyCurrentWebhook();
      }

      document.getElementById("btn-wh-sign").addEventListener("click", () => {
        void signCurrentWebhook();
      });

      document.getElementById("btn-wh-verify").addEventListener("click", () => {
        void verifyCurrentWebhook();
      });

      document.getElementById("btn-wh-tamper").addEventListener("click", () => {
        whBody.value = whBody.value.replace("acme-web-app", "tampered-app");
        void verifyCurrentWebhook();
      });

      // View 4: Button Preview
      let btnMode = "signin";
      let btnTheme = "dark";
      let btnVariant = "solid";
      const previewStage = document.getElementById("button-preview-stage");
      const previewBtn = document.getElementById("preview-xelorra-btn");
      const previewLabel = document.getElementById("preview-xelorra-label");
      const previewStatus = document.getElementById("preview-status");

      function renderPreviewButton() {
        const isDark = btnTheme === "dark";
        const isSolid = btnVariant === "solid";
        previewLabel.textContent =
          btnMode === "signup" ? "Sign up with Xelorra" : "Continue with Xelorra";
        previewStage.style.background = isDark ? "#030811" : "#f8fafc";
        Object.assign(previewBtn.style, {
          display: "inline-flex",
          alignItems: "center",
          justifyContent: "center",
          gap: "10px",
          minHeight: "44px",
          padding: "0 18px",
          borderRadius: "10px",
          fontSize: "14px",
          fontWeight: "600",
          fontFamily: "var(--font-sans)",
          cursor: "pointer",
          transition: "opacity 140ms ease, background-color 140ms ease",
          backgroundColor: isSolid ? (isDark ? "#2563EB" : "#0F172A") : "transparent",
          color: isSolid ? "#FFFFFF" : isDark ? "#F8FAFC" : "#0F172A",
          border: isSolid
            ? "1px solid transparent"
            : isDark
              ? "1px solid rgba(148, 163, 184, 0.35)"
              : "1px solid rgba(15, 23, 42, 0.22)",
        });
      }

      for (const btn of document.querySelectorAll("[data-btn-mode]")) {
        btn.addEventListener("click", () => {
          btnMode = btn.dataset.btnMode;
          for (const el of document.querySelectorAll("[data-btn-mode]")) {
            el.setAttribute("aria-pressed", String(el === btn));
          }
          renderPreviewButton();
        });
      }

      for (const btn of document.querySelectorAll("[data-btn-theme]")) {
        btn.addEventListener("click", () => {
          btnTheme = btn.dataset.btnTheme;
          for (const el of document.querySelectorAll("[data-btn-theme]")) {
            el.setAttribute("aria-pressed", String(el === btn));
          }
          renderPreviewButton();
        });
      }

      for (const btn of document.querySelectorAll("[data-btn-variant]")) {
        btn.addEventListener("click", () => {
          btnVariant = btn.dataset.btnVariant;
          for (const el of document.querySelectorAll("[data-btn-variant]")) {
            el.setAttribute("aria-pressed", String(el === btn));
          }
          renderPreviewButton();
        });
      }

      previewBtn.addEventListener("click", () => {
        previewStatus.textContent =
          btnMode === "signup"
            ? "Calls client.signUp() with prompt=create and PKCE S256."
            : "Calls client.loginWithRedirect() with PKCE S256.";
      });

      renderPreviewButton();
      updateStorageCounters();
      void generatePkcePreview();
      void signCurrentWebhook();
    </script>
  </body>
</html>`;

const server = createServer(async (req, res) => {
  const url = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);
  const pathname = url.pathname;

  if (pathname === "/" || pathname === "/index.html") {
    res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    res.end(HTML_PAGE);
    return;
  }

  if (pathname.startsWith("/dist/")) {
    const safeRelative = pathname.replace(/^\/+/, "");
    const targetPath = resolve(__dirname, safeRelative);
    if (!targetPath.startsWith(DIST_DIR + sep) || !existsSync(targetPath)) {
      res.writeHead(404);
      res.end("Not found");
      return;
    }
    const ext = extname(targetPath);
    res.writeHead(200, {
      "content-type": MIME_TYPES[ext] || "application/octet-stream",
      "cache-control": "no-store",
    });
    res.end(readFileSync(targetPath));
    return;
  }

  // Local OAuth 2.0 + OIDC + PKCE sandbox endpoints matching https://one.xelorra.app
  if (pathname === "/mock/oauth/token" && req.method === "POST") {
    const body = await readJsonBody(req);
    if (body.grant_type === "authorization_code") {
      if (!body.code || !body.code_verifier) {
        sendJson(res, 400, {
          error: "invalid_request",
          error_description: "code and code_verifier are required.",
        });
        return;
      }
      const suffix = createHash("sha256")
        .update(String(body.code_verifier))
        .digest("hex")
        .slice(0, 12);
      sendJson(res, 200, {
        access_token: `xc_at_${suffix}_${randomBytes(4).toString("hex")}`,
        refresh_token: `xlr_rt_${randomBytes(8).toString("hex")}`,
        token_type: "Bearer",
        expires_in: 3600,
        scope: "profile.read passport.read kyc.assertion",
        xid: "XLR-9284-1039",
      });
      return;
    }

    if (body.grant_type === "refresh_token" && body.refresh_token) {
      if (revokedTokens.has(String(body.refresh_token))) {
        sendJson(res, 401, {
          error: "access_revoked",
          error_description: "Refresh token was revoked.",
          reason: "user_disconnected",
        });
        return;
      }
      sendJson(res, 200, {
        access_token: `xc_at_rot_${randomBytes(6).toString("hex")}`,
        refresh_token: `xlr_rt_rot_${randomBytes(8).toString("hex")}`,
        token_type: "Bearer",
        expires_in: 3600,
        scope: "profile.read passport.read kyc.assertion",
        xid: "XLR-9284-1039",
      });
      return;
    }

    sendJson(res, 400, { error: "unsupported_grant_type" });
    return;
  }

  if (pathname === "/mock/oauth/userinfo" && req.method === "GET") {
    const authHeader = req.headers.authorization || "";
    const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7).trim() : "";
    if (!token.startsWith("xc_at_")) {
      sendJson(res, 401, { error: "invalid_token" });
      return;
    }
    if (revokedTokens.has(token)) {
      sendJson(res, 401, {
        error: "access_revoked",
        error_description: "Access was revoked on Xelorra One.",
        reason: "user_disconnected",
      });
      return;
    }
    sendJson(res, 200, {
      sub: "xlr_app_7c91e4f02b8a",
      xid: "XLR-9284-1039",
      name: "Adaeze Okafor",
      email: "adaeze@example.com",
      email_verified: true,
      verification_level: "government_verified",
    });
    return;
  }

  if (pathname === "/mock/oauth/introspect" && req.method === "POST") {
    const body = await readJsonBody(req);
    const token = typeof body.token === "string" ? body.token : "";
    if (!token.startsWith("xc_at_") || revokedTokens.has(token)) {
      sendJson(res, 200, {
        active: false,
        connected: false,
        client_id: body.client_id || "acme-web-app",
        sub: null,
        xid: null,
        scope: null,
        exp: null,
        reason: revokedTokens.has(token) ? "user_disconnected" : "inactive",
      });
      return;
    }
    sendJson(res, 200, {
      active: true,
      connected: true,
      client_id: body.client_id || "acme-web-app",
      sub: "xlr_app_7c91e4f02b8a",
      xid: "XLR-9284-1039",
      scope: "profile.read passport.read kyc.assertion",
      exp: Math.floor(Date.now() / 1000) + 3600,
      reason: null,
    });
    return;
  }

  if (pathname === "/mock/api/v1/verify/assertion" && req.method === "GET") {
    const authHeader = req.headers.authorization || "";
    const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7).trim() : "";
    if (!token.startsWith("xc_at_")) {
      sendJson(res, 401, { error: "invalid_token" });
      return;
    }
    if (revokedTokens.has(token)) {
      sendJson(res, 401, { error: "access_revoked", reason: "user_disconnected" });
      return;
    }
    sendJson(res, 200, {
      assertion: {
        verification_status: "verified",
        verification_level: "government_verified",
        verification_reference: "xvr_8492019482",
        verified_at: new Date().toISOString(),
        country: "Nigeria",
      },
    });
    return;
  }

  if (pathname === "/mock/oauth/revoke" && req.method === "POST") {
    const body = await readJsonBody(req);
    if (typeof body.token === "string" && body.token) {
      revokedTokens.add(body.token);
    }
    res.writeHead(200);
    res.end();
    return;
  }

  if (pathname === "/mock/webhooks/sign" && req.method === "POST") {
    const body = await readJsonBody(req);
    const sig = createHmac("sha256", String(body.secret || ""))
      .update(String(body.payload || ""))
      .digest("hex");
    sendJson(res, 200, { signature: `sha256=${sig}` });
    return;
  }

  res.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
  res.end("Not found");
});

server.listen(PORT, HOST, () => {
  console.log(`@xelorra/identity dev server listening at http://localhost:${PORT}`);
});
