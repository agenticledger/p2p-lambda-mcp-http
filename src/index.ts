#!/usr/bin/env node
/**
 * P2P Lambda MCP Server — Exposed via Streamable HTTP
 *
 * Auth model: Triple-mode — supports direct Bearer passthrough,
 * OAuth 2.0 Client Credentials grant, and OAuth 2.0 Authorization
 * Code flow with PKCE (for Claude.ai Cowork and agent platforms).
 * No permanent credentials are stored on the server.
 */

import { randomUUID, createHash } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { zodToJsonSchema as _zodToJsonSchema } from 'zod-to-json-schema';
import { P2PLambdaClient } from './api-client.js';
import { tools } from './tools.js';

function zodToJsonSchema(schema: any): any {
  return _zodToJsonSchema(schema);
}

const PORT = parseInt(process.env.PORT || '3100', 10);
const SERVER_BASE_URL = process.env.SERVER_BASE_URL || `http://localhost:${PORT}`;
const SLUG = 'p2p-lambda';

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// --- OAuth token store (in-memory, ephemeral) ---
const TOKEN_TTL_MS = 60 * 60 * 1000; // 1 hour

interface OAuthToken {
  apiKey: string;
  expiresAt: number;
}

const oauthTokens = new Map<string, OAuthToken>();

// Cleanup expired tokens every 10 minutes
setInterval(() => {
  const now = Date.now();
  for (const [token, data] of oauthTokens) {
    if (now > data.expiresAt) oauthTokens.delete(token);
  }
}, 10 * 60 * 1000);

// --- OAuth authorization code store (in-memory, ephemeral) ---
const AUTH_CODE_TTL_MS = 5 * 60 * 1000; // 5 minutes

interface AuthCode {
  apiKey: string;
  codeChallenge: string;
  codeChallengeMethod: string;
  redirectUri: string;
  expiresAt: number;
}

const authCodes = new Map<string, AuthCode>();

// Cleanup expired auth codes every 2 minutes
setInterval(() => {
  const now = Date.now();
  for (const [code, data] of authCodes) {
    if (now > data.expiresAt) authCodes.delete(code);
  }
}, 2 * 60 * 1000);

// PKCE S256 verifier
function verifyPKCE(codeVerifier: string, codeChallenge: string, method: string): boolean {
  if (method === 'S256') {
    const hash = createHash('sha256').update(codeVerifier).digest('base64url');
    return hash === codeChallenge;
  }
  if (method === 'plain') {
    return codeVerifier === codeChallenge;
  }
  return false;
}

// --- Static assets (logo) ---
const __dirname = path.dirname(fileURLToPath(import.meta.url));
app.use('/static', express.static(path.join(__dirname, 'public')));

// Health check (no auth required)
app.get('/health', (_req, res) => {
  res.json({
    status: 'ok',
    server: 'p2p-lambda-mcp-http',
    version: '1.0.0',
    tools: tools.length,
    transport: 'streamable-http',
    auth: 'dual-mode',
    auth_modes: ['bearer-passthrough', 'oauth-client-credentials'],
  });
});

// --- OAuth 2.0 Discovery ---
app.get('/.well-known/oauth-authorization-server', (_req, res) => {
  res.json({
    issuer: SERVER_BASE_URL,
    authorization_endpoint: `${SERVER_BASE_URL}/authorize`,
    token_endpoint: `${SERVER_BASE_URL}/oauth/token`,
    revocation_endpoint: `${SERVER_BASE_URL}/oauth/revoke`,
    registration_endpoint: `${SERVER_BASE_URL}/oauth/register`,
    grant_types_supported: ['authorization_code', 'client_credentials'],
    token_endpoint_auth_methods_supported: ['client_secret_post', 'none'],
    response_types_supported: ['code'],
    code_challenge_methods_supported: ['S256'],
    service_documentation: `https://financemcps.agenticledger.ai/${SLUG}/`,
  });
});

// --- OAuth 2.0 Dynamic Client Registration (RFC 7591) ---
// Claude.ai calls this to register itself as a client before starting the auth flow.
// We accept any registration and return the SLUG as client_id.
app.post('/oauth/register', (req, res) => {
  res.status(201).json({
    client_id: SLUG,
    client_name: req.body?.client_name || 'MCP Client',
    redirect_uris: req.body?.redirect_uris || [],
    grant_types: ['authorization_code'],
    response_types: ['code'],
    token_endpoint_auth_method: 'none',
  });
});

// --- OAuth 2.0 Authorization Endpoint ---
// GET: Show branded consent page where user enters their API key
// POST: Process the form, generate auth code, redirect back to client
app.get('/authorize', (req, res) => {
  const { response_type, client_id, redirect_uri, code_challenge, code_challenge_method, state, scope } = req.query;

  if (response_type !== 'code') {
    res.status(400).json({ error: 'unsupported_response_type', error_description: 'Only response_type=code is supported' });
    return;
  }

  // Render the branded consent page
  res.send(AUTHORIZE_HTML(
    client_id as string || '',
    redirect_uri as string || '',
    code_challenge as string || '',
    code_challenge_method as string || 'S256',
    state as string || '',
    scope as string || '',
  ));
});

app.post('/authorize', (req, res) => {
  const { api_key, client_id, redirect_uri, code_challenge, code_challenge_method, state, scope } = req.body;

  if (!api_key) {
    res.status(400).send('API key is required');
    return;
  }

  if (!redirect_uri) {
    res.status(400).json({ error: 'invalid_request', error_description: 'redirect_uri is required' });
    return;
  }

  // Generate authorization code
  const code = `authcode_${randomUUID().replace(/-/g, '')}`;

  authCodes.set(code, {
    apiKey: api_key,
    codeChallenge: code_challenge || '',
    codeChallengeMethod: code_challenge_method || 'S256',
    redirectUri: redirect_uri,
    expiresAt: Date.now() + AUTH_CODE_TTL_MS,
  });

  // Redirect back to the client with the code
  const url = new URL(redirect_uri);
  url.searchParams.set('code', code);
  if (state) url.searchParams.set('state', state);

  res.redirect(302, url.toString());
});

// --- OAuth 2.0 Token Exchange ---
app.post('/oauth/token', (req, res) => {
  const { grant_type } = req.body;

  // --- Authorization Code Grant (Claude.ai Cowork / PKCE flow) ---
  if (grant_type === 'authorization_code') {
    const { code, code_verifier, redirect_uri } = req.body;

    if (!code) {
      res.status(400).json({ error: 'invalid_request', error_description: 'code is required' });
      return;
    }

    const entry = authCodes.get(code);
    if (!entry) {
      res.status(400).json({ error: 'invalid_grant', error_description: 'Authorization code not found or expired' });
      return;
    }

    // Delete the code immediately (single use)
    authCodes.delete(code);

    // Check expiry
    if (Date.now() > entry.expiresAt) {
      res.status(400).json({ error: 'invalid_grant', error_description: 'Authorization code expired' });
      return;
    }

    // Verify redirect_uri matches
    if (redirect_uri && redirect_uri !== entry.redirectUri) {
      res.status(400).json({ error: 'invalid_grant', error_description: 'redirect_uri mismatch' });
      return;
    }

    // Verify PKCE
    if (entry.codeChallenge) {
      if (!code_verifier) {
        res.status(400).json({ error: 'invalid_request', error_description: 'code_verifier is required for PKCE' });
        return;
      }
      if (!verifyPKCE(code_verifier, entry.codeChallenge, entry.codeChallengeMethod)) {
        res.status(400).json({ error: 'invalid_grant', error_description: 'PKCE verification failed' });
        return;
      }
    }

    // Issue token
    const accessToken = `mcp_${randomUUID().replace(/-/g, '')}`;
    const expiresIn = TOKEN_TTL_MS / 1000;

    oauthTokens.set(accessToken, {
      apiKey: entry.apiKey,
      expiresAt: Date.now() + TOKEN_TTL_MS,
    });

    res.json({
      access_token: accessToken,
      token_type: 'bearer',
      expires_in: expiresIn,
    });
    return;
  }

  // --- Client Credentials Grant (programmatic / M2M) ---
  if (grant_type === 'client_credentials') {
    const { client_id, client_secret } = req.body;

    if (client_id !== SLUG) {
      res.status(400).json({ error: 'invalid_client', error_description: `client_id must be "${SLUG}"` });
      return;
    }

    if (!client_secret) {
      res.status(400).json({ error: 'invalid_request', error_description: 'client_secret is required (your API key)' });
      return;
    }

    const accessToken = `mcp_${randomUUID().replace(/-/g, '')}`;
    const expiresIn = TOKEN_TTL_MS / 1000;

    oauthTokens.set(accessToken, {
      apiKey: client_secret,
      expiresAt: Date.now() + TOKEN_TTL_MS,
    });

    res.json({
      access_token: accessToken,
      token_type: 'bearer',
      expires_in: expiresIn,
    });
    return;
  }

  res.status(400).json({ error: 'unsupported_grant_type', error_description: 'Supported: authorization_code, client_credentials' });
});

// --- OAuth 2.0 Token Revocation ---
app.post('/oauth/revoke', (req, res) => {
  const { token } = req.body;
  if (token) oauthTokens.delete(token);
  res.status(200).json({ status: 'revoked' });
});

// --- Smart root route: content negotiation ---
app.get('/', (req, res) => {
  const accept = req.headers.accept || '';
  if (accept.includes('text/html')) {
    res.send(BRANDED_LANDING_HTML);
    return;
  }
  res.json({
    name: 'P2P Lambda MCP Server',
    provider: 'AgenticLedger',
    version: '1.0.0',
    description: 'Wallet portfolio analytics, PnL tracking, token prices, NFTs, yield recommendations, and APR history across 20+ chains',
    mcpEndpoint: '/mcp',
    transport: 'streamable-http',
    tools: tools.length,
    auth: {
      type: 'dual-mode',
      description: 'Supports both direct Bearer token and OAuth 2.0 Client Credentials',
      modes: {
        bearer: {
          description: 'Pass your API key directly as the Bearer token',
          header: 'Authorization: Bearer <your-api-key>',
        },
        oauth: {
          description: 'Exchange credentials for a time-limited token',
          token_endpoint: `${SERVER_BASE_URL}/oauth/token`,
          client_id: SLUG,
          client_secret: '<your-api-key>',
          grant_type: 'client_credentials',
        },
      },
    },
    configTemplate: {
      mcpServers: {
        'p2p-lambda': {
          url: `${SERVER_BASE_URL}/mcp`,
          headers: { Authorization: 'Bearer <your-api-key>' }
        }
      }
    },
    links: {
      health: '/health',
      documentation: 'https://financemcps.agenticledger.ai/p2p-lambda/',
      oauth_discovery: '/.well-known/oauth-authorization-server',
    }
  });
});

// --- Dual-mode API key resolver ---
function resolveApiKey(req: express.Request): string | null {
  const auth = req.headers.authorization;
  if (!auth) return null;

  const token = auth.replace(/^Bearer\s+/i, '');
  if (!token) return null;

  // Mode 1: OAuth-issued token
  if (token.startsWith('mcp_')) {
    const entry = oauthTokens.get(token);
    if (!entry) return null;
    if (Date.now() > entry.expiresAt) {
      oauthTokens.delete(token);
      return null;
    }
    return entry.apiKey;
  }

  // Mode 2: Raw API key passthrough
  return token;
}

// --- Per-session state ---
interface SessionState {
  server: Server;
  transport: StreamableHTTPServerTransport;
  client: P2PLambdaClient;
}

const sessions = new Map<string, SessionState>();

function createMCPServer(client: P2PLambdaClient): Server {
  const server = new Server(
    { name: 'p2p-lambda-mcp-server', version: '1.0.0' },
    { capabilities: { tools: {} } }
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: tools.map((tool) => ({
      name: tool.name,
      description: tool.description,
      inputSchema: zodToJsonSchema(tool.inputSchema),
    })),
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    const tool = tools.find((t) => t.name === name);

    if (!tool) {
      throw new Error(`Unknown tool: ${name}`);
    }

    try {
      const result = await tool.handler(client, args as any);
      return {
        content: [{ type: 'text' as const, text: JSON.stringify(result, null, 2) }],
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return {
        content: [{ type: 'text' as const, text: `Error: ${message}` }],
        isError: true,
      };
    }
  });

  return server;
}

// --- Streamable HTTP endpoint ---
app.post('/mcp', async (req, res) => {
  const sessionId = req.headers['mcp-session-id'] as string | undefined;

  if (sessionId && sessions.has(sessionId)) {
    const { transport } = sessions.get(sessionId)!;
    await transport.handleRequest(req, res, req.body);
    return;
  }

  const apiKey = resolveApiKey(req);
  if (!apiKey) {
    res.status(401).json({
      error: 'Missing or invalid Authorization header.',
      modes: {
        bearer: 'Authorization: Bearer <your-api-key>',
        oauth: `POST ${SERVER_BASE_URL}/oauth/token with client_id=${SLUG}&client_secret=<your-api-key>&grant_type=client_credentials`,
      },
    });
    return;
  }

  // Create per-session API client with the user's credentials
  const client = new P2PLambdaClient(apiKey);

  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: () => randomUUID(),
  });

  const server = createMCPServer(client);

  transport.onclose = () => {
    const sid = transport.sessionId;
    if (sid) {
      sessions.delete(sid);
      console.log(`[mcp] Session closed: ${sid}`);
    }
  };

  await server.connect(transport);
  await transport.handleRequest(req, res, req.body);

  const newSessionId = transport.sessionId;
  if (newSessionId) {
    sessions.set(newSessionId, { server, transport, client });
    console.log(`[mcp] New session: ${newSessionId}`);
  }
});

// GET /mcp — SSE stream for server notifications
app.get('/mcp', async (req, res) => {
  const sessionId = req.headers['mcp-session-id'] as string | undefined;
  if (!sessionId || !sessions.has(sessionId)) {
    res.status(400).json({ error: 'Invalid or missing session. Send initialization POST first.' });
    return;
  }
  const { transport } = sessions.get(sessionId)!;
  await transport.handleRequest(req, res);
});

// DELETE /mcp — close session
app.delete('/mcp', async (req, res) => {
  const sessionId = req.headers['mcp-session-id'] as string | undefined;
  if (!sessionId || !sessions.has(sessionId)) {
    res.status(404).json({ error: 'Session not found' });
    return;
  }
  const { transport, server } = sessions.get(sessionId)!;
  await transport.close();
  await server.close();
  sessions.delete(sessionId);
  res.status(200).json({ status: 'session closed' });
});

// ==================== OAUTH AUTHORIZE CONSENT PAGE ====================
function AUTHORIZE_HTML(clientId: string, redirectUri: string, codeChallenge: string, codeChallengeMethod: string, state: string, scope: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Authorize — P2P Lambda MCP</title>
  <link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
  <style>
    :root{--primary:#2563EB;--primary-dark:#1D4ED8;--primary-light:#DBEAFE;--primary-50:#EFF6FF;--fg:#0F172A;--muted:#64748B;--surface:#F8FAFC;--border:#E2E8F0;--success:#10B981;--success-light:#D1FAE5;--warn:#F59E0B;--warn-light:#FEF3C7;}
    *{margin:0;padding:0;box-sizing:border-box;}
    body{font-family:'DM Sans',sans-serif;color:var(--fg);min-height:100vh;display:flex;align-items:center;justify-content:center;background:var(--surface);background-image:linear-gradient(135deg,var(--primary-50) 0%,var(--surface) 50%,#F0F9FF 100%);}
    .card{background:#fff;border:1px solid var(--border);border-radius:16px;padding:40px;max-width:480px;width:100%;margin:20px;box-shadow:0 1px 3px rgba(0,0,0,.04),0 8px 24px rgba(0,0,0,.06);}
    .header{display:flex;align-items:center;gap:14px;margin-bottom:24px;padding-bottom:20px;border-bottom:1px solid var(--border);}
    .header img{height:36px;}
    .header span{font-size:18px;font-weight:700;}
    .consent-msg{font-size:14px;color:var(--muted);margin-bottom:20px;line-height:1.6;}
    .consent-msg strong{color:var(--fg);}
    .scope-badge{display:inline-block;background:var(--primary-50);border:1px solid var(--primary-light);border-radius:8px;padding:4px 10px;font-size:12px;font-weight:600;color:var(--primary-dark);margin-bottom:20px;}
    .key-label{font-size:13px;font-weight:600;margin-bottom:8px;display:block;}
    .key-input{width:100%;padding:12px 16px;border:2px solid var(--border);border-radius:10px;font-family:'JetBrains Mono',monospace;font-size:13px;transition:border-color .2s;margin-bottom:6px;}
    .key-input:focus{outline:none;border-color:var(--primary);}
    .key-hint{font-size:11px;color:var(--muted);margin-bottom:24px;line-height:1.5;}
    .btn-authorize{width:100%;padding:14px;background:var(--primary);color:#fff;border:none;border-radius:10px;font-family:'DM Sans',sans-serif;font-size:15px;font-weight:600;cursor:pointer;transition:background .15s;}
    .btn-authorize:hover{background:var(--primary-dark);}
    .btn-authorize:disabled{background:var(--border);cursor:not-allowed;}
    .trust-row{display:flex;align-items:center;gap:6px;font-size:11px;color:var(--muted);margin-top:16px;}
    .trust-row svg{width:14px;height:14px;color:var(--success);flex-shrink:0;}
    .footer{margin-top:20px;padding-top:16px;border-top:1px solid var(--border);text-align:center;font-size:11px;color:var(--muted);}
  </style>
</head>
<body>
  <div class="card">
    <div class="header"><img src="/static/logo.png" alt="AgenticLedger"><span>P2P Lambda MCP</span></div>
    <div class="consent-msg">An application wants to connect to <strong>P2P Lambda MCP Server</strong> on your behalf. Enter your API key to authorize access.</div>
    ${scope ? `<div class="scope-badge">Scope: ${scope}</div>` : ''}
    <form method="POST" action="/authorize">
      <input type="hidden" name="client_id" value="${clientId}">
      <input type="hidden" name="redirect_uri" value="${redirectUri}">
      <input type="hidden" name="code_challenge" value="${codeChallenge}">
      <input type="hidden" name="code_challenge_method" value="${codeChallengeMethod}">
      <input type="hidden" name="state" value="${state}">
      <input type="hidden" name="scope" value="${scope}">
      <label class="key-label">Your P2P Lambda API Key</label>
      <input type="password" class="key-input" name="api_key" id="apiKey" placeholder="Enter your API key" required autofocus oninput="document.getElementById('authBtn').disabled=!this.value">
      <div class="key-hint">Your key is used to create a temporary access token. It is not stored permanently on this server.</div>
      <button type="submit" class="btn-authorize" id="authBtn" disabled>Authorize</button>
    </form>
    <div class="trust-row"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>No credentials stored permanently &mdash; tokens expire after 1 hour</div>
    <div class="footer">Powered by AgenticLedger</div>
  </div>
</body>
</html>`;
}

// ==================== BRANDED HTML HELPER PAGE ====================
const BRANDED_LANDING_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>P2P Lambda MCP Server — AgenticLedger</title>
  <link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
  <style>
    :root{--primary:#2563EB;--primary-dark:#1D4ED8;--primary-light:#DBEAFE;--primary-50:#EFF6FF;--fg:#0F172A;--muted:#64748B;--surface:#F8FAFC;--border:#E2E8F0;--success:#10B981;--success-light:#D1FAE5;}
    *{margin:0;padding:0;box-sizing:border-box;}
    body{font-family:'DM Sans',sans-serif;color:var(--fg);min-height:100vh;display:flex;align-items:center;justify-content:center;background:var(--surface);background-image:linear-gradient(135deg,var(--primary-50) 0%,var(--surface) 50%,#F0F9FF 100%);background-size:400% 400%;animation:gradientShift 15s ease infinite;}
    @keyframes gradientShift{0%{background-position:0% 50%}50%{background-position:100% 50%}100%{background-position:0% 50%}}
    .card{background:#fff;border:1px solid var(--border);border-radius:16px;padding:40px;max-width:560px;width:100%;margin:20px;box-shadow:0 1px 3px rgba(0,0,0,.04),0 8px 24px rgba(0,0,0,.06);animation:slideUp .5s ease-out;}
    @keyframes slideUp{from{opacity:0;transform:translateY(20px)}to{opacity:1;transform:translateY(0)}}
    .header{display:flex;align-items:center;gap:14px;margin-bottom:28px;padding-bottom:20px;border-bottom:1px solid var(--border);}
    .header img{height:36px;}
    .header span{font-size:18px;font-weight:700;color:var(--fg);}
    .status-badge{display:inline-flex;align-items:center;gap:6px;background:var(--success-light);border:1px solid #A7F3D0;border-radius:20px;padding:6px 14px;font-size:13px;font-weight:600;color:#065F46;margin-bottom:20px;}
    .status-badge::before{content:'';width:8px;height:8px;border-radius:50%;background:var(--success);animation:pulse 2s infinite;}
    @keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
    .info-grid{display:grid;gap:12px;margin-bottom:24px;}
    .info-row{display:flex;justify-content:space-between;align-items:center;padding:10px 14px;background:var(--primary-50);border-radius:10px;font-size:13px;}
    .info-row .label{color:var(--muted);font-weight:500;}
    .info-row .value{color:var(--fg);font-weight:600;font-family:'JetBrains Mono',monospace;font-size:12px;}
    .section-title{font-size:14px;font-weight:600;color:var(--fg);margin:24px 0 10px;display:flex;align-items:center;gap:8px;}
    .key-input{width:100%;padding:12px 16px;border:2px solid var(--border);border-radius:10px;font-family:'JetBrains Mono',monospace;font-size:13px;transition:border-color .2s;margin-bottom:8px;}
    .key-input:focus{outline:none;border-color:var(--primary);}
    .key-hint{font-size:12px;color:var(--muted);margin-bottom:20px;line-height:1.5;}
    .config-block{position:relative;}
    .config-pre{background:#1E293B;border-radius:12px;padding:20px;overflow-x:auto;font-family:'JetBrains Mono',monospace;font-size:12.5px;line-height:1.7;margin:0 0 24px;color:#E2E8F0;white-space:pre;}
    .config-copy{position:absolute;top:12px;right:12px;background:rgba(255,255,255,.1);color:#CBD5E1;border:1px solid rgba(255,255,255,.15);border-radius:8px;padding:6px 12px;font-family:'DM Sans',sans-serif;font-size:12px;cursor:pointer;transition:all .15s;}
    .config-copy:hover{background:rgba(255,255,255,.2);color:#fff;}
    .config-copy.copied{background:rgba(16,185,129,.3);color:#86EFAC;}
    .trust{display:flex;gap:16px;flex-wrap:wrap;padding-top:20px;border-top:1px solid var(--border);}
    .trust-item{display:flex;align-items:center;gap:6px;font-size:12px;color:var(--muted);}
    .trust-item svg{width:14px;height:14px;color:var(--success);}
    .footer{padding-top:16px;border-top:1px solid var(--border);text-align:center;font-size:12px;color:var(--muted);margin-top:20px;}
  </style>
</head>
<body>
  <div class="card">
    <div class="header"><img src="/static/logo.png" alt="AgenticLedger"><span>P2P Lambda MCP</span></div>
    <div class="status-badge">Server Online</div>
    <div class="info-grid">
      <div class="info-row"><span class="label">Tools</span><span class="value">${tools.length}</span></div>
      <div class="info-row"><span class="label">Transport</span><span class="value">Streamable HTTP</span></div>
      <div class="info-row"><span class="label">Auth</span><span class="value">Dual-Mode (Bearer + OAuth)</span></div>
    </div>

    <div class="section-title">Enter your P2P Lambda API key</div>
    <input type="text" class="key-input" id="apiKeyInput" placeholder="your-p2p-lambda-api-key" oninput="updateConfig()">
    <div class="key-hint">Your key stays in your browser — it is never sent to this server. Get a key at <a href="https://p2p-lambda.readme.io" target="_blank" style="color:var(--primary)">p2p-lambda.readme.io</a></div>

    <div class="section-title">MCP Configuration (Bearer)</div>
    <p style="font-size:13px;color:var(--muted);margin-bottom:12px;">Add to your <strong style="color:var(--fg)">claude_desktop_config.json</strong> or <strong style="color:var(--fg)">.mcp.json</strong>:</p>
    <div class="config-block">
      <button class="config-copy" onclick="copyConfig()">Copy</button>
      <pre class="config-pre" id="configBlock"></pre>
    </div>

    <div class="section-title">OAuth Configuration (Claude.ai / Agent Platforms)</div>
    <p style="font-size:13px;color:var(--muted);margin-bottom:12px;">For platforms that require OAuth Client Credentials:</p>
    <div class="config-block">
      <button class="config-copy" onclick="copyOAuth()">Copy</button>
      <pre class="config-pre" id="oauthBlock"></pre>
    </div>

    <div class="trust">
      <div class="trust-item"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>No credentials stored</div>
      <div class="trust-item"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>Stateless</div>
      <div class="trust-item"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>Per-session auth</div>
    </div>
    <div class="footer">Powered by AgenticLedger &middot; <a href="https://financemcps.agenticledger.ai/" target="_blank" style="color:var(--primary);text-decoration:none">Explore Other MCPs</a></div>
  </div>
  <script>
    function updateConfig(){
      var key=document.getElementById('apiKeyInput').value||'<your-api-key>';
      var config=JSON.stringify({mcpServers:{"p2p-lambda":{url:"${SERVER_BASE_URL}/mcp",headers:{Authorization:"Bearer "+key}}}},null,2);
      document.getElementById('configBlock').textContent=config;
      var oauth="Token URL:      ${SERVER_BASE_URL}/oauth/token\\nClient ID:      ${SLUG}\\nClient Secret:  "+key+"\\nGrant Type:     client_credentials";
      document.getElementById('oauthBlock').textContent=oauth;
    }
    function copyConfig(){
      var text=document.getElementById('configBlock').textContent;
      navigator.clipboard.writeText(text).then(function(){
        var btn=document.querySelectorAll('.config-copy')[0];
        btn.textContent='Copied!';btn.classList.add('copied');
        setTimeout(function(){btn.textContent='Copy';btn.classList.remove('copied');},2000);
      });
    }
    function copyOAuth(){
      var text=document.getElementById('oauthBlock').textContent;
      navigator.clipboard.writeText(text).then(function(){
        var btn=document.querySelectorAll('.config-copy')[1];
        btn.textContent='Copied!';btn.classList.add('copied');
        setTimeout(function(){btn.textContent='Copy';btn.classList.remove('copied');},2000);
      });
    }
    updateConfig();
  </script>
</body>
</html>`;

app.listen(PORT, () => {
  console.log(`P2P Lambda MCP HTTP Server running on port ${PORT}`);
  console.log(`  MCP endpoint:   ${SERVER_BASE_URL}/mcp`);
  console.log(`  OAuth token:    ${SERVER_BASE_URL}/oauth/token`);
  console.log(`  OAuth discovery: ${SERVER_BASE_URL}/.well-known/oauth-authorization-server`);
  console.log(`  Health check:   ${SERVER_BASE_URL}/health`);
  console.log(`  Landing page:   ${SERVER_BASE_URL}/`);
  console.log(`  Tools:          ${tools.length}`);
  console.log(`  Transport:      Streamable HTTP`);
  console.log(`  Auth:           Dual-mode (Bearer passthrough + OAuth Client Credentials)`);
});
