#!/usr/bin/env node
/**
 * P2P Lambda MCP Server — Exposed via Streamable HTTP
 *
 * Auth model: Dual-mode — supports both direct Bearer passthrough
 * and OAuth 2.0 Client Credentials grant.
 * No permanent credentials are stored on the server.
 */

import { randomUUID } from 'node:crypto';
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
    token_endpoint: `${SERVER_BASE_URL}/oauth/token`,
    revocation_endpoint: `${SERVER_BASE_URL}/oauth/revoke`,
    grant_types_supported: ['client_credentials'],
    token_endpoint_auth_methods_supported: ['client_secret_post'],
    response_types_supported: ['token'],
    service_documentation: `https://financemcps.agenticledger.ai/${SLUG}/`,
  });
});

// --- OAuth 2.0 Token Exchange ---
app.post('/oauth/token', (req, res) => {
  const { grant_type, client_id, client_secret } = req.body;

  if (grant_type !== 'client_credentials') {
    res.status(400).json({ error: 'unsupported_grant_type', error_description: 'Only client_credentials is supported' });
    return;
  }

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
