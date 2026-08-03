/**
 * WebSSH 集成路由（来自 CF-Workers-WebSSH 的会话协议层）
 *
 * 挂载于 /api/admin/ssh，全部接口都受 /api/admin/* 管理员 JWT 会话中间件保护：
 * - POST /session     创建一次性会话票据（需 CSRF token，由前端自动携带）
 * - GET  /connect     升级为 SSH 终端 WebSocket（票据 + 会话 ID）
 * - GET  /sftp        升级为 SFTP 文件管理 WebSocket（附加令牌）
 * - GET  /processes   升级为实时进程监控 WebSocket（附加令牌）
 */
import { Hono } from 'hono';
import { SSHSessionDO } from '../webssh/backend/durable-object';

export { SSHSessionDO };

type SshBindings = {
  SSH_SESSIONS: DurableObjectNamespace;
  CONNECT_TIMEOUT_MS?: string;
};

function clientAddress(request: Request): string {
  const value = request.headers.get('CF-Connecting-IP') ?? 'local';
  return /^[0-9A-Fa-f:.]{2,64}$/.test(value) ? value.toLowerCase() : 'unknown';
}

function hasValidWebSocketOrigin(request: Request): boolean {
  const origin = request.headers.get('Origin');
  return origin === null || origin === new URL(request.url).origin;
}

function jsonError(message: string, status: number): Response {
  return Response.json({ error: message }, { status });
}

const app = new Hono<{ Bindings: SshBindings }>();

// POST /api/admin/ssh/session —— 创建一次性会话票据
app.post('/session', async (c) => {
  if (!c.req.header('Content-Type')?.toLowerCase().startsWith('application/json')) {
    return jsonError('Expected application/json', 415);
  }
  const contentLength = Number(c.req.header('Content-Length') ?? 0);
  if (!Number.isFinite(contentLength) || contentLength < 0 || contentLength > 8192) {
    return jsonError('Request body is too large', 413);
  }
  let body: unknown;
  try {
    const text = await c.req.text();
    if (new TextEncoder().encode(text).length > 8192) return jsonError('Request body is too large', 413);
    body = JSON.parse(text);
  } catch {
    return jsonError('Invalid JSON body', 400);
  }
  if (!body || typeof body !== 'object' || Array.isArray(body)) return jsonError('Invalid JSON body', 400);
  const fields = Object.keys(body as Record<string, unknown>);
  if (fields.length > 0) return jsonError('Unsupported request field', 400);

  const id = c.env.SSH_SESSIONS.newUniqueId();
  const stub = c.env.SSH_SESSIONS.get(id);
  const response = await stub.fetch(new Request('https://session.internal/ticket', {
    method: 'POST',
    headers: { 'x-client-ip': clientAddress(c.req.raw) },
  }));
  if (!response.ok) return jsonError('Unable to create a session ticket', 503);
  const ticket = await response.json<{ ticket: string; expiresAt: number }>();
  return c.json({ ...ticket, sessionId: id.toString() }, 200, {
    'Cache-Control': 'no-store',
  });
});

// GET /api/admin/ssh/connect —— SSH 终端 WebSocket 升级
app.get('/connect', async (c) => {
  const request = c.req.raw;
  if (request.headers.get('Upgrade')?.toLowerCase() !== 'websocket') {
    return jsonError('WebSocket upgrade required', 426);
  }
  if (!hasValidWebSocketOrigin(request)) return jsonError('WebSocket origin is not allowed', 403);
  const url = new URL(request.url);
  const ticket = url.searchParams.get('ticket');
  const sessionId = url.searchParams.get('session');
  if (!ticket || !sessionId) return jsonError('Missing session ticket', 401);
  let id: DurableObjectId;
  try {
    id = c.env.SSH_SESSIONS.idFromString(sessionId);
  } catch {
    return jsonError('Invalid session identifier', 401);
  }

  const headers = new Headers(request.headers);
  headers.delete('Cookie');
  headers.delete('Authorization');
  const sftpAttachToken = crypto.randomUUID();
  const processAttachToken = crypto.randomUUID();
  const sftpAttachUrl = new URL('/api/admin/ssh/sftp', 'https://session.invalid');
  sftpAttachUrl.searchParams.set('session', id.toString());
  sftpAttachUrl.searchParams.set('token', sftpAttachToken);
  const processAttachUrl = new URL('/api/admin/ssh/processes', 'https://session.invalid');
  processAttachUrl.searchParams.set('session', id.toString());
  processAttachUrl.searchParams.set('token', processAttachToken);
  headers.set('x-session-ticket', ticket);
  headers.set('x-client-ip', clientAddress(request));
  headers.set('x-sftp-attach-token', sftpAttachToken);
  headers.set('x-sftp-attach-url', `${sftpAttachUrl.pathname}${sftpAttachUrl.search}`);
  headers.set('x-process-attach-token', processAttachToken);
  headers.set('x-process-attach-url', `${processAttachUrl.pathname}${processAttachUrl.search}`);

  const response = await c.env.SSH_SESSIONS.get(id).fetch(
    new Request('https://session.internal/connect', { headers }),
  );
  if (response.status === 401) return jsonError('Invalid, expired, or already used session ticket', 401);
  return response;
});

// GET /api/admin/ssh/sftp —— SFTP 文件管理 WebSocket 升级
app.get('/sftp', async (c) => {
  const request = c.req.raw;
  if (request.headers.get('Upgrade')?.toLowerCase() !== 'websocket') {
    return jsonError('WebSocket upgrade required', 426);
  }
  if (!hasValidWebSocketOrigin(request)) return jsonError('WebSocket origin is not allowed', 403);
  const url = new URL(request.url);
  const sessionId = url.searchParams.get('session');
  const token = url.searchParams.get('token');
  if (!sessionId || !token) return jsonError('Missing SFTP attachment authorization', 401);
  let id: DurableObjectId;
  try {
    id = c.env.SSH_SESSIONS.idFromString(sessionId);
  } catch {
    return jsonError('Invalid session identifier', 401);
  }
  const headers = new Headers(request.headers);
  headers.delete('Cookie');
  headers.delete('Authorization');
  headers.delete('x-session-ticket');
  headers.delete('x-client-ip');
  headers.delete('x-sftp-attach-url');
  headers.set('x-sftp-attach-token', token);
  const response = await c.env.SSH_SESSIONS.get(id).fetch(
    new Request('https://session.internal/sftp', { method: 'GET', headers }),
  );
  if (response.status === 401) return jsonError('Invalid, expired, or already used SFTP attachment token', 401);
  return response;
});

// GET /api/admin/ssh/processes —— 实时进程监控 WebSocket 升级
app.get('/processes', async (c) => {
  const request = c.req.raw;
  if (request.headers.get('Upgrade')?.toLowerCase() !== 'websocket') {
    return jsonError('WebSocket upgrade required', 426);
  }
  if (!hasValidWebSocketOrigin(request)) return jsonError('WebSocket origin is not allowed', 403);
  const url = new URL(request.url);
  const sessionId = url.searchParams.get('session');
  const token = url.searchParams.get('token');
  if (!sessionId || !token) return jsonError('Missing process attachment authorization', 401);
  let id: DurableObjectId;
  try {
    id = c.env.SSH_SESSIONS.idFromString(sessionId);
  } catch {
    return jsonError('Invalid session identifier', 401);
  }
  const headers = new Headers(request.headers);
  headers.delete('Cookie');
  headers.delete('Authorization');
  headers.delete('x-session-ticket');
  headers.delete('x-client-ip');
  headers.delete('x-process-attach-url');
  headers.set('x-process-attach-token', token);
  const response = await c.env.SSH_SESSIONS.get(id).fetch(
    new Request('https://session.internal/processes', { method: 'GET', headers }),
  );
  if (response.status === 401) return jsonError('Invalid, expired, or already used process attachment token', 401);
  return response;
});

export default app;
