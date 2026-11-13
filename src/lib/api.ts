import type {
  GatewayStatus,
  HarnessKind,
  HarnessProfile,
  HideConfig,
  RuleValidation,
  TrafficAuditRecord,
  TrafficCategory,
  TrafficSummary,
  VaultEntry,
} from '../types';

declare global {
  interface Window {
    __HIDE_GO_TOKEN__?: string;
  }
}

const TOKEN_KEY = 'hg-dev-token';

/**
 * The desktop binary injects the management token into the page. During `npm run dev`
 * it can be passed once as `?token=…`; it is then moved to sessionStorage and removed
 * from the address bar so it does not linger in history.
 */
function resolveToken(): string {
  if (window.__HIDE_GO_TOKEN__) return window.__HIDE_GO_TOKEN__;
  const url = new URL(window.location.href);
  const fromQuery = url.searchParams.get('token');
  if (fromQuery) {
    sessionStorage.setItem(TOKEN_KEY, fromQuery);
    url.searchParams.delete('token');
    window.history.replaceState(null, '', url.toString());
    return fromQuery;
  }
  return sessionStorage.getItem(TOKEN_KEY) ?? '';
}

const token = resolveToken();

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  if (token) headers.set('X-Hide-Go-Token', token);
  if (init.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json');
  let res: Response;
  try {
    res = await fetch(path, { ...init, headers, credentials: 'omit', cache: 'no-store' });
  } catch {
    throw new ApiError(0, '无法连接本地网关');
  }
  if (!res.ok) {
    let message = `HTTP ${res.status}`;
    try {
      const body = await res.json();
      message = body.message ?? body.error ?? message;
    } catch {
      /* non-JSON error body */
    }
    if (res.status === 401) message = '管理令牌无效：请通过 Hide-Go 桌面程序打开控制台';
    throw new ApiError(res.status, message);
  }
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

export const api = {
  hasToken: () => token.length > 0,
  status: () => request<GatewayStatus>('/api/status'),
  config: () => request<HideConfig>('/api/config'),
  saveConfig: (cfg: HideConfig) => request<HideConfig>('/api/config', { method: 'POST', body: JSON.stringify(cfg) }),
  logs: () => request<TrafficSummary[]>('/api/logs'),
  log: (id: string) => request<TrafficAuditRecord>(`/api/logs/${encodeURIComponent(id)}`),
  clearLogs: () => request<void>('/api/logs', { method: 'DELETE' }),
  harnesses: () => request<HarnessProfile[]>('/api/harnesses'),
  vault: () => request<VaultEntry[]>('/api/vault'),
  clearVault: () => request<void>('/api/vault', { method: 'DELETE' }),
  simulate: (harness: HarnessKind, category: TrafficCategory, customPayload?: string) =>
    request<TrafficAuditRecord>('/api/simulate', {
      method: 'POST',
      body: JSON.stringify({ harness, category, customPayload: customPayload || null }),
    }),
  validateRule: (pattern: string, sample?: string) =>
    request<RuleValidation>('/api/rules/validate', { method: 'POST', body: JSON.stringify({ pattern, sample }) }),
};
