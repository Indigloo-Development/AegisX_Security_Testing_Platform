export const API_BASE = (process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:8000').replace(/\/$/, '');

export async function apiFetch(path: string, init: RequestInit = {}) {
  const headers = new Headers(init.headers || {});
  if (!headers.has('Content-Type') && init.body) headers.set('Content-Type', 'application/json');
  const response = await fetch(`${API_BASE}${path}`, { ...init, headers, cache: 'no-store' });
  const text = await response.text();
  let data: any = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  if (!response.ok) {
    const message = typeof data === 'object' && data?.detail ? data.detail : `Request failed (${response.status})`;
    const error: any = new Error(message);
    error.status = response.status;
    throw error;
  }
  if ((init.method || 'GET').toUpperCase() !== 'GET' && typeof window !== 'undefined') {
    window.dispatchEvent(new Event('aegisx:data-change'));
    try { localStorage.setItem('aegisx:data-change', String(Date.now())); } catch {}
  }
  return data;
}

export const api = apiFetch;
export const API = API_BASE;
