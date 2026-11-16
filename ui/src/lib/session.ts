import { apiJson } from "@/lib/api"

const TOKEN_KEY = "meiling_session"

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY)
}

export function setToken(token: string) {
  localStorage.setItem(TOKEN_KEY, token)
}

export function clearToken() {
  localStorage.removeItem(TOKEN_KEY)
}

export function authHeaders(): HeadersInit {
  const token = getToken()
  return token ? { Authorization: `Bearer ${token}` } : {}
}

type CreateSessionResponse = {
  token: string
  expiresAt: string
  renewableAfter: string
  renewed: boolean
}

export async function createSession(): Promise<string> {
  const headers = getToken() ? authHeaders() : {}
  const data = await apiJson<CreateSessionResponse>("/v2/sessions/", {
    method: "POST",
    headers,
  })
  setToken(data.token)
  return data.token
}

export async function validateSession(): Promise<boolean> {
  try {
    await apiJson<{ renewable: boolean }>("/v2/sessions/", {
      headers: authHeaders(),
    })
    return true
  } catch {
    return false
  }
}

/**
 * Signs every user out of the session. Returns the applications'
 * front-channel logout URIs for the browser to load.
 */
export async function signOut(): Promise<string[]> {
  try {
    const result = await apiJson<{ frontchannelLogoutUris?: string[] }>(
      "/v2/auth/signout",
      { method: "POST", headers: authHeaders() },
    )
    return result.frontchannelLogoutUris ?? []
  } catch {
    return []
  } finally {
    clearToken()
  }
}

export async function ensureSession(): Promise<string> {
  const existing = getToken()
  if (existing) return existing
  return createSession()
}
