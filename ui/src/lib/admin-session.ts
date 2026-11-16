const ADMIN_AUTH_KEY = "meiling_admin_auth"

/** Default matches the server default of admin.adminTokenMethod. */
export const DEFAULT_ADMIN_TOKEN_METHOD = "Meiling-Admin-Token"

export type AdminAuth = {
  method: string
  token: string
}

export function getAdminAuth(): AdminAuth | null {
  const raw = localStorage.getItem(ADMIN_AUTH_KEY)
  if (!raw) return null
  try {
    const parsed = JSON.parse(raw) as AdminAuth
    if (!parsed?.method || !parsed?.token) return null
    return parsed
  } catch {
    return null
  }
}

export function setAdminAuth(auth: AdminAuth) {
  localStorage.setItem(ADMIN_AUTH_KEY, JSON.stringify(auth))
}

export function clearAdminAuth() {
  localStorage.removeItem(ADMIN_AUTH_KEY)
}

export function adminAuthHeaders(): HeadersInit {
  const auth = getAdminAuth()
  if (!auth) return {}
  return { Authorization: `${auth.method} ${auth.token}` }
}

export function setAdminBearerToken(token: string) {
  setAdminAuth({ method: "Bearer", token })
}

export function setAdminToken(
  token: string,
  method = DEFAULT_ADMIN_TOKEN_METHOD,
) {
  setAdminAuth({ method, token })
}
