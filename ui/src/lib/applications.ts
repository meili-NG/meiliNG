import { apiJson } from "@/lib/api"
import { authHeaders } from "@/lib/session"

/** A registered application. Its id is also its OAuth2 client_id. */
export type Application = {
  id: string
  iconUrl?: string
  name: string
  terms: string
  privacy: string
  ownerId: string | null
  isVerified: boolean
  isPublicClient: boolean
}

/** The API path of one application, or of `tail` under it. */
export function appPath(appId: string, tail = ""): string {
  return `/v2/apps/${encodeURIComponent(appId)}/${tail}`
}

export async function getApplications(
  owned?: boolean,
): Promise<{ data: Application[] }> {
  const qs = owned ? "?owned=true" : ""
  return apiJson<{ data: Application[] }>(`/v2/apps/${qs}`, {
    headers: authHeaders(),
  })
}

export async function getApplication(appId: string): Promise<Application> {
  return apiJson<Application>(appPath(appId), { headers: authHeaders() })
}

export async function createApplication(
  userId: string,
  payload: {
    name: string
    redirectURIs: string[]
    privacy: string
    terms: string
    isPublicClient?: boolean
  },
): Promise<void> {
  await apiJson<unknown>(`/v2/apps/?user_id=${encodeURIComponent(userId)}`, {
    method: "POST",
    headers: authHeaders(),
    body: JSON.stringify(payload),
  })
}

export async function updateApplication(
  appId: string,
  payload: { name?: string; isPublicClient?: boolean },
): Promise<void> {
  await apiJson<unknown>(appPath(appId), {
    method: "PUT",
    headers: authHeaders(),
    body: JSON.stringify(payload),
  })
}

export async function deleteApplication(appId: string): Promise<void> {
  await apiJson<unknown>(appPath(appId), {
    method: "DELETE",
    headers: authHeaders(),
  })
}
