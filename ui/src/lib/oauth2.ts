import { apiJson } from "@/lib/api"
import { appPath } from "@/lib/applications"
import { authHeaders } from "@/lib/session"

export type ClientSecret = {
  id: string
  client_secret: string
  notes?: string
}

/** A registered audience assigned to a client, which the client may then
 * request with the client_credentials grant. */
export type ClientAudience = {
  id: string
  audience_id: string
  audience: string
  description: string
}

/** An audience registered on this instance: a resource server clients can be
 * assigned to. */
export type Audience = {
  id: string
  audience: string
  description: string
  client_count: number
}

export type ClientRedirectUri = {
  id: string
  redirect_uri: string
}

export type ConsentInfo = {
  userConsentRequired: boolean
  /** The user has to sign in again first, for max_age or acr_values. */
  reauthenticationRequired?: boolean
  /** What still needs consent: already granted or contained ones are left out. */
  permissions?: { scope: string; message?: string }[]
}

/** Redirect URIs that show the response in the page instead of redirecting. */
export const OOB_REDIRECT_URIS = [
  "urn:ietf:wg:oauth:2.0:oob",
  "urn:ietf:wg:oauth:2.0:oob:auto",
]

/** The authorization-request parameters the consent check accepts. */
const CONSENT_PARAMS = [
  "response_type",
  "scope",
  "redirect_uri",
  "prompt",
  "include_granted_scopes",
  "max_age",
  "acr_values",
]

/** The authorize operation accepts these as well. */
const AUTHORIZE_PARAMS = [
  ...CONSENT_PARAMS,
  "access_type",
  "state",
  "nonce",
  "code_challenge",
  "code_challenge_method",
]

/** Forwards the named parameters of the authorization request as they came. */
function authQuery(
  request: URLSearchParams,
  names: string[],
  userId: string,
): URLSearchParams {
  const query = new URLSearchParams({ user_id: userId })
  for (const name of names) {
    const value = request.get(name)
    if (value !== null) query.set(name, value)
  }
  return query
}

/** Asks which permissions of the authorization request still need consent. */
export async function getAuthConsent(
  appId: string,
  request: URLSearchParams,
  userId: string,
): Promise<ConsentInfo> {
  return apiJson<ConsentInfo>(
    appPath(appId, `oauth2/auth/?${authQuery(request, CONSENT_PARAMS, userId)}`),
    { headers: authHeaders() },
  )
}

/**
 * Completes the authorization request. `approve` is the user's explicit
 * approval: without it the server refuses while anything needs consent.
 */
export async function authorizeClient(
  appId: string,
  request: URLSearchParams,
  userId: string,
  approve: boolean,
): Promise<{ code?: string }> {
  const query = authQuery(request, AUTHORIZE_PARAMS, userId)
  if (approve) query.set("approve", "true")
  return apiJson<{ code?: string }>(
    appPath(appId, `oauth2/auth/?${query}`),
    { method: "POST", headers: authHeaders() },
  )
}

export async function getSecrets(
  appId: string,
): Promise<ClientSecret[]> {
  return apiJson<ClientSecret[]>(
    appPath(appId, "oauth2/secrets/"),
    { headers: authHeaders() },
  )
}

export async function createSecret(
  appId: string,
  notes?: string,
): Promise<void> {
  await apiJson<unknown>(appPath(appId, "oauth2/secrets/"), {
    method: "POST",
    headers: authHeaders(),
    body: JSON.stringify({ notes }),
  })
}

export async function deleteSecret(
  appId: string,
  secretId: string,
): Promise<void> {
  await apiJson<unknown>(
    appPath(appId, `oauth2/secrets/?secret_id=${encodeURIComponent(secretId)}`),
    { method: "DELETE", headers: authHeaders() },
  )
}

export async function getRedirectUris(
  appId: string,
): Promise<ClientRedirectUri[]> {
  return apiJson<ClientRedirectUri[]>(
    appPath(appId, "oauth2/redirect_uris/"),
    { headers: authHeaders() },
  )
}

export async function addRedirectUri(
  appId: string,
  redirectUri: string,
): Promise<void> {
  await apiJson<unknown>(
    appPath(appId, "oauth2/redirect_uris/"),
    {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify({ redirect_uri: redirectUri }),
    },
  )
}

export async function deleteRedirectUri(
  appId: string,
  redirectUriId: string,
): Promise<void> {
  await apiJson<unknown>(
    appPath(appId, `oauth2/redirect_uris/?redirectUriId=${encodeURIComponent(redirectUriId)}`),
    { method: "DELETE", headers: authHeaders() },
  )
}

/** Where the browser goes after a confirmed logout. */
export type EndSessionResult = {
  /** The application's post-logout redirect URI with state, if it gave one. */
  redirectUri?: string
  frontchannelLogoutUris: string[]
}

/**
 * Confirms the OpenID Connect logout request the page was opened with: the
 * server signs the user out and tells the applications they used.
 */
export async function confirmEndSession(
  request: URLSearchParams,
  userId?: string,
): Promise<EndSessionResult> {
  return apiJson<EndSessionResult>("/v2/oauth2/logout/confirm", {
    method: "POST",
    headers: authHeaders(),
    body: JSON.stringify({
      idTokenHint: request.get("id_token_hint") ?? undefined,
      clientId: request.get("client_id") ?? undefined,
      postLogoutRedirectUri: request.get("post_logout_redirect_uri") ?? undefined,
      state: request.get("state") ?? undefined,
      userId,
    }),
  })
}
