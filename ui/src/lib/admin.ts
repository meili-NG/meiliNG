import { ApiError, apiJson } from "@/lib/api"
import {
  adminAuthHeaders,
  clearAdminAuth,
  getAdminAuth,
} from "@/lib/admin-session"
import type {
  SignInLog,
  SignInLogsPage,
  UserData,
  UserEmail,
  UserPhone,
  UserSerialized,
  TOTPEntry,
  WebAuthnEntry,
} from "@/lib/users"
import { appPath, type Application } from "@/lib/applications"
import type {
  Audience,
  ClientAudience,
  ClientSecret,
  ClientRedirectUri,
} from "@/lib/oauth2"


export type PermissionSerialized = {
  id: string
  scope: string
  message: string
  localizedMessages?: Record<string, unknown>
  /** The broader permission that contains this one; null for top level. */
  parentId: string | null
  isPublic: boolean
  /** New applications start allowed it; existing applications are not changed. */
  isDefault: boolean
}

type Pagination = { total: number; page: number; size: number }

type PaginatedUsers = {
  data: UserSerialized[]
  pagination: Pagination
}

type PaginatedPermissions = {
  data: PermissionSerialized[]
  pagination: Pagination
}

type PaginatedApplications = {
  data: Application[]
  pagination: Pagination
}

/**
 * Probe an admin-only endpoint to confirm the given credentials have admin
 * rights. `GET /v2/admin/` answers 200 for an admin token or an admin-audience M2M
 * access token, and 401/403 otherwise. Account sessions are never admins.
 */
async function probeAdmin(headers: HeadersInit): Promise<boolean> {
  try {
    await apiJson<unknown>("/v2/admin/", { headers })
    return true
  } catch (err) {
    if (err instanceof ApiError && err.type) {
      // A structured auth error means "reached the server, not an admin".
      return false
    }
    return false
  }
}

export async function verifyAdminAuth(): Promise<boolean> {
  if (!getAdminAuth()) return false
  if (await probeAdmin(adminAuthHeaders())) return true
  clearAdminAuth()
  return false
}

function h(): HeadersInit {
  return adminAuthHeaders()
}

/* ── Users ─────────────────────────────────────────────── */

export async function listAllUsers(options?: {
  search?: string
  page?: number
  size?: number
}): Promise<PaginatedUsers & { total: number }> {
  const params = new URLSearchParams({
    all: "true",
    page: String(options?.page ?? 1),
    size: String(options?.size ?? 20),
  })
  if (options?.search) params.set("search", options.search)
  const data = await apiJson<PaginatedUsers>(`/v2/users/?${params}`, {
    headers: h(),
  })
  return { ...data, total: data.pagination.total }
}

export async function createUser(body: {
  username?: string
  password: string
  emails?: { email: string; verified?: boolean }[]
  phones?: { phone: string; verified?: boolean }[]
}): Promise<UserSerialized | void> {
  return apiJson<UserSerialized | void>("/v2/users/", {
    method: "POST",
    headers: h(),
    body: JSON.stringify(body),
  })
}

export async function bulkCheckUsers(
  userIds: string[],
): Promise<{ found: string[]; notFound: string[]; users: UserSerialized[] }> {
  const data = await apiJson<{
    users: UserSerialized[]
    notFound: string[]
  }>("/v2/users/bulk", {
    method: "POST",
    headers: h(),
    body: JSON.stringify({ userIds }),
  })
  return { ...data, found: data.users.map((u) => u.id) }
}

export async function adminGetUser(userId: string): Promise<UserSerialized> {
  return apiJson<UserSerialized>(`/v2/users/${userId}/`, { headers: h() })
}

export async function adminUpdateUser(
  userId: string,
  body: { twoFactorEnabled?: boolean },
): Promise<void> {
  await apiJson<unknown>(`/v2/users/${userId}/`, {
    method: "PUT",
    headers: h(),
    body: JSON.stringify(body),
  })
}

export async function adminDeleteUser(userId: string): Promise<void> {
  await apiJson<unknown>(`/v2/users/${userId}/`, {
    method: "DELETE",
    headers: h(),
  })
}

export async function adminGetUserData(userId: string): Promise<UserData> {
  return apiJson<UserData>(`/v2/users/${userId}/userdata`, { headers: h() })
}

export async function adminUpdateUserData(
  userId: string,
  data: Partial<UserData>,
): Promise<void> {
  await apiJson<unknown>(`/v2/users/${userId}/userdata`, {
    method: "PUT",
    headers: h(),
    body: JSON.stringify(data),
  })
}

export async function adminGetUserDataLock(
  userId: string,
): Promise<Record<string, unknown>> {
  return apiJson<Record<string, unknown>>(`/v2/users/${userId}/userdata/lock`, {
    headers: h(),
  })
}

export async function adminSetUserDataLock(
  userId: string,
  lock: Record<string, unknown>,
): Promise<void> {
  await apiJson<unknown>(`/v2/users/${userId}/userdata/lock`, {
    method: "PUT",
    headers: h(),
    body: JSON.stringify(lock),
  })
}

export async function adminGetEmails(userId: string): Promise<UserEmail[]> {
  return apiJson<UserEmail[]>(`/v2/users/${userId}/emails`, { headers: h() })
}

export async function adminAddEmail(
  userId: string,
  email: string,
  verified = false,
): Promise<void> {
  await apiJson<unknown>(`/v2/users/${userId}/emails`, {
    method: "POST",
    headers: h(),
    body: JSON.stringify({ email, verified }),
  })
}

export async function adminSetEmailVerified(
  userId: string,
  email: string,
  verified: boolean,
): Promise<void> {
  await apiJson<unknown>(
    `/v2/users/${userId}/emails?email=${encodeURIComponent(email)}`,
    { method: "PUT", headers: h(), body: JSON.stringify({ verified }) },
  )
}

export async function adminRemoveEmail(
  userId: string,
  email: string,
): Promise<void> {
  await apiJson<unknown>(
    `/v2/users/${userId}/emails?email=${encodeURIComponent(email)}`,
    { method: "DELETE", headers: h() },
  )
}

export async function adminGetPhones(userId: string): Promise<UserPhone[]> {
  return apiJson<UserPhone[]>(`/v2/users/${userId}/phones`, { headers: h() })
}

export async function adminAddPhone(
  userId: string,
  phone: string,
  verified = false,
): Promise<void> {
  await apiJson<unknown>(`/v2/users/${userId}/phones`, {
    method: "POST",
    headers: h(),
    body: JSON.stringify({ phone, verified }),
  })
}

export async function adminSetPhoneVerified(
  userId: string,
  phone: string,
  verified: boolean,
): Promise<void> {
  await apiJson<unknown>(
    `/v2/users/${userId}/phones?phone=${encodeURIComponent(phone)}`,
    { method: "PUT", headers: h(), body: JSON.stringify({ verified }) },
  )
}

export async function adminRemovePhone(
  userId: string,
  phone: string,
): Promise<void> {
  await apiJson<unknown>(
    `/v2/users/${userId}/phones?phone=${encodeURIComponent(phone)}`,
    { method: "DELETE", headers: h() },
  )
}

export async function adminChangeUsername(
  userId: string,
  username: string,
): Promise<void> {
  await apiJson<unknown>(`/v2/users/${userId}/usernames`, {
    method: "PUT",
    headers: h(),
    body: JSON.stringify({ username }),
  })
}

export async function adminAddUsername(
  userId: string,
  username: string,
): Promise<void> {
  await apiJson<unknown>(`/v2/users/${userId}/usernames`, {
    method: "POST",
    headers: h(),
    body: JSON.stringify({ username }),
  })
}

export async function adminRemoveUsername(
  userId: string,
  username: string,
): Promise<void> {
  await apiJson<unknown>(
    `/v2/users/${userId}/usernames?username=${encodeURIComponent(username)}`,
    { method: "DELETE", headers: h() },
  )
}

export async function adminChangePassword(
  userId: string,
  newPassword: string,
): Promise<void> {
  await apiJson<unknown>(`/v2/users/${userId}/password`, {
    method: "PUT",
    headers: h(),
    body: JSON.stringify({ prevPassword: "", newPassword }),
  })
}

/* ── Backup codes ──────────────────────────────────────── */

export async function adminGetBackupCodes(
  userId: string,
): Promise<{ remaining: number }> {
  return apiJson<{ remaining: number }>(`/v2/users/${userId}/backup-codes`, {
    headers: h(),
  })
}

export async function adminRegenerateBackupCodes(
  userId: string,
): Promise<{ codes: string[]; remaining: number }> {
  return apiJson<{ codes: string[]; remaining: number }>(
    `/v2/users/${userId}/backup-codes/regenerate`,
    { method: "POST", headers: h() },
  )
}

export async function adminDeleteBackupCodes(userId: string): Promise<void> {
  await apiJson<unknown>(`/v2/users/${userId}/backup-codes`, {
    method: "DELETE",
    headers: h(),
  })
}

/* ── Sign-in statistics ────────────────────────────────── */

export type SignInCountryStat = {
  country: string
  countryCode: string
  count: number
}

export async function adminGetSignInStats(
  userId: string,
): Promise<SignInCountryStat[]> {
  const data = await apiJson<{
    statistics: { countries: SignInCountryStat[] | null }
  }>(`/v2/users/${userId}/logs/statistics`, { headers: h() })
  return data.statistics.countries ?? []
}

export async function adminGetTOTPs(userId: string): Promise<TOTPEntry[]> {
  return apiJson<TOTPEntry[]>(`/v2/users/${userId}/totp`, { headers: h() })
}

export async function adminRemoveTOTP(
  userId: string,
  totpId: string,
): Promise<void> {
  await apiJson<unknown>(
    `/v2/users/${userId}/totp?totp_id=${encodeURIComponent(totpId)}`,
    { method: "DELETE", headers: h() },
  )
}

export async function adminGetWebAuthn(
  userId: string,
): Promise<WebAuthnEntry[]> {
  return apiJson<WebAuthnEntry[]>(`/v2/users/${userId}/webauthn`, {
    headers: h(),
  })
}

export async function adminRemoveWebAuthn(
  userId: string,
  webauthnId: string,
): Promise<void> {
  await apiJson<unknown>(
    `/v2/users/${userId}/webauthn?webauthn_id=${encodeURIComponent(webauthnId)}`,
    { method: "DELETE", headers: h() },
  )
}

export async function adminGetSignInLogs(
  userId: string,
  options?: { page?: number; size?: number },
): Promise<SignInLogsPage> {
  const page = options?.page ?? 1
  const size = options?.size ?? 25
  const data = await apiJson<{
    data: SignInLog[]
    pagination: Pagination
  }>(`/v2/users/${userId}/logs?page=${page}&size=${size}`, { headers: h() })
  return {
    data: data.data ?? [],
    total: data.pagination.total,
    page: data.pagination.page,
    size: data.pagination.size,
  }
}

export async function adminForceSignOut(
  userId: string,
  logId?: string,
): Promise<void> {
  const qs = logId ? `?id=${encodeURIComponent(logId)}` : ""
  await apiJson<unknown>(`/v2/users/${userId}/logs${qs}`, {
    method: "DELETE",
    headers: h(),
  })
}

export async function adminGetMetadata(
  userId: string,
): Promise<Record<string, unknown>> {
  return apiJson<Record<string, unknown>>(`/v2/users/${userId}/metadata/`, {
    headers: h(),
  })
}

export async function adminPutMetadata(
  userId: string,
  metadata: Record<string, unknown>,
): Promise<void> {
  await apiJson<unknown>(`/v2/users/${userId}/metadata/`, {
    method: "PUT",
    headers: h(),
    body: JSON.stringify(metadata),
  })
}

export async function adminPatchMetadata(
  userId: string,
  metadata: Record<string, unknown>,
): Promise<void> {
  await apiJson<unknown>(`/v2/users/${userId}/metadata/`, {
    method: "PATCH",
    headers: h(),
    body: JSON.stringify(metadata),
  })
}

/* ── Permissions ───────────────────────────────────────── */

export async function listAllPermissions(): Promise<PermissionSerialized[]> {
  const size = 100
  const byId = new Map<string, PermissionSerialized>()
  for (let page = 1; ; page++) {
    const params = new URLSearchParams({
      all: "true",
      page: String(page),
      size: String(size),
    })
    const data = await apiJson<PaginatedPermissions>(
      `/v2/permissions/?${params}`,
      { headers: h() },
    )
    const rows = data.data ?? []
    const before = byId.size
    for (const row of rows) byId.set(row.id, row)
    // Stop on a page that adds nothing, so a server ignoring `page` cannot loop us forever.
    if (
      rows.length < size ||
      byId.size === before ||
      byId.size >= data.pagination.total
    ) {
      return [...byId.values()]
    }
  }
}

export async function createPermission(body: {
  scope: string
  isPublic?: boolean
  isDefault?: boolean
  parentId?: string
  message?: string
}): Promise<void> {
  await apiJson<unknown>("/v2/permissions/", {
    method: "POST",
    headers: h(),
    body: JSON.stringify(body),
  })
}

/** Replaces the mutable fields; parentId "" moves it to top level. */
export async function updatePermission(
  id: string,
  body: {
    parentId: string
    isPublic: boolean
    isDefault: boolean
    message: string
  },
): Promise<void> {
  await apiJson<unknown>(`/v2/permissions/?id=${encodeURIComponent(id)}`, {
    method: "PUT",
    headers: h(),
    body: JSON.stringify(body),
  })
}

export async function deletePermission(id: string): Promise<void> {
  await apiJson<unknown>(`/v2/permissions/?id=${encodeURIComponent(id)}`, {
    method: "DELETE",
    headers: h(),
  })
}

/* ── Applications ─────────────────────────────────────── */

export async function listAllApplications(options?: {
  page?: number
  size?: number
  owned?: boolean
  search?: string
}): Promise<PaginatedApplications & { total: number }> {
  const params = new URLSearchParams({
    all: "true",
    page: String(options?.page ?? 1),
    size: String(options?.size ?? 20),
  })
  if (options?.owned) params.set("owned", "true")
  const data = await apiJson<PaginatedApplications>(
    `/v2/apps/?${params}`,
    { headers: h() },
  )
  return { ...data, total: data.pagination.total }
}

export async function adminGetApplication(appId: string): Promise<Application> {
  return apiJson<Application>(appPath(appId), {
    headers: h(),
  })
}

export async function adminUpdateApplication(
  appId: string,
  body: Partial<Application> & { name?: string; isPublicClient?: boolean },
): Promise<void> {
  await apiJson<unknown>(appPath(appId), {
    method: "PUT",
    headers: h(),
    body: JSON.stringify(body),
  })
}

export async function adminDeleteApplication(appId: string): Promise<void> {
  await apiJson<unknown>(appPath(appId), {
    method: "DELETE",
    headers: h(),
  })
}

export async function adminListUserApplications(
  userId: string,
): Promise<Application[]> {
  const params = new URLSearchParams({
    owned: "true",
    user_id: userId,
    page: "1",
    size: "50",
  })
  const data = await apiJson<PaginatedApplications>(
    `/v2/apps/?${params}`,
    { headers: h() },
  )
  return data.data ?? []
}

export async function adminListAuthorizedApps(
  userId: string,
): Promise<Application[]> {
  const params = new URLSearchParams({
    authorized: "true",
    user_id: userId,
    page: "1",
    size: "50",
  })
  const data = await apiJson<PaginatedApplications>(
    `/v2/apps/?${params}`,
    { headers: h() },
  )
  return data.data ?? []
}

export async function adminUnauthorizeApp(
  appId: string,
  userId: string,
): Promise<void> {
  await apiJson<unknown>(
    appPath(appId, `unauthorize?user_id=${encodeURIComponent(userId)}`),
    { method: "POST", headers: h() },
  )
}

export async function adminGetSecrets(
  appId: string,
): Promise<ClientSecret[]> {
  return apiJson<ClientSecret[]>(appPath(appId, "oauth2/secrets/"), {
    headers: h(),
  })
}

export async function adminCreateSecret(
  appId: string,
  notes?: string,
): Promise<void> {
  await apiJson<unknown>(appPath(appId, "oauth2/secrets/"), {
    method: "POST",
    headers: h(),
    body: JSON.stringify({ notes }),
  })
}

export async function adminDeleteSecret(
  appId: string,
  secretId: string,
): Promise<void> {
  await apiJson<unknown>(
    appPath(appId, `oauth2/secrets/?secret_id=${encodeURIComponent(secretId)}`),
    { method: "DELETE", headers: h() },
  )
}

export async function adminGetRedirectUris(
  appId: string,
): Promise<ClientRedirectUri[]> {
  return apiJson<ClientRedirectUri[]>(
    appPath(appId, "oauth2/redirect_uris/"),
    { headers: h() },
  )
}

export async function adminAddRedirectUri(
  appId: string,
  uri: string,
): Promise<void> {
  await apiJson<unknown>(appPath(appId, "oauth2/redirect_uris/"), {
    method: "POST",
    headers: h(),
    body: JSON.stringify({ redirect_uri: uri }),
  })
}

export async function adminDeleteRedirectUri(
  appId: string,
  uriId: string,
): Promise<void> {
  await apiJson<unknown>(
    appPath(appId, `oauth2/redirect_uris/?redirectUriId=${encodeURIComponent(uriId)}`),
    { method: "DELETE", headers: h() },
  )
}

export async function adminGetAudiences(
  appId: string,
): Promise<ClientAudience[]> {
  return apiJson<ClientAudience[]>(
    appPath(appId, "oauth2/audiences/"),
    { headers: h() },
  )
}

export async function adminAssignAudience(
  appId: string,
  audienceId: string,
): Promise<void> {
  await apiJson<unknown>(appPath(appId, "oauth2/audiences/"), {
    method: "POST",
    headers: h(),
    body: JSON.stringify({ audience_id: audienceId }),
  })
}

export async function adminUnassignAudience(
  appId: string,
  assignmentId: string,
): Promise<void> {
  await apiJson<unknown>(
    appPath(appId, `oauth2/audiences/?audienceId=${encodeURIComponent(assignmentId)}`),
    { method: "DELETE", headers: h() },
  )
}

export type ApplicationPermissionLimit = {
  /** false: the application may request any permission, whatever `permissions` holds. */
  limited: boolean
  permissions: PermissionSerialized[]
}

export async function adminGetApplicationPermissions(
  appId: string,
): Promise<ApplicationPermissionLimit> {
  return apiJson<ApplicationPermissionLimit>(
    appPath(appId, "permissions/"),
    { headers: h() },
  )
}

/** Full replacement of the limit and the allowed set. */
export async function adminSetApplicationPermissions(
  appId: string,
  body: { limited: boolean; permissionIds: string[] },
): Promise<ApplicationPermissionLimit> {
  return apiJson<ApplicationPermissionLimit>(
    appPath(appId, "permissions/"),
    { method: "PUT", headers: h(), body: JSON.stringify(body) },
  )
}

export async function adminListRegisteredAudiences(): Promise<Audience[]> {
  return apiJson<Audience[]>(`/v2/oauth2/audiences/`, { headers: h() })
}

export async function adminRegisterAudience(input: {
  audience: string
  description?: string
}): Promise<Audience> {
  return apiJson<Audience>(`/v2/oauth2/audiences/`, {
    method: "POST",
    headers: h(),
    body: JSON.stringify(input),
  })
}

export async function adminUpdateRegisteredAudience(
  audienceId: string,
  description: string,
): Promise<Audience> {
  return apiJson<Audience>(`/v2/oauth2/audiences/${audienceId}/`, {
    method: "PUT",
    headers: h(),
    body: JSON.stringify({ description }),
  })
}

export async function adminDeleteRegisteredAudience(
  audienceId: string,
): Promise<void> {
  await apiJson<unknown>(`/v2/oauth2/audiences/${audienceId}/`, {
    method: "DELETE",
    headers: h(),
  })
}

/* ── Token debug ───────────────────────────────────────── */

export type TokenInfo = Record<string, unknown>

export async function getTokenInfo(input: {
  accessToken?: string
  refreshToken?: string
  idToken?: string
}): Promise<TokenInfo> {
  return apiJson<TokenInfo>("/v2/oauth2/tokeninfo", {
    method: "POST",
    headers: h(),
    body: JSON.stringify({
      access_token: input.accessToken || undefined,
      refresh_token: input.refreshToken || undefined,
      id_token: input.idToken || undefined,
    }),
  })
}

export async function revokeToken(input: {
  token: string
  tokenTypeHint?: string
}): Promise<void> {
  await apiJson<unknown>("/v2/oauth2/revoke", {
    method: "POST",
    headers: h(),
    body: JSON.stringify({
      token: input.token,
      token_type_hint: input.tokenTypeHint || undefined,
    }),
  })
}

export async function debugSession(token: string): Promise<unknown> {
  return apiJson<unknown>(
    `/v2/sessions/debug/?token=${encodeURIComponent(token)}`,
    { headers: h() },
  )
}
