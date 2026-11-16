import { apiJson } from "@/lib/api"
import { authHeaders } from "@/lib/session"

export type UserEmail = { email: string; verified: boolean }
export type UserPhone = { phone: string; verified: boolean }

export type UserSerialized = {
  id: string
  usernames: string[]
  emails: string[]
  phones: string[]
  twoFactorEnabled: boolean
  userData?: UserData
  deletedAt?: string
}

export type UserData = {
  name?: string
  firstName?: string
  middleName?: string
  lastName?: string
  displayName?: string
  birthday?: string
  language?: string
  timezone?: string
}

export type SignInLog = {
  id: string
  ip: string
  country?: string
  countryCode?: string
  geoipData?: Record<string, unknown>
  signedInAt: string
  expiresAt?: string
  signedOutAt?: string
  userAgent: string
}

export type SignInLogsPage = {
  data: SignInLog[]
  total: number
  page: number
  size: number
}

export type TOTPEntry = { id: string; note: string }
export type WebAuthnEntry = { id: string; note: string }
export type BackupCodesInfo = { remaining: number }

export async function listSessionUsers(): Promise<UserSerialized[]> {
  const data = await apiJson<{ data: UserSerialized[] }>("/v2/users/?page=1&size=10", {
    headers: authHeaders(),
  })
  return data.data
}

export async function getUser(userId: string): Promise<UserSerialized> {
  return apiJson<UserSerialized>(`/v2/users/${userId}/`, {
    headers: authHeaders(),
  })
}

export async function getUserData(userId: string): Promise<UserData> {
  return apiJson<UserData>(`/v2/users/${userId}/userdata`, {
    headers: authHeaders(),
  })
}

export async function updateUserData(
  userId: string,
  data: Partial<UserData>,
): Promise<void> {
  await apiJson<unknown>(`/v2/users/${userId}/userdata`, {
    method: "PUT",
    headers: authHeaders(),
    body: JSON.stringify(data),
  })
}

export async function getUsernames(userId: string): Promise<string[]> {
  return apiJson<string[]>(`/v2/users/${userId}/usernames`, {
    headers: authHeaders(),
  })
}

export async function changeUsername(
  userId: string,
  username: string,
): Promise<void> {
  await apiJson<unknown>(`/v2/users/${userId}/usernames`, {
    method: "PUT",
    headers: authHeaders(),
    body: JSON.stringify({ username }),
  })
}

export async function getEmails(userId: string): Promise<UserEmail[]> {
  return apiJson<UserEmail[]>(`/v2/users/${userId}/emails`, {
    headers: authHeaders(),
  })
}

export async function addEmail(
  userId: string,
  email: string,
): Promise<void> {
  await apiJson<unknown>(`/v2/users/${userId}/emails`, {
    method: "POST",
    headers: authHeaders(),
    body: JSON.stringify({ email }),
  })
}

export async function removeEmail(
  userId: string,
  email: string,
): Promise<void> {
  await apiJson<unknown>(
    `/v2/users/${userId}/emails?email=${encodeURIComponent(email)}`,
    { method: "DELETE", headers: authHeaders() },
  )
}

export async function getPhones(userId: string): Promise<UserPhone[]> {
  return apiJson<UserPhone[]>(`/v2/users/${userId}/phones`, {
    headers: authHeaders(),
  })
}

export async function addPhone(
  userId: string,
  phone: string,
): Promise<void> {
  await apiJson<unknown>(`/v2/users/${userId}/phones`, {
    method: "POST",
    headers: authHeaders(),
    body: JSON.stringify({ phone }),
  })
}

export async function removePhone(
  userId: string,
  phone: string,
): Promise<void> {
  await apiJson<unknown>(
    `/v2/users/${userId}/phones?phone=${encodeURIComponent(phone)}`,
    { method: "DELETE", headers: authHeaders() },
  )
}

export async function changePassword(
  userId: string,
  prevPassword: string,
  newPassword: string,
): Promise<void> {
  await apiJson<unknown>(`/v2/users/${userId}/password`, {
    method: "PUT",
    headers: authHeaders(),
    body: JSON.stringify({ prevPassword, newPassword }),
  })
}

export async function getSignInLogs(
  userId: string,
  options?: { page?: number; size?: number },
): Promise<SignInLogsPage> {
  const page = options?.page ?? 1
  const size = options?.size ?? 25
  const data = await apiJson<{
    data: SignInLog[]
    pagination: { total: number; page: number; size: number }
  }>(`/v2/users/${userId}/logs?page=${page}&size=${size}`, {
    headers: authHeaders(),
  })
  return {
    data: data.data ?? [],
    total: data.pagination.total,
    page: data.pagination.page,
    size: data.pagination.size,
  }
}

export async function forceSignOut(
  userId: string,
  logId?: string,
): Promise<void> {
  const qs = logId ? `?id=${encodeURIComponent(logId)}` : ""
  await apiJson<unknown>(`/v2/users/${userId}/logs${qs}`, {
    method: "DELETE",
    headers: authHeaders(),
  })
}

export type BeginTOTPResponse = {
  totpUrl: string
  token: string
}

export type BeginWebAuthnResponse = {
  token: string
  response: Record<string, unknown>
}

export async function updateTwoFactorEnabled(
  userId: string,
  twoFactorEnabled: boolean,
): Promise<void> {
  await apiJson<unknown>(`/v2/users/${userId}/`, {
    method: "PUT",
    headers: authHeaders(),
    body: JSON.stringify({ twoFactorEnabled }),
  })
}

export async function getTOTPs(userId: string): Promise<TOTPEntry[]> {
  return apiJson<TOTPEntry[]>(`/v2/users/${userId}/totp`, {
    headers: authHeaders(),
  })
}

export async function beginAddTOTP(
  userId: string,
): Promise<BeginTOTPResponse> {
  return apiJson<BeginTOTPResponse>(`/v2/users/${userId}/totp`, {
    method: "POST",
    headers: authHeaders(),
    body: JSON.stringify({ token: "", challenge: "", note: "" }),
  })
}

export async function confirmAddTOTP(
  userId: string,
  input: { token: string; challenge: string; note?: string },
): Promise<void> {
  await apiJson<unknown>(`/v2/users/${userId}/totp`, {
    method: "POST",
    headers: authHeaders(),
    body: JSON.stringify({
      token: input.token,
      challenge: input.challenge,
      note: input.note ?? "",
    }),
  })
}

export async function removeTOTP(
  userId: string,
  totpId: string,
): Promise<void> {
  await apiJson<unknown>(
    `/v2/users/${userId}/totp?totp_id=${encodeURIComponent(totpId)}`,
    { method: "DELETE", headers: authHeaders() },
  )
}

export async function getWebAuthnKeys(
  userId: string,
): Promise<WebAuthnEntry[]> {
  return apiJson<WebAuthnEntry[]>(`/v2/users/${userId}/webauthn`, {
    headers: authHeaders(),
  })
}

export async function beginAddWebAuthn(
  userId: string,
): Promise<BeginWebAuthnResponse> {
  return apiJson<BeginWebAuthnResponse>(`/v2/users/${userId}/webauthn`, {
    method: "POST",
    headers: authHeaders(),
    body: JSON.stringify({ token: "", note: "", response: {} }),
  })
}

export async function confirmAddWebAuthn(
  userId: string,
  input: {
    token: string
    response: Record<string, unknown>
    note?: string
  },
): Promise<void> {
  await apiJson<unknown>(`/v2/users/${userId}/webauthn`, {
    method: "POST",
    headers: authHeaders(),
    body: JSON.stringify({
      token: input.token,
      response: input.response,
      note: input.note ?? "",
    }),
  })
}

export async function removeWebAuthnKey(
  userId: string,
  webauthnId: string,
): Promise<void> {
  await apiJson<unknown>(
    `/v2/users/${userId}/webauthn?webauthn_id=${encodeURIComponent(webauthnId)}`,
    { method: "DELETE", headers: authHeaders() },
  )
}

export async function getBackupCodes(
  userId: string,
): Promise<BackupCodesInfo> {
  return apiJson<BackupCodesInfo>(`/v2/users/${userId}/backup-codes`, {
    headers: authHeaders(),
  })
}

export async function regenerateBackupCodes(
  userId: string,
): Promise<{ codes: string[]; remaining: number }> {
  return apiJson<{ codes: string[]; remaining: number }>(
    `/v2/users/${userId}/backup-codes/regenerate`,
    { method: "POST", headers: authHeaders() },
  )
}
