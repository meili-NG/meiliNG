import { apiJson, ApiError } from "@/lib/api"
import { authHeaders } from "@/lib/session"

type ChallengeAction = {
  action: "challenge"
  requestToken: string
}

type ValidateResult = {
  passed: boolean
}

export async function beginSignIn(username: string): Promise<string> {
  const data = await apiJson<ChallengeAction>("/v2/auth/signin", {
    method: "POST",
    headers: authHeaders(),
    body: JSON.stringify({ username: username.trim() }),
  })
  if (data.action !== "challenge" || !data.requestToken) {
    throw new Error("unexpected sign-in response")
  }
  return data.requestToken
}

export async function issueChallenge(
  challengeToken: string,
  type: string,
  purpose: string = "signin",
): Promise<void> {
  const params = new URLSearchParams({
    token: challengeToken,
    type,
    for: purpose,
  })
  await apiJson<unknown>(`/v2/auth/challenge/issue?${params}`, {
    method: "POST",
  })
}

export async function validateChallenge(
  challengeToken: string,
  type: string,
  response: string,
  purpose: string = "signin",
): Promise<boolean> {
  const params = new URLSearchParams({
    token: challengeToken,
    type,
    for: purpose,
  })
  const data = await apiJson<ValidateResult>(
    `/v2/auth/challenge/validate?${params}`,
    {
      method: "POST",
      body: JSON.stringify({ response }),
    },
  )
  return data.passed
}

export async function getChallengeTypes(
  challengeToken: string,
  purpose: string = "signin",
): Promise<string[]> {
  const params = new URLSearchParams({
    token: challengeToken,
    for: purpose,
  })
  return apiJson<string[]>(`/v2/auth/challenge?${params}`)
}

/**
 * Complete sign-in with password. If 2FA is required, throws ApiError
 * with type "two_factor_required" — caller should then issue+validate
 * a 2FA challenge and retry.
 */
export async function completePasswordChallenge(
  challengeToken: string,
  password: string,
): Promise<void> {
  await issueChallenge(challengeToken, "password")
  const passed = await validateChallenge(challengeToken, "password", password)
  if (!passed) {
    throw new ApiError("Incorrect password", "invalid_credentials")
  }
}

/**
 * Final sign-in step: submit challengeToken back.
 * Throws "two_factor_required" if 2FA is needed.
 */
export async function finalizeSignIn(
  username: string,
  challengeToken: string,
): Promise<void> {
  await apiJson<unknown>("/v2/auth/signin", {
    method: "POST",
    headers: authHeaders(),
    body: JSON.stringify({
      username: username.trim(),
      challengeToken,
    }),
  })
}

/** The contact channel an ownership verification targets. */
export type OwnershipTarget = { email: string } | { phone: string }

function ownershipBody(target: OwnershipTarget): Record<string, string> {
  return "email" in target
    ? { email: target.email.trim() }
    : { phone: target.phone.trim() }
}

export async function requestOwnershipCode(
  target: OwnershipTarget,
): Promise<string> {
  const data = await apiJson<{ token: string }>("/v2/auth/verify", {
    method: "POST",
    body: JSON.stringify(ownershipBody(target)),
  })
  if (!data.token) {
    throw new Error("verification could not be started")
  }
  return data.token
}

export async function confirmOwnershipCode(
  target: OwnershipTarget,
  ownershipToken: string,
  response: string,
): Promise<string> {
  const data = await apiJson<{ token: string }>("/v2/auth/verify", {
    method: "POST",
    body: JSON.stringify({
      ...ownershipBody(target),
      ownershipToken,
      response: response.trim(),
    }),
  })
  if (!data.token) {
    throw new Error("verification failed")
  }
  return data.token
}

export async function resetPassword(
  username: string,
  ownershipToken: string,
  password: string,
): Promise<void> {
  await apiJson<unknown>("/v2/auth/iforgot", {
    method: "POST",
    body: JSON.stringify({
      username: username.trim(),
      ownership_token: ownershipToken,
      password,
    }),
  })
}
