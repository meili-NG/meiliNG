import { apiJson } from "@/lib/api"

export type SignUpConfig = {
  allowSignup: boolean
  emailRequired: boolean
  emailVerificationRequired: boolean
  usernameRequired: boolean
  phoneRequired: boolean
  phoneVerificationRequired: boolean
}

export async function getSignUpConfig(): Promise<SignUpConfig> {
  return apiJson<SignUpConfig>("/v2/auth/signup")
}

export async function signUp(payload: {
  username?: string
  password: string
  email?: string
  phone?: string
  name?: string
  ownershipToken?: string
}): Promise<void> {
  await apiJson<unknown>("/v2/auth/signup", {
    method: "POST",
    body: JSON.stringify(payload),
  })
}
