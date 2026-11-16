import { apiJson } from "@/lib/api"

/**
 * Exchange OAuth2 client credentials for an M2M access token.
 *
 * The instance must be configured with admin.adminTokenAudience and an admin
 * must have assigned that audience to the client for the token to be accepted as admin.
 */
export async function exchangeClientCredentials(input: {
  clientId: string
  clientSecret: string
  audience: string
  scope?: string
}): Promise<string> {
  const data = await apiJson<{ access_token: string }>("/v2/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "client_credentials",
      client_id: input.clientId,
      client_secret: input.clientSecret,
      audience: input.audience,
      ...(input.scope ? { scope: input.scope } : {}),
    }).toString(),
  })
  if (!data.access_token) {
    throw new Error("Token endpoint did not return an access_token")
  }
  return data.access_token
}
