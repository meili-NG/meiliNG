import { useEffect, useState, type FormEvent } from "react"

import { AuthAlert, PendingButton } from "@/components/auth-ui"
import { AuthCard } from "@/components/auth-card"
import {
  Field,
  FieldDescription,
  FieldGroup,
  FieldLabel,
} from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Textarea } from "@/components/ui/textarea"
import { ApiError } from "@/lib/api"
import { verifyAdminAuth } from "@/lib/admin"
import { exchangeClientCredentials } from "@/lib/admin-crypto"
import {
  DEFAULT_ADMIN_TOKEN_METHOD,
  setAdminBearerToken,
  setAdminToken,
} from "@/lib/admin-session"
import { accountUiPath } from "@/lib/paths"

type AdminGateViewProps = {
  instanceName: string
  onAuthed: () => void
}

export function AdminGateView({ instanceName, onAuthed }: AdminGateViewProps) {
  const [method, setMethod] = useState("token")
  const [error, setError] = useState<string | null>(null)
  const [errorVariant, setErrorVariant] = useState<"destructive" | "warning">(
    "destructive",
  )
  const [pending, setPending] = useState(false)
  // When a fragment carries autosubmit=true, this holds the tab to submit once
  // its fields have been prefilled. Consumed exactly once.
  const [autoSubmit, setAutoSubmit] = useState<string | null>(null)

  // Admin token
  const [adminToken, setAdminTokenValue] = useState("")
  const [customHeader, setCustomHeader] = useState(false)
  const [tokenMethod, setTokenMethod] = useState(DEFAULT_ADMIN_TOKEN_METHOD)

  // M2M client credentials
  const [clientId, setClientId] = useState("")
  const [clientSecret, setClientSecret] = useState("")
  const [audience, setAudience] = useState("")

  // Raw JWT paste
  const [jwt, setJwt] = useState("")

  // Prefill from a URL fragment: #token=…, #clientId=…&clientSecret=…, etc.
  // Consumed once and cleared so credentials don't linger in the address bar.
  useEffect(() => {
    const hash = window.location.hash.replace(/^#/, "")
    if (!hash) return
    const params = new URLSearchParams(hash)
    let target: string | null = null

    const token = params.get("token")
    if (token !== null) {
      setAdminTokenValue(token)
      target = "token"
    }
    const header = params.get("header")
    if (header !== null) {
      setCustomHeader(true)
      setTokenMethod(header)
      target ??= "token"
    }

    const cid = params.get("clientId")
    const csecret = params.get("clientSecret")
    const aud = params.get("audience")
    if (cid !== null) setClientId(cid)
    if (csecret !== null) setClientSecret(csecret)
    if (aud !== null) setAudience(aud)
    if (cid !== null || csecret !== null) target = "m2m"

    const rawJwt = params.get("jwt")
    if (rawJwt !== null) {
      setJwt(rawJwt)
      target = "jwt"
    }

    const tab = params.get("tab")
    if (tab && ["token", "m2m", "jwt"].includes(tab)) target = tab

    if (target) setMethod(target)

    // A one-click link can request auto-submission once fields are prefilled.
    const auto = params.get("autosubmit")
    const wantsAuto = auto === "" || auto === "true" || auto === "1"
    if (wantsAuto && target) setAutoSubmit(target)

    // Strip the fragment without adding a history entry.
    history.replaceState(
      null,
      "",
      window.location.pathname + window.location.search,
    )
  }, [])

  async function finishIfAdmin() {
    const ok = await verifyAdminAuth()
    if (!ok) {
      // Not a hard failure: the credentials were valid, they just aren't an
      // admin. Flagged as "not_admin" so the gate can show it as a warning.
      throw new ApiError(
        "Credentials accepted, but they don't have admin access.",
        "not_admin",
      )
    }
    onAuthed()
  }

  async function submit(fn: () => Promise<void>, fallback: string) {
    setError(null)
    setErrorVariant("destructive")
    setPending(true)
    try {
      await fn()
    } catch (err) {
      const notAdmin = err instanceof ApiError && err.type === "not_admin"
      setErrorVariant(notAdmin ? "warning" : "destructive")
      setError(
        err instanceof ApiError
          ? err.message
          : ((err as Error)?.message ?? fallback),
      )
    } finally {
      setPending(false)
    }
  }

  function onTokenSubmit(event?: FormEvent) {
    event?.preventDefault()
    void submit(async () => {
      const header =
        customHeader && tokenMethod.trim()
          ? tokenMethod.trim()
          : DEFAULT_ADMIN_TOKEN_METHOD
      setAdminToken(adminToken.trim(), header)
      await finishIfAdmin()
    }, "Invalid admin token")
  }

  function onM2MSubmit(event?: FormEvent) {
    event?.preventDefault()
    void submit(async () => {
      const token = await exchangeClientCredentials({
        clientId: clientId.trim(),
        clientSecret: clientSecret.trim(),
        audience: audience.trim(),
      })
      setAdminBearerToken(token)
      await finishIfAdmin()
    }, "Client credentials exchange failed")
  }

  function onJwtSubmit(event?: FormEvent) {
    event?.preventDefault()
    void submit(async () => {
      setAdminBearerToken(jwt.trim())
      await finishIfAdmin()
    }, "Invalid JWT or not admin")
  }

  // Fire the requested submission once its fields are populated from the
  // fragment. Runs at most once: the flag is cleared as soon as it fires.
  useEffect(() => {
    if (!autoSubmit || pending) return
    const ready =
      (autoSubmit === "token" && adminToken.trim() !== "") ||
      (autoSubmit === "m2m" &&
        clientId.trim() !== "" &&
        clientSecret.trim() !== "") ||
      (autoSubmit === "jwt" && jwt.trim() !== "")
    if (!ready) return

    setAutoSubmit(null)
    if (autoSubmit === "token") onTokenSubmit()
    else if (autoSubmit === "m2m") onM2MSubmit()
    else if (autoSubmit === "jwt") onJwtSubmit()
    // eslint-disable-next-line react-hooks/exhaustive-deps -- rerun only on the flag and the fields it checks
  }, [autoSubmit, pending, adminToken, clientId, clientSecret, jwt])

  return (
    <AuthCard
      instanceName={instanceName}
      title="Admin panel"
      description={`Authenticate to administer ${instanceName}.`}
      className="max-w-md"
      footer={
        <a href={accountUiPath()} className="underline-offset-4 hover:underline">
          Back to account
        </a>
      }
    >
      <Tabs value={method} onValueChange={setMethod}>
        <TabsList className="grid w-full grid-cols-3">
          <TabsTrigger value="token">Token</TabsTrigger>
          <TabsTrigger value="m2m">M2M</TabsTrigger>
          <TabsTrigger value="jwt">JWT</TabsTrigger>
        </TabsList>

        <TabsContent value="token" className="mt-4">
          <form className="flex flex-col gap-4" onSubmit={onTokenSubmit}>
            <FieldGroup>
              <Field>
                <FieldLabel htmlFor="admin-token">Admin token</FieldLabel>
                <Textarea
                  id="admin-token"
                  required
                  rows={3}
                  className="font-mono text-xs"
                  placeholder="admin.adminTokens value"
                  value={adminToken}
                  onChange={(e) => setAdminTokenValue(e.target.value)}
                />
                <FieldDescription>
                  A value from the instance's admin.adminTokens.
                </FieldDescription>
              </Field>
              <Field>
                <label className="flex items-center gap-2 text-sm">
                  <input
                    type="checkbox"
                    checked={customHeader}
                    onChange={(e) => setCustomHeader(e.target.checked)}
                  />
                  Custom admin header
                </label>
              </Field>
              {customHeader ? (
                <Field>
                  <FieldLabel htmlFor="admin-token-method">
                    Header name
                  </FieldLabel>
                  <Input
                    id="admin-token-method"
                    type="text"
                    autoComplete="off"
                    placeholder={DEFAULT_ADMIN_TOKEN_METHOD}
                    value={tokenMethod}
                    onChange={(e) => setTokenMethod(e.target.value)}
                  />
                  <FieldDescription>
                    Matches the instance's admin.adminTokenMethod. Defaults to{" "}
                    {DEFAULT_ADMIN_TOKEN_METHOD}.
                  </FieldDescription>
                </Field>
              ) : null}
            </FieldGroup>
            {error && method === "token" ? (
              <AuthAlert message={error} variant={errorVariant} />
            ) : null}
            <PendingButton pending={pending} type="submit" className="w-full">
              Continue
            </PendingButton>
          </form>
        </TabsContent>

        <TabsContent value="m2m" className="mt-4">
          <form className="flex flex-col gap-4" onSubmit={onM2MSubmit}>
            <FieldGroup>
              <Field>
                <FieldLabel htmlFor="m2m-client-id">Client ID</FieldLabel>
                <Input
                  id="m2m-client-id"
                  required
                  autoComplete="off"
                  value={clientId}
                  onChange={(e) => setClientId(e.target.value)}
                />
              </Field>
              <Field>
                <FieldLabel htmlFor="m2m-client-secret">
                  Client secret
                </FieldLabel>
                <Input
                  id="m2m-client-secret"
                  type="password"
                  required
                  autoComplete="off"
                  value={clientSecret}
                  onChange={(e) => setClientSecret(e.target.value)}
                />
              </Field>
              <Field>
                <FieldLabel htmlFor="m2m-audience">Audience</FieldLabel>
                <Input
                  id="m2m-audience"
                  required
                  placeholder="admin.adminTokenAudience"
                  value={audience}
                  onChange={(e) => setAudience(e.target.value)}
                />
                <FieldDescription>
                  Must match the instance's admin.adminTokenAudience, and an
                  admin must have assigned it to the client.
                </FieldDescription>
              </Field>
            </FieldGroup>
            {error && method === "m2m" ? (
              <AuthAlert message={error} variant={errorVariant} />
            ) : null}
            <PendingButton pending={pending} type="submit" className="w-full">
              Exchange & continue
            </PendingButton>
          </form>
        </TabsContent>

        <TabsContent value="jwt" className="mt-4">
          <form className="flex flex-col gap-4" onSubmit={onJwtSubmit}>
            <FieldGroup>
              <Field>
                <FieldLabel htmlFor="admin-jwt">
                  Admin session or access JWT
                </FieldLabel>
                <Textarea
                  id="admin-jwt"
                  required
                  rows={4}
                  className="font-mono text-xs"
                  placeholder="eyJ…"
                  value={jwt}
                  onChange={(e) => setJwt(e.target.value)}
                />
              </Field>
            </FieldGroup>
            {error && method === "jwt" ? (
              <AuthAlert message={error} variant={errorVariant} />
            ) : null}
            <PendingButton pending={pending} type="submit" className="w-full">
              Continue
            </PendingButton>
          </form>
        </TabsContent>
      </Tabs>
    </AuthCard>
  )
}
