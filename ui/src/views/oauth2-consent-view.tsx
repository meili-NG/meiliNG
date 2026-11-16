import { useEffect, useState } from "react"
import { BadgeCheckIcon, CheckIcon, ExternalLinkIcon } from "lucide-react"

import { AuthAlert, PendingButton } from "@/components/auth-ui"
import { AuthCard } from "@/components/auth-card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Spinner } from "@/components/ui/spinner"
import { ApiError } from "@/lib/api"
import { getApplication, type Application } from "@/lib/applications"
import { authorizeClient, getAuthConsent, OOB_REDIRECT_URIS } from "@/lib/oauth2"
import { httpUrl } from "@/lib/utils"

type OAuth2ConsentViewProps = {
  instanceName: string
  userId: string
  /** The display label of the signed-in account the app will act for. */
  accountLabel?: string
  onNav: (screen: string) => void
}

const SCOPE_LABELS: Record<string, string> = {
  openid: "Verify your identity",
  profile: "View your profile information",
  email: "View your email address",
  phone: "View your phone number",
  address: "View your address",
  offline_access: "Stay connected when you are not using it",
}

/** Marks a sign-in the consent screen asked for, so a second ask in a row,
 * which signing in again cannot satisfy, goes back to the app instead. */
const REAUTH_KEY = "meiling_oauth2_reauth"

function hasPrompt(params: URLSearchParams, value: string): boolean {
  return (params.get("prompt") ?? "").split(/\s+/).includes(value)
}

function initialOf(name: string): string {
  return name.trim().charAt(0).toUpperCase() || "?"
}

export function OAuth2ConsentView({
  instanceName,
  userId,
  accountLabel,
  onNav,
}: OAuth2ConsentViewProps) {
  const [app, setApp] = useState<Application | null>(null)
  const [scopes, setScopes] = useState<string[]>([])
  const [messages, setMessages] = useState<Record<string, string>>({})
  const [error, setError] = useState<string | null>(null)
  const [pending, setPending] = useState(false)
  const [oobCode, setOobCode] = useState<string | null>(null)
  const [rejected, setRejected] = useState<string | null>(null)
  // Unset until the server accepts this request. Then its redirect_uri, which
  // the server matched against the client, or null for one shown in the page.
  const [returnTo, setReturnTo] = useState<URL | null>()

  const params = new URLSearchParams(window.location.search)
  const clientId = params.get("client_id") ?? ""
  const redirectUri = params.get("redirect_uri") ?? ""
  const scope = params.get("scope") ?? ""
  const state = params.get("state") ?? ""

  /** Sends the user to sign in again, then back here; see REAUTH_KEY. */
  function requestSignIn(target: URL | null) {
    const key = `${clientId}:${userId}`
    if (sessionStorage.getItem(REAUTH_KEY) === key) {
      sessionStorage.removeItem(REAUTH_KEY)
      returnError("login_required", target)
      return
    }
    sessionStorage.setItem(REAUTH_KEY, key)
    if (accountLabel) sessionStorage.setItem("meiling_prefill_email", accountLabel)
    onNav("sign-in")
  }

  useEffect(() => {
    if (!clientId) return

    // prompt=login asks for a fresh sign-in once; drop it from the request so
    // the consent screen that follows the sign-in does not ask again.
    if (hasPrompt(params, "login")) {
      const next = new URLSearchParams(params)
      const rest = (next.get("prompt") ?? "")
        .split(/\s+/)
        .filter((p) => p && p !== "login")
      if (rest.length > 0) next.set("prompt", rest.join(" "))
      else next.delete("prompt")
      history.replaceState(null, "", `${window.location.pathname}?${next}`)
      if (accountLabel) sessionStorage.setItem("meiling_prefill_email", accountLabel)
      onNav("sign-in")
      return
    }

    setScopes(scope ? scope.split(" ").filter(Boolean) : [])

    getApplication(clientId)
      .then(setApp)
      .catch((err) =>
        setError(err instanceof ApiError ? err.message : "Invalid application"),
      )

    getAuthConsent(clientId, params, userId)
      .then((info) => {
        const target = httpUrl(redirectUri)
        if (!target && !OOB_REDIRECT_URIS.includes(redirectUri)) {
          setRejected("redirect_uri is invalid")
          return
        }
        setReturnTo(target)

        if (info.reauthenticationRequired) {
          if (hasPrompt(params, "none")) returnError("login_required", target)
          else requestSignIn(target)
          return
        }
        sessionStorage.removeItem(REAUTH_KEY)

        if (!info.userConsentRequired) {
          void authorize(false, target)
          return
        }
        if (hasPrompt(params, "none")) {
          returnError("consent_required", target)
          return
        }
        if (info.permissions) {
          setScopes(info.permissions.map((p) => p.scope))
          setMessages(
            Object.fromEntries(
              info.permissions.map((p) => [p.scope, p.message ?? ""]),
            ),
          )
        }
      })
      .catch((err) =>
        setRejected(
          err instanceof ApiError ? err.message : "Authorization request failed",
        ),
      )
  }, [clientId])

  /** Sends the browser to the redirect_uri the server accepted. */
  function sendBack(target: URL, response: Record<string, string | undefined>) {
    const url = new URL(target)
    for (const [name, value] of Object.entries({ ...response, state })) {
      if (value) url.searchParams.set(name, value)
    }
    window.location.href = url.toString()
  }

  /** `approve` is set only by the Approve button, never by the automatic path. */
  async function authorize(approve: boolean, target: URL | null) {
    setPending(true)
    try {
      const result = await authorizeClient(clientId, params, userId, approve)

      if (!target) {
        setError(null)
        setOobCode(result.code ?? "")
        return
      }

      sendBack(target, { code: result.code })
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Authorization failed")
    } finally {
      setPending(false)
    }
  }

  function returnError(code: string, target: URL | null) {
    if (target) {
      sendBack(target, { error: code })
    } else {
      onNav("account")
    }
  }

  const failure = clientId
    ? (rejected ?? (app ? null : error))
    : "client_id is required"
  if (failure) {
    return (
      <AuthCard
        instanceName={instanceName}
        title="Authorization error"
        description={failure}
      >
        <Button type="button" className="w-full" onClick={() => onNav("account")}>
          Go home
        </Button>
      </AuthCard>
    )
  }

  if (!app || returnTo === undefined) {
    return (
      <AuthCard
        instanceName={instanceName}
        title="Authorize"
        description="Loading application…"
      >
        <div className="flex justify-center">
          <Spinner />
        </div>
      </AuthCard>
    )
  }

  const iconUrl = httpUrl(app.iconUrl)?.href
  const privacy = httpUrl(app.privacy)?.href
  const terms = httpUrl(app.terms)?.href

  return (
    <AuthCard
      instanceName={instanceName}
      title={app.name}
      description={`wants to access your ${instanceName} account`}
      media={
        <>
          {iconUrl ? (
            <img
              src={iconUrl}
              alt=""
              className="size-14 rounded-2xl border object-cover"
            />
          ) : (
            <div className="flex size-14 items-center justify-center rounded-2xl border bg-muted text-xl font-semibold">
              {initialOf(app.name)}
            </div>
          )}
          {app.isVerified ? (
            <Badge variant="secondary">
              <BadgeCheckIcon data-icon="inline-start" />
              Verified application
            </Badge>
          ) : null}
        </>
      }
      footer={
        oobCode ? (
          <Button type="button" variant="link" className="h-auto p-0" onClick={() => onNav("account")}>
            Done
          </Button>
        ) : privacy || terms ? (
          <span className="inline-flex flex-wrap items-center justify-center gap-x-4 gap-y-1">
            {privacy ? (
              <a
                href={privacy}
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-1 underline-offset-4 hover:text-foreground hover:underline"
              >
                Privacy policy
                <ExternalLinkIcon className="size-3" />
              </a>
            ) : null}
            {terms ? (
              <a
                href={terms}
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-1 underline-offset-4 hover:text-foreground hover:underline"
              >
                Terms of service
                <ExternalLinkIcon className="size-3" />
              </a>
            ) : null}
          </span>
        ) : null
      }
    >
      <div className="flex flex-col gap-5">
        {accountLabel ? (
          <div className="flex items-center justify-between gap-3 rounded-lg border bg-muted/40 px-3 py-2 text-sm">
            <span className="text-muted-foreground">Signed in as</span>
            <span className="min-w-0 truncate font-medium">{accountLabel}</span>
          </div>
        ) : null}

        {scopes.length > 0 ? (
          <div className="flex flex-col gap-2">
            <p className="text-sm font-medium">This will allow {app.name} to:</p>
            <ul className="flex flex-col gap-2.5 text-sm">
              {scopes.map((s) => (
                <li key={s} className="flex items-start gap-2.5">
                  <CheckIcon className="mt-0.5 size-4 shrink-0 text-muted-foreground" />
                  <span>{SCOPE_LABELS[s] ?? (messages[s] || s)}</span>
                </li>
              ))}
            </ul>
          </div>
        ) : null}

        {error ? <AuthAlert message={error} /> : null}

        {oobCode ? (
          <code className="break-all rounded-lg bg-muted p-3 font-mono text-sm">
            {oobCode}
          </code>
        ) : (
          <div className="flex flex-col gap-3">
            <div className="flex flex-col-reverse gap-2 sm:flex-row">
              <Button
                type="button"
                variant="outline"
                className="sm:flex-1"
                onClick={() => returnError("access_denied", returnTo)}
                disabled={pending}
              >
                Deny
              </Button>
              <PendingButton
                type="button"
                className="sm:flex-1"
                pending={pending}
                pendingLabel="Authorizing…"
                onClick={() => authorize(true, returnTo)}
              >
                Approve
              </PendingButton>
            </div>
            {returnTo ? (
              <p className="text-center text-xs text-muted-foreground">
                Approving will send you to{" "}
                <span className="font-medium text-foreground">
                  {returnTo.host}
                </span>
              </p>
            ) : null}
          </div>
        )}
      </div>
    </AuthCard>
  )
}
