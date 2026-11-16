import { useEffect, useState } from "react"

import { AuthAlert, PendingButton } from "@/components/auth-ui"
import { AuthCard } from "@/components/auth-card"
import { FrontchannelLogout } from "@/components/frontchannel-logout"
import { Button } from "@/components/ui/button"
import { ApiError } from "@/lib/api"
import { getApplication } from "@/lib/applications"
import { confirmEndSession, type EndSessionResult } from "@/lib/oauth2"
import { httpUrl } from "@/lib/utils"

type EndSessionViewProps = {
  instanceName: string
  /** Called after signing out when the application gave nowhere to return to. */
  onSignedOut: () => void
  onCancel: () => void
}

/**
 * Asks the user to confirm a logout an application requested (OpenID Connect
 * RP-Initiated Logout), then sends the browser back to the application.
 */
export function EndSessionView({ instanceName, onSignedOut, onCancel }: EndSessionViewProps) {
  const [appName, setAppName] = useState<string | null>(null)
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<EndSessionResult | null>(null)

  const params = new URLSearchParams(window.location.search)
  const clientId = params.get("client_id")

  useEffect(() => {
    if (!clientId) return
    getApplication(clientId)
      .then((app) => setAppName(app.name))
      .catch(() => {
        // The name is only for the prompt.
      })
  }, [clientId])

  async function onConfirm() {
    setPending(true)
    setError(null)
    try {
      setResult(await confirmEndSession(params))
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not sign out")
      setPending(false)
    }
  }

  function leave() {
    const target = result?.redirectUri ? httpUrl(result.redirectUri) : null
    if (target) window.location.href = target.toString()
    else onSignedOut()
  }

  return (
    <AuthCard
      instanceName={instanceName}
      title="Sign out"
      description={
        appName
          ? `${appName} asks to sign you out of ${instanceName}.`
          : `Sign out of ${instanceName}?`
      }
    >
      {error ? <AuthAlert message={error} /> : null}
      {result ? (
        <>
          <p className="text-sm text-muted-foreground">Signing you out…</p>
          <FrontchannelLogout uris={result.frontchannelLogoutUris} onDone={leave} />
        </>
      ) : (
        <div className="flex flex-col gap-2">
          <PendingButton pending={pending} type="button" className="w-full" onClick={() => void onConfirm()}>
            Sign out
          </PendingButton>
          <Button type="button" variant="ghost" className="w-full" disabled={pending} onClick={onCancel}>
            Stay signed in
          </Button>
        </div>
      )}
    </AuthCard>
  )
}
