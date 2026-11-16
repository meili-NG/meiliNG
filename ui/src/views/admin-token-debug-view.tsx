import { useState, type FormEvent } from "react"

import { AdminPageHeader, AdminSection } from "@/components/admin-panel"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import {
  Field,
  FieldGroup,
  FieldLabel,
} from "@/components/ui/field"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Textarea } from "@/components/ui/textarea"
import { JsonEditor } from "@/components/ui/json-editor"
import { ApiError } from "@/lib/api"
import {
  debugSession,
  getTokenInfo,
  revokeToken,
  type TokenInfo,
} from "@/lib/admin"

type Hint = "access_token" | "refresh_token" | "id_token"

export function AdminTokenDebugView() {
  const [token, setToken] = useState("")
  const [hint, setHint] = useState<Hint>("access_token")
  const [info, setInfo] = useState<TokenInfo | null>(null)
  const [sessionDebug, setSessionDebug] = useState<unknown>(null)
  const [error, setError] = useState<string | null>(null)
  const [message, setMessage] = useState<string | null>(null)
  const [pending, setPending] = useState(false)

  async function onInspect(event: FormEvent) {
    event.preventDefault()
    setPending(true)
    setError(null)
    setMessage(null)
    setInfo(null)
    setSessionDebug(null)
    const value = token.trim()
    if (!value) {
      setError("Paste a token first")
      setPending(false)
      return
    }
    try {
      const selected = hint
      const body =
        selected === "refresh_token"
          ? { refreshToken: value }
          : selected === "id_token"
            ? { idToken: value }
            : { accessToken: value }
      const result = await getTokenInfo(body)
      setInfo(result)
    } catch (err) {
      setError(
        err instanceof ApiError ? err.message : "Token info request failed",
      )
    } finally {
      setPending(false)
    }
  }

  async function onSessionDebug() {
    setPending(true)
    setError(null)
    setMessage(null)
    setSessionDebug(null)
    try {
      const result = await debugSession(token.trim())
      setSessionDebug(result)
    } catch (err) {
      setError(
        err instanceof ApiError ? err.message : "Session debug failed",
      )
    } finally {
      setPending(false)
    }
  }

  async function onRevoke() {
    setPending(true)
    setError(null)
    setMessage(null)
    try {
      await revokeToken({
        token: token.trim(),
        tokenTypeHint: hint === "id_token" ? "access_token" : hint,
      })
      setMessage("Token revoked")
      setInfo(null)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Revoke failed")
    } finally {
      setPending(false)
    }
  }

  return (
    <div className="flex flex-col gap-6">
      <AdminPageHeader
        title="Token debug"
        description="Inspect or revoke OAuth tokens, or decode a session."
      />
      <AdminSection>
        <form className="flex flex-col gap-4" onSubmit={onInspect}>
          <FieldGroup>
            <Field>
              <FieldLabel htmlFor="token-debug-value">Token</FieldLabel>
              <Textarea
                id="token-debug-value"
                rows={5}
                className="font-mono text-xs"
                placeholder="Paste access, refresh, ID, or session token"
                value={token}
                onChange={(e) => setToken(e.target.value)}
              />
            </Field>
            <Field>
              <FieldLabel>Type hint</FieldLabel>
              <Select
                value={hint}
                onValueChange={(value) => setHint(value as Hint)}
              >
                <SelectTrigger className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="access_token">Access token</SelectItem>
                  <SelectItem value="refresh_token">Refresh token</SelectItem>
                  <SelectItem value="id_token">ID token</SelectItem>
                </SelectContent>
              </Select>
            </Field>
          </FieldGroup>

          {error ? (
            <Alert variant="destructive">
              <AlertTitle>Error</AlertTitle>
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          ) : null}
          {message ? (
            <Alert>
              <AlertDescription>{message}</AlertDescription>
            </Alert>
          ) : null}

          <div className="flex flex-wrap gap-2">
            <Button type="submit" disabled={pending}>
              {pending ? "Working…" : "Token info"}
            </Button>
            <Button
              type="button"
              variant="outline"
              disabled={pending || !token.trim()}
              onClick={() => void onSessionDebug()}
            >
              Session debug
            </Button>
            <Button
              type="button"
              variant="destructive"
              disabled={pending || !token.trim()}
              onClick={() => void onRevoke()}
            >
              Revoke
            </Button>
          </div>
        </form>
      </AdminSection>

      {info ? (
        <AdminSection title="Token info">
          <JsonEditor
            readOnly
            value={JSON.stringify(info, null, 2)}
            height={280}
            aria-label="Token info JSON"
          />
        </AdminSection>
      ) : null}

      {sessionDebug ? (
        <AdminSection title="Session debug">
          <JsonEditor
            readOnly
            value={JSON.stringify(sessionDebug, null, 2)}
            height={280}
            aria-label="Session debug JSON"
          />
        </AdminSection>
      ) : null}
    </div>
  )
}
