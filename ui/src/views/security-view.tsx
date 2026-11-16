import { useEffect, useState, type FormEvent } from "react"
import { startRegistration } from "@simplewebauthn/browser"
import { PlusIcon } from "lucide-react"
import QRCode from "qrcode"

import { SettingsRow, SettingsSection } from "@/components/dashboard-shell"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import {
  Field,
  FieldError,
  FieldGroup,
  FieldLabel,
} from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { ApiError } from "@/lib/api"
import {
  beginAddTOTP,
  beginAddWebAuthn,
  changePassword,
  confirmAddTOTP,
  confirmAddWebAuthn,
  getBackupCodes,
  getTOTPs,
  getUser,
  getWebAuthnKeys,
  regenerateBackupCodes,
  removeTOTP,
  removeWebAuthnKey,
  updateTwoFactorEnabled,
  type TOTPEntry,
  type WebAuthnEntry,
} from "@/lib/users"

type SecurityViewProps = {
  userId: string
}

function totpSecretFromUrl(url: string): string | null {
  try {
    return new URL(url).searchParams.get("secret")
  } catch {
    return null
  }
}

export function SecurityView({ userId }: SecurityViewProps) {
  const [prevPassword, setPrevPassword] = useState("")
  const [newPassword, setNewPassword] = useState("")
  const [error, setError] = useState<string | null>(null)
  const [pending, setPending] = useState(false)
  const [passwordDone, setPasswordDone] = useState(false)

  const [twoFactorEnabled, setTwoFactorEnabled] = useState(false)
  const [totps, setTotps] = useState<TOTPEntry[]>([])
  const [webauthnKeys, setWebauthnKeys] = useState<WebAuthnEntry[]>([])
  const [backupRemaining, setBackupRemaining] = useState<number | null>(null)
  const [backupCodes, setBackupCodes] = useState<string[] | null>(null)

  const [totpOpen, setTotpOpen] = useState(false)
  const [totpToken, setTotpToken] = useState("")
  const [totpUrl, setTotpUrl] = useState("")
  const [totpQr, setTotpQr] = useState<string | null>(null)
  const [totpNote, setTotpNote] = useState("")
  const [totpChallenge, setTotpChallenge] = useState("")
  const [totpError, setTotpError] = useState<string | null>(null)
  const [totpPending, setTotpPending] = useState(false)

  const [passkeyOpen, setPasskeyOpen] = useState(false)
  const [passkeyNote, setPasskeyNote] = useState("")
  const [passkeyError, setPasskeyError] = useState<string | null>(null)
  const [passkeyPending, setPasskeyPending] = useState(false)

  const [backupOpen, setBackupOpen] = useState(false)
  const [backupError, setBackupError] = useState<string | null>(null)
  const [backupPending, setBackupPending] = useState(false)

  const [twoFactorPending, setTwoFactorPending] = useState(false)

  const hasTwoFactorMethod = totps.length > 0 || webauthnKeys.length > 0

  async function refreshMethods() {
    const [user, nextTotps, nextKeys, backup] = await Promise.all([
      getUser(userId),
      getTOTPs(userId),
      getWebAuthnKeys(userId),
      getBackupCodes(userId).catch(() => null),
    ])
    setTwoFactorEnabled(user.twoFactorEnabled)
    setTotps(nextTotps)
    setWebauthnKeys(nextKeys)
    if (backup) setBackupRemaining(backup.remaining)
  }

  useEffect(() => {
    refreshMethods().catch(() => {})
  }, [userId])

  async function onChangePassword(event: FormEvent) {
    event.preventDefault()
    setError(null)
    setPending(true)
    try {
      await changePassword(userId, prevPassword, newPassword)
      setPrevPassword("")
      setNewPassword("")
      setPasswordDone(true)
    } catch (err) {
      setError(
        err instanceof ApiError ? err.message : "Failed to change password",
      )
    } finally {
      setPending(false)
    }
  }

  async function onToggleTwoFactor() {
    setTwoFactorPending(true)
    setError(null)
    try {
      await updateTwoFactorEnabled(userId, !twoFactorEnabled)
      setTwoFactorEnabled(!twoFactorEnabled)
      if (twoFactorEnabled) {
        setBackupRemaining(null)
        setBackupCodes(null)
      }
    } catch (err) {
      setError(
        err instanceof ApiError
          ? err.message
          : "Failed to update two-factor authentication",
      )
    } finally {
      setTwoFactorPending(false)
    }
  }

  async function onRemoveTOTP(id: string) {
    await removeTOTP(userId, id)
    setTotps((prev) => prev.filter((t) => t.id !== id))
    const user = await getUser(userId).catch(() => null)
    if (user) setTwoFactorEnabled(user.twoFactorEnabled)
  }

  async function onRemoveWebAuthn(id: string) {
    await removeWebAuthnKey(userId, id)
    setWebauthnKeys((prev) => prev.filter((k) => k.id !== id))
    const user = await getUser(userId).catch(() => null)
    if (user) setTwoFactorEnabled(user.twoFactorEnabled)
  }

  async function openTotpDialog() {
    setTotpError(null)
    setTotpNote("")
    setTotpChallenge("")
    setTotpQr(null)
    setTotpUrl("")
    setTotpToken("")
    setTotpOpen(true)
    setTotpPending(true)
    try {
      const started = await beginAddTOTP(userId)
      if (!started.totpUrl || !started.token) {
        throw new Error("Authenticator setup did not return a QR payload")
      }
      setTotpToken(started.token)
      setTotpUrl(started.totpUrl)
      setTotpQr(
        await QRCode.toDataURL(started.totpUrl, { margin: 1, width: 200 }),
      )
    } catch (err) {
      setTotpError(
        err instanceof ApiError
          ? err.message
          : err instanceof Error
            ? err.message
            : "Failed to start authenticator setup",
      )
    } finally {
      setTotpPending(false)
    }
  }

  function closeTotpDialog() {
    setTotpOpen(false)
    setTotpError(null)
    setTotpNote("")
    setTotpChallenge("")
    setTotpQr(null)
    setTotpUrl("")
    setTotpToken("")
  }

  async function onConfirmTotp(event: FormEvent) {
    event.preventDefault()
    setTotpError(null)
    setTotpPending(true)
    try {
      await confirmAddTOTP(userId, {
        token: totpToken,
        challenge: totpChallenge,
        note: totpNote.trim() || undefined,
      })
      closeTotpDialog()
      await refreshMethods()
    } catch (err) {
      setTotpError(
        err instanceof ApiError
          ? err.message
          : "Failed to register authenticator",
      )
    } finally {
      setTotpPending(false)
    }
  }

  async function openPasskeyDialog() {
    setPasskeyNote("")
    setPasskeyError(null)
    setPasskeyOpen(true)
  }

  function closePasskeyDialog() {
    setPasskeyOpen(false)
    setPasskeyNote("")
    setPasskeyError(null)
  }

  async function onRegisterPasskey(event: FormEvent) {
    event.preventDefault()
    setPasskeyError(null)
    setPasskeyPending(true)
    try {
      const started = await beginAddWebAuthn(userId)
      const attestation = await startRegistration({
        // The server returns the creation options as an opaque JSON object;
        // cast through unknown since Record<string, unknown> does not
        // structurally overlap with the SimpleWebAuthn options type.
        optionsJSON: started.response as unknown as Parameters<
          typeof startRegistration
        >[0]["optionsJSON"],
      })
      await confirmAddWebAuthn(userId, {
        token: started.token,
        response: attestation as unknown as Record<string, unknown>,
        note: passkeyNote.trim() || undefined,
      })
      closePasskeyDialog()
      await refreshMethods()
    } catch (err) {
      if (err instanceof Error && err.name === "NotAllowedError") {
        setPasskeyError("Passkey registration was cancelled.")
      } else {
        setPasskeyError(
          err instanceof ApiError
            ? err.message
            : err instanceof Error
              ? err.message
              : "Failed to register passkey",
        )
      }
    } finally {
      setPasskeyPending(false)
    }
  }

  async function onRegenerateBackup() {
    setBackupError(null)
    setBackupPending(true)
    try {
      const data = await regenerateBackupCodes(userId)
      setBackupCodes(data.codes)
      setBackupRemaining(data.remaining)
      setBackupOpen(true)
    } catch (err) {
      setBackupError(
        err instanceof ApiError
          ? err.message
          : "Failed to regenerate backup codes",
      )
      setBackupOpen(true)
    } finally {
      setBackupPending(false)
    }
  }

  const totpSecret = totpSecretFromUrl(totpUrl)

  return (
    <div className="flex flex-col gap-8">
      {error ? (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      ) : null}

      <div className="grid grid-cols-1 gap-8 md:grid-cols-2">
        <SettingsSection title="Password">
          {passwordDone ? (
            <p className="text-sm text-muted-foreground">Password updated.</p>
          ) : (
            <form className="flex flex-col gap-4" onSubmit={onChangePassword}>
              <FieldGroup>
                <Field>
                  <FieldLabel htmlFor="prev-pw">Current password</FieldLabel>
                  <Input
                    id="prev-pw"
                    type="password"
                    autoComplete="current-password"
                    required
                    value={prevPassword}
                    onChange={(e) => setPrevPassword(e.target.value)}
                  />
                </Field>
                <Field data-invalid={error ? true : undefined}>
                  <FieldLabel htmlFor="new-pw">New password</FieldLabel>
                  <Input
                    id="new-pw"
                    type="password"
                    autoComplete="new-password"
                    required
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                  />
                </Field>
              </FieldGroup>
              <Button type="submit" disabled={pending} className="self-start">
                {pending ? "Saving…" : "Update password"}
              </Button>
            </form>
          )}
        </SettingsSection>

        <SettingsSection
          title="Two-factor authentication"
          description="Extra verification when signing in."
          action={
            <div className="flex items-center gap-2">
              <Badge variant={twoFactorEnabled ? "secondary" : "outline"}>
                {twoFactorEnabled ? "Enabled" : "Disabled"}
              </Badge>
              {hasTwoFactorMethod || twoFactorEnabled ? (
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  disabled={twoFactorPending || (!twoFactorEnabled && !hasTwoFactorMethod)}
                  onClick={onToggleTwoFactor}
                >
                  {twoFactorPending
                    ? "Saving…"
                    : twoFactorEnabled
                      ? "Disable"
                      : "Enable"}
                </Button>
              ) : null}
            </div>
          }
        />
      </div>

      <SettingsSection title="2FA methods">
        <div className="grid grid-cols-1 gap-6 md:grid-cols-3">
          <SettingsRow
            label="Authenticator apps"
            action={
              <Button
                type="button"
                variant="link"
                className="h-auto p-0 text-sm"
                onClick={openTotpDialog}
              >
                <PlusIcon data-icon="inline-start" />
                Register
              </Button>
            }
          >
            {totps.length > 0 ? (
              <ul className="flex flex-col gap-2">
                {totps.map((t) => (
                  <li
                    key={t.id}
                    className="flex items-center justify-between gap-2 text-sm"
                  >
                    <span className="min-w-0 truncate">{t.note || t.id}</span>
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      className="h-auto shrink-0 p-0 text-xs text-destructive"
                      onClick={() => onRemoveTOTP(t.id)}
                    >
                      Remove
                    </Button>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-sm text-muted-foreground">None</p>
            )}
          </SettingsRow>

          <SettingsRow
            label="Passkeys"
            action={
              <Button
                type="button"
                variant="link"
                className="h-auto p-0 text-sm"
                onClick={openPasskeyDialog}
              >
                <PlusIcon data-icon="inline-start" />
                Register
              </Button>
            }
          >
            {webauthnKeys.length > 0 ? (
              <ul className="flex flex-col gap-2">
                {webauthnKeys.map((k) => (
                  <li
                    key={k.id}
                    className="flex items-center justify-between gap-2 text-sm"
                  >
                    <span className="min-w-0 truncate">{k.note || k.id}</span>
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      className="h-auto shrink-0 p-0 text-xs text-destructive"
                      onClick={() => onRemoveWebAuthn(k.id)}
                    >
                      Remove
                    </Button>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-sm text-muted-foreground">None</p>
            )}
          </SettingsRow>

          <SettingsRow
            label="Backup codes"
            action={
              <Button
                type="button"
                variant="link"
                className="h-auto p-0 text-sm"
                disabled={backupPending || !hasTwoFactorMethod}
                onClick={onRegenerateBackup}
              >
                Regenerate
              </Button>
            }
          >
            <p className="text-sm text-muted-foreground">
              {backupRemaining !== null
                ? `${backupRemaining} remaining`
                : hasTwoFactorMethod
                  ? "Not generated"
                  : "Register a method first"}
            </p>
          </SettingsRow>
        </div>
      </SettingsSection>

      <Dialog
        open={totpOpen}
        onOpenChange={(open) => {
          if (!open) closeTotpDialog()
        }}
      >
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Register authenticator</DialogTitle>
            <DialogDescription>
              Scan the QR code with your authenticator app, then enter a code.
            </DialogDescription>
          </DialogHeader>
          <form
            id="register-totp"
            className="flex flex-col gap-4"
            onSubmit={onConfirmTotp}
          >
            {totpQr ? (
              <div className="flex flex-col items-center gap-3">
                <img
                  src={totpQr}
                  alt="Authenticator QR code"
                  className="size-[200px] rounded-lg bg-white p-2"
                />
                {totpSecret ? (
                  <p className="max-w-full break-all text-center font-mono text-xs text-muted-foreground">
                    {totpSecret}
                  </p>
                ) : null}
              </div>
            ) : totpPending && !totpError ? (
              <p className="text-sm text-muted-foreground">Preparing…</p>
            ) : null}
            <FieldGroup>
              <Field>
                <FieldLabel htmlFor="totp-note">Label (optional)</FieldLabel>
                <Input
                  id="totp-note"
                  type="text"
                  placeholder="Phone authenticator"
                  value={totpNote}
                  onChange={(e) => setTotpNote(e.target.value)}
                />
              </Field>
              <Field data-invalid={totpError ? true : undefined}>
                <FieldLabel htmlFor="totp-challenge">Authentication code</FieldLabel>
                <Input
                  id="totp-challenge"
                  type="text"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  required
                  pattern="[0-9]{6}"
                  placeholder="123456"
                  value={totpChallenge}
                  onChange={(e) => setTotpChallenge(e.target.value)}
                  disabled={!totpToken}
                />
                {totpError ? <FieldError>{totpError}</FieldError> : null}
              </Field>
            </FieldGroup>
          </form>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={closeTotpDialog}>
              Cancel
            </Button>
            <Button
              type="submit"
              form="register-totp"
              disabled={totpPending || !totpToken}
            >
              {totpPending ? "Registering…" : "Register"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog
        open={passkeyOpen}
        onOpenChange={(open) => {
          if (!open) closePasskeyDialog()
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Register passkey</DialogTitle>
            <DialogDescription>
              Use this device’s passkey or security key.
            </DialogDescription>
          </DialogHeader>
          <form
            id="register-passkey"
            className="flex flex-col gap-4"
            onSubmit={onRegisterPasskey}
          >
            <Field>
              <FieldLabel htmlFor="passkey-note">Label (optional)</FieldLabel>
              <Input
                id="passkey-note"
                type="text"
                placeholder="Laptop"
                value={passkeyNote}
                onChange={(e) => setPasskeyNote(e.target.value)}
              />
            </Field>
            {passkeyError ? (
              <Alert variant="destructive">
                <AlertDescription>{passkeyError}</AlertDescription>
              </Alert>
            ) : null}
          </form>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={closePasskeyDialog}>
              Cancel
            </Button>
            <Button
              type="submit"
              form="register-passkey"
              disabled={passkeyPending}
            >
              {passkeyPending ? "Waiting…" : "Continue"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog
        open={backupOpen}
        onOpenChange={(open) => {
          setBackupOpen(open)
          if (!open) setBackupError(null)
        }}
      >
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Backup codes</DialogTitle>
            <DialogDescription>
              Store these somewhere safe. Each code works once.
            </DialogDescription>
          </DialogHeader>
          {backupError ? (
            <Alert variant="destructive">
              <AlertDescription>{backupError}</AlertDescription>
            </Alert>
          ) : backupCodes ? (
            <pre className="rounded-lg bg-muted p-4 font-mono text-sm">
              {backupCodes.join("\n")}
            </pre>
          ) : null}
          <DialogFooter showCloseButton />
        </DialogContent>
      </Dialog>
    </div>
  )
}
