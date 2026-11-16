import { useEffect, useState, type FormEvent } from "react"
import { EyeIcon, EyeOffIcon, PencilIcon } from "lucide-react"

import { AuthAlert, PendingButton } from "@/components/auth-ui"
import { AuthCard } from "@/components/auth-card"
import { Button } from "@/components/ui/button"
import {
  Field,
  FieldGroup,
  FieldLabel,
} from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import {
  InputGroup,
  InputGroupAddon,
  InputGroupButton,
  InputGroupInput,
} from "@/components/ui/input-group"
import { ApiError } from "@/lib/api"
import { useBranding, type SignInOptions } from "@/lib/branding"
import {
  beginSignIn,
  completePasswordChallenge,
  finalizeSignIn,
  issueChallenge,
  validateChallenge,
} from "@/lib/auth"

type SignInViewProps = {
  instanceName: string
  onForgotPassword: () => void
  onSignUp?: () => void
  onSignedIn?: () => void
  prefillEmail?: string
}

type Step = "identifier" | "password" | "2fa"

function AccountChip({
  username,
  onEdit,
  disabled,
}: {
  username: string
  onEdit: () => void
  disabled?: boolean
}) {
  return (
    <div className="flex items-center justify-between gap-2 rounded-lg border border-border bg-muted/40 px-3 py-2">
      <span className="min-w-0 truncate text-sm font-medium">{username}</span>
      <Button
        type="button"
        variant="ghost"
        size="icon-sm"
        className="shrink-0"
        disabled={disabled}
        aria-label="Change account"
        onClick={onEdit}
      >
        <PencilIcon />
      </Button>
    </div>
  )
}

export function SignInView({
  instanceName,
  onForgotPassword,
  onSignUp,
  onSignedIn,
  prefillEmail,
}: SignInViewProps) {
  const [step, setStep] = useState<Step>(
    prefillEmail ? "password" : "identifier",
  )
  const { signIn } = useBranding()
  const [username, setUsername] = useState(prefillEmail ?? "")
  const [password, setPassword] = useState("")
  const [showPassword, setShowPassword] = useState(false)
  const [totpCode, setTotpCode] = useState("")
  const [challengeToken, setChallengeToken] = useState("")
  const [twoFaMode, setTwoFaMode] = useState<"totp" | "backup_code">("totp")
  const [error, setError] = useState<string | null>(null)
  const [pending, setPending] = useState(false)

  useEffect(() => {
    if (prefillEmail) {
      setUsername(prefillEmail)
      setStep("password")
    }
  }, [prefillEmail])

  function goToIdentifier() {
    setStep("identifier")
    setPassword("")
    setTotpCode("")
    setChallengeToken("")
    setError(null)
    setShowPassword(false)
  }

  async function onIdentifierSubmit(event: FormEvent) {
    event.preventDefault()
    setError(null)
    setPending(true)
    try {
      const token = await beginSignIn(username)
      setChallengeToken(token)
      setPassword("")
      setStep("password")
    } catch (err) {
      setError(
        err instanceof ApiError ? err.message : "Could not continue with that account",
      )
    } finally {
      setPending(false)
    }
  }

  async function onPasswordSubmit(event: FormEvent) {
    event.preventDefault()
    setError(null)
    setPending(true)
    try {
      let token = challengeToken
      if (!token) {
        token = await beginSignIn(username)
        setChallengeToken(token)
      }
      await completePasswordChallenge(token, password)
      await finalizeSignIn(username, token)
      onSignedIn?.()
    } catch (err) {
      if (err instanceof ApiError && err.type === "two_factor_required") {
        setStep("2fa")
        setError(null)
      } else {
        setError(err instanceof ApiError ? err.message : "Sign-in failed")
      }
    } finally {
      setPending(false)
    }
  }

  async function onTwoFaSubmit(event: FormEvent) {
    event.preventDefault()
    setError(null)
    setPending(true)
    try {
      await issueChallenge(challengeToken, twoFaMode)
      const passed = await validateChallenge(
        challengeToken,
        twoFaMode,
        totpCode,
      )
      if (!passed) {
        setError("Invalid code")
        return
      }
      await finalizeSignIn(username, challengeToken)
      onSignedIn?.()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Verification failed")
    } finally {
      setPending(false)
    }
  }

  if (step === "identifier") {
    return (
      <AuthCard
        instanceName={instanceName}
        title="Sign in"
        description={`Continue to ${instanceName}.`}
        footer={
          onSignUp ? (
            <>
              Need an account?{" "}
              <Button
                type="button"
                variant="link"
                className="h-auto p-0"
                onClick={onSignUp}
              >
                Sign up
              </Button>
            </>
          ) : null
        }
      >
        <form className="flex flex-col gap-4" onSubmit={onIdentifierSubmit}>
          {error ? <AuthAlert message={error} /> : null}
          <FieldGroup>
            <Field>
              <FieldLabel htmlFor="username">{identifierLabel(signIn)}</FieldLabel>
              <Input
                id="username"
                type="text"
                autoComplete="username"
                autoFocus
                required
                value={username}
                onChange={(e) => {
                  setUsername(e.target.value)
                  setError(null)
                }}
              />
            </Field>
          </FieldGroup>
          <PendingButton
            type="submit"
            className="w-full"
            pending={pending}
            pendingLabel="Checking…"
          >
            Next
          </PendingButton>
        </form>
      </AuthCard>
    )
  }

  if (step === "password") {
    return (
      <AuthCard
        instanceName={instanceName}
        title="Enter password"
        description={`Welcome back to ${instanceName}.`}
      >
        <form className="flex flex-col gap-4" onSubmit={onPasswordSubmit}>
          {error ? <AuthAlert message={error} /> : null}
          <AccountChip
            username={username}
            disabled={pending}
            onEdit={goToIdentifier}
          />
          <FieldGroup>
            <Field>
              <div className="flex items-center">
                <FieldLabel htmlFor="password">Password</FieldLabel>
                <Button
                  type="button"
                  variant="link"
                  className="ml-auto h-auto p-0 text-sm"
                  onClick={onForgotPassword}
                >
                  Forgot password?
                </Button>
              </div>
              <InputGroup>
                <InputGroupInput
                  id="password"
                  type={showPassword ? "text" : "password"}
                  autoComplete="current-password"
                  autoFocus
                  required
                  value={password}
                  onChange={(e) => {
                    setPassword(e.target.value)
                    setError(null)
                  }}
                />
                <InputGroupAddon align="inline-end">
                  <InputGroupButton
                    type="button"
                    size="icon-xs"
                    aria-label={
                      showPassword ? "Hide password" : "Show password"
                    }
                    onClick={() => setShowPassword((v) => !v)}
                  >
                    {showPassword ? <EyeOffIcon /> : <EyeIcon />}
                  </InputGroupButton>
                </InputGroupAddon>
              </InputGroup>
            </Field>
          </FieldGroup>
          <PendingButton
            type="submit"
            className="w-full"
            pending={pending}
            pendingLabel="Signing in…"
          >
            Sign in
          </PendingButton>
        </form>
      </AuthCard>
    )
  }

  return (
    <AuthCard
      instanceName={instanceName}
      title="Two-factor authentication"
      description="Enter a verification code to finish signing in."
      footer={
        <Button
          type="button"
          variant="link"
          className="h-auto p-0"
          onClick={() =>
            setTwoFaMode((m) => (m === "totp" ? "backup_code" : "totp"))
          }
        >
          {twoFaMode === "totp" ? "Use backup code" : "Use authenticator"}
        </Button>
      }
    >
      <form className="flex flex-col gap-4" onSubmit={onTwoFaSubmit}>
        {error ? <AuthAlert message={error} /> : null}
        <AccountChip
          username={username}
          disabled={pending}
          onEdit={goToIdentifier}
        />
        <FieldGroup>
          <Field>
            <FieldLabel htmlFor="totp">
              {twoFaMode === "totp" ? "Authenticator code" : "Backup code"}
            </FieldLabel>
            <Input
              id="totp"
              type="text"
              inputMode={twoFaMode === "totp" ? "numeric" : "text"}
              autoComplete="one-time-code"
              autoFocus
              required
              value={totpCode}
              onChange={(e) => {
                setTotpCode(e.target.value)
                setError(null)
              }}
            />
          </Field>
        </FieldGroup>
        <PendingButton
          type="submit"
          className="w-full"
          pending={pending}
          pendingLabel="Verifying…"
        >
          Verify
        </PendingButton>
      </form>
    </AuthCard>
  )
}

/** The identifier field label for what auth.signin accepts. */
function identifierLabel({ username, email }: SignInOptions): string {
  if (email && !username) return "Email"
  if (username && !email) return "Username"
  return "Email or username"
}
