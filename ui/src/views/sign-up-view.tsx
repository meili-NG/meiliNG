import { useEffect, useState, type FormEvent } from "react"

import { AuthAlert, PendingButton } from "@/components/auth-ui"
import { AuthCard } from "@/components/auth-card"
import { Button } from "@/components/ui/button"
import {
  Field,
  FieldDescription,
  FieldGroup,
  FieldLabel,
} from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { ApiError } from "@/lib/api"
import {
  beginSignIn,
  completePasswordChallenge,
  confirmOwnershipCode,
  finalizeSignIn,
  requestOwnershipCode,
  type OwnershipTarget,
} from "@/lib/auth"
import {
  getSignUpConfig,
  signUp,
  type SignUpConfig,
} from "@/lib/signup"

type SignUpViewProps = {
  instanceName: string
  onSignIn: () => void
  /** Called when the new account could not be signed in automatically. */
  onDone: (email?: string) => void
  onSignedIn: () => void
}

export function SignUpView({
  instanceName,
  onSignIn,
  onDone,
  onSignedIn,
}: SignUpViewProps) {
  const [config, setConfig] = useState<SignUpConfig | null>(null)
  const [step, setStep] = useState<"form" | "verify" | "done">("form")

  const [username, setUsername] = useState("")
  const [email, setEmail] = useState("")
  const [phone, setPhone] = useState("")
  const [password, setPassword] = useState("")
  const [name, setName] = useState("")
  const [code, setCode] = useState("")

  const [ownershipToken, setOwnershipToken] = useState("")
  // Which channel the verification step is confirming (email or phone).
  const [verifyTarget, setVerifyTarget] = useState<OwnershipTarget | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [pending, setPending] = useState(false)

  useEffect(() => {
    getSignUpConfig()
      .then(setConfig)
      .catch(() => setConfig(null))
  }, [])

  if (config && !config.allowSignup) {
    return (
      <AuthCard
        instanceName={instanceName}
        title="Sign up unavailable"
        description="This instance is not accepting new accounts."
        footer={
          <>
            Already have an account?{" "}
            <Button
              type="button"
              variant="link"
              className="h-auto p-0"
              onClick={onSignIn}
            >
              Sign in
            </Button>
          </>
        }
      >
        <Button type="button" className="w-full" onClick={onSignIn}>
          Sign in
        </Button>
      </AuthCard>
    )
  }

  async function finishSignUp(token?: string) {
    await signUp({
      username,
      password,
      email,
      phone,
      name,
      ownershipToken: token,
    })
    setStep("done")
    // The password was just typed, so sign in with it rather than asking
    // again. Anything unexpected falls back to the sign-in screen.
    const identifier = email || username
    try {
      const token = await beginSignIn(identifier)
      await completePasswordChallenge(token, password)
      await finalizeSignIn(identifier, token)
    } catch {
      onDone(identifier)
      return
    }
    onSignedIn()
  }

  async function onFormSubmit(event: FormEvent) {
    event.preventDefault()
    setError(null)
    setPending(true)
    try {
      // Start ownership verification for whichever channel the instance
      // requires. Email takes precedence; phone verification is then handled
      // after the email step completes (see onVerifySubmit).
      if (config?.emailVerificationRequired && email) {
        const target: OwnershipTarget = { email }
        const token = await requestOwnershipCode(target)
        setOwnershipToken(token)
        setVerifyTarget(target)
        setStep("verify")
      } else if (config?.phoneVerificationRequired && phone) {
        const target: OwnershipTarget = { phone }
        const token = await requestOwnershipCode(target)
        setOwnershipToken(token)
        setVerifyTarget(target)
        setStep("verify")
      } else {
        await finishSignUp()
      }
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Sign-up failed")
    } finally {
      setPending(false)
    }
  }

  async function onVerifySubmit(event: FormEvent) {
    event.preventDefault()
    if (!verifyTarget) return
    setError(null)
    setPending(true)
    try {
      const token = await confirmOwnershipCode(verifyTarget, ownershipToken, code)
      await finishSignUp(token)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Verification failed")
    } finally {
      setPending(false)
    }
  }

  if (step === "done") {
    return (
      <AuthCard
        instanceName={instanceName}
        title="Account created"
        description="You can now sign in."
      >
        <Button type="button" className="w-full" onClick={onSignIn}>
          Sign in
        </Button>
      </AuthCard>
    )
  }

  if (step === "verify") {
    const verifyingPhone = verifyTarget !== null && "phone" in verifyTarget
    const sentTo = verifyingPhone ? phone : email
    return (
      <AuthCard
        instanceName={instanceName}
        title={verifyingPhone ? "Verify phone" : "Verify email"}
        description={`Enter the code sent to ${sentTo}.`}
        footer={
          <Button
            type="button"
            variant="link"
            className="h-auto p-0"
            disabled={pending}
            onClick={() => {
              setStep("form")
              setCode("")
              setError(null)
            }}
          >
            Back
          </Button>
        }
      >
        <form className="flex flex-col gap-4" onSubmit={onVerifySubmit}>
          {error ? <AuthAlert message={error} /> : null}
          <FieldGroup>
            <Field>
              <FieldLabel htmlFor="verify-code">Verification code</FieldLabel>
              <Input
                id="verify-code"
                type="text"
                inputMode="numeric"
                autoComplete="one-time-code"
                autoFocus
                required
                value={code}
                onChange={(e) => setCode(e.target.value)}
              />
            </Field>
          </FieldGroup>
          <PendingButton
            type="submit"
            className="w-full"
            pending={pending}
            pendingLabel="Verifying…"
          >
            Create account
          </PendingButton>
        </form>
      </AuthCard>
    )
  }

  return (
    <AuthCard
      instanceName={instanceName}
      title="Create account"
      description={`Join ${instanceName}.`}
      footer={
        <>
          Already have an account?{" "}
          <Button
            type="button"
            variant="link"
            className="h-auto p-0"
            onClick={onSignIn}
          >
            Sign in
          </Button>
        </>
      }
    >
      <form className="flex flex-col gap-4" onSubmit={onFormSubmit}>
        {error ? <AuthAlert message={error} /> : null}
        <FieldGroup>
          <Field>
            <FieldLabel htmlFor="signup-username">
              Username{config?.usernameRequired ? "" : " (optional)"}
            </FieldLabel>
            <Input
              id="signup-username"
              type="text"
              autoComplete="username"
              autoFocus
              required={config?.usernameRequired ?? false}
              value={username}
              onChange={(e) => setUsername(e.target.value)}
            />
          </Field>
          <Field>
            <FieldLabel htmlFor="signup-email">Email</FieldLabel>
            <Input
              id="signup-email"
              type="email"
              autoComplete="email"
              required={config?.emailRequired ?? false}
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />
            {config?.emailVerificationRequired ? (
              <FieldDescription>
                We will send a verification code to this address.
              </FieldDescription>
            ) : null}
          </Field>
          <Field>
            <FieldLabel htmlFor="signup-name">Name</FieldLabel>
            <Input
              id="signup-name"
              type="text"
              autoComplete="name"
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
          </Field>
          {(config?.phoneRequired || config?.phoneVerificationRequired) ? (
            <Field>
              <FieldLabel htmlFor="signup-phone">Phone</FieldLabel>
              <Input
                id="signup-phone"
                type="tel"
                autoComplete="tel"
                required={config?.phoneRequired ?? false}
                value={phone}
                onChange={(e) => setPhone(e.target.value)}
              />
              {config?.phoneVerificationRequired ? (
                <FieldDescription>
                  We will send a verification code to this number.
                </FieldDescription>
              ) : null}
            </Field>
          ) : null}
          <Field>
            <FieldLabel htmlFor="signup-password">Password</FieldLabel>
            <Input
              id="signup-password"
              type="password"
              autoComplete="new-password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </Field>
        </FieldGroup>
        <PendingButton
          type="submit"
          className="w-full"
          pending={pending || !config}
          pendingLabel="Creating…"
        >
          Create account
        </PendingButton>
      </form>
    </AuthCard>
  )
}
