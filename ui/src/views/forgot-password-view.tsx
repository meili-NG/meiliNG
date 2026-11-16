import { useState, type FormEvent } from "react"

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
  confirmOwnershipCode,
  requestOwnershipCode,
  resetPassword,
} from "@/lib/auth"

type ForgotPasswordViewProps = {
  instanceName: string
  onBack: () => void
}

type Step = "identify" | "code" | "password" | "done"

export function ForgotPasswordView({
  instanceName,
  onBack,
}: ForgotPasswordViewProps) {
  const [step, setStep] = useState<Step>("identify")
  const [username, setUsername] = useState("")
  const [email, setEmail] = useState("")
  const [code, setCode] = useState("")
  const [password, setPassword] = useState("")
  const [ownershipToken, setOwnershipToken] = useState("")
  const [error, setError] = useState<string | null>(null)
  const [pending, setPending] = useState(false)

  async function onIdentifySubmit(event: FormEvent) {
    event.preventDefault()
    setError(null)
    setPending(true)
    try {
      const token = await requestOwnershipCode({ email })
      setOwnershipToken(token)
      setStep("code")
    } catch (err) {
      setError(
        err instanceof ApiError
          ? err.message
          : "Could not send verification code",
      )
    } finally {
      setPending(false)
    }
  }

  async function onCodeSubmit(event: FormEvent) {
    event.preventDefault()
    setError(null)
    setPending(true)
    try {
      const token = await confirmOwnershipCode({ email }, ownershipToken, code)
      setOwnershipToken(token)
      setStep("password")
    } catch (err) {
      setError(
        err instanceof ApiError ? err.message : "Invalid verification code",
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
      await resetPassword(username, ownershipToken, password)
      setStep("done")
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Password reset failed")
    } finally {
      setPending(false)
    }
  }

  if (step === "done") {
    return (
      <AuthCard
        instanceName={instanceName}
        title="Password updated"
        description="You can sign in with your new password."
      >
        <Button type="button" className="w-full" onClick={onBack}>
          Back to sign in
        </Button>
      </AuthCard>
    )
  }

  if (step === "password") {
    return (
      <AuthCard
        instanceName={instanceName}
        title="New password"
        description="Choose a new password for your account."
        footer={
          <Button
            type="button"
            variant="link"
            className="h-auto p-0"
            disabled={pending}
            onClick={() => {
              setStep("code")
              setPassword("")
              setError(null)
            }}
          >
            Back
          </Button>
        }
      >
        <form className="flex flex-col gap-4" onSubmit={onPasswordSubmit}>
          {error ? <AuthAlert message={error} /> : null}
          <FieldGroup>
            <Field>
              <FieldLabel htmlFor="new-password">New password</FieldLabel>
              <Input
                id="new-password"
                type="password"
                autoComplete="new-password"
                autoFocus
                required
                value={password}
                onChange={(event) => setPassword(event.target.value)}
              />
            </Field>
          </FieldGroup>
          <PendingButton
            type="submit"
            className="w-full"
            pending={pending}
            pendingLabel="Saving…"
          >
            Reset password
          </PendingButton>
        </form>
      </AuthCard>
    )
  }

  if (step === "code") {
    return (
      <AuthCard
        instanceName={instanceName}
        title="Check your email"
        description={`Enter the verification code sent to ${email}.`}
        footer={
          <Button
            type="button"
            variant="link"
            className="h-auto p-0"
            disabled={pending}
            onClick={() => {
              setStep("identify")
              setCode("")
              setError(null)
            }}
          >
            Back
          </Button>
        }
      >
        <form className="flex flex-col gap-4" onSubmit={onCodeSubmit}>
          {error ? <AuthAlert message={error} /> : null}
          <FieldGroup>
            <Field>
              <FieldLabel htmlFor="code">Verification code</FieldLabel>
              <Input
                id="code"
                type="text"
                inputMode="numeric"
                autoComplete="one-time-code"
                autoFocus
                required
                value={code}
                onChange={(event) => setCode(event.target.value)}
              />
            </Field>
          </FieldGroup>
          <PendingButton
            type="submit"
            className="w-full"
            pending={pending}
            pendingLabel="Verifying…"
          >
            Continue
          </PendingButton>
        </form>
      </AuthCard>
    )
  }

  return (
    <AuthCard
      instanceName={instanceName}
      title="Forgot password"
      description="We will send a verification code to your email."
      footer={
        <Button type="button" variant="link" className="h-auto p-0" onClick={onBack}>
          Back to sign in
        </Button>
      }
    >
      <form className="flex flex-col gap-4" onSubmit={onIdentifySubmit}>
        {error ? <AuthAlert message={error} /> : null}
        <FieldGroup>
          <Field>
            <FieldLabel htmlFor="forgot-username">Username</FieldLabel>
            <Input
              id="forgot-username"
              type="text"
              autoComplete="username"
              autoFocus
              required
              value={username}
              onChange={(event) => setUsername(event.target.value)}
            />
          </Field>
          <Field>
            <FieldLabel htmlFor="forgot-email">Email</FieldLabel>
            <Input
              id="forgot-email"
              type="email"
              autoComplete="email"
              required
              value={email}
              onChange={(event) => setEmail(event.target.value)}
            />
            <FieldDescription>
              Use the email associated with this username.
            </FieldDescription>
          </Field>
        </FieldGroup>
        <PendingButton
          type="submit"
          className="w-full"
          pending={pending}
          pendingLabel="Sending…"
        >
          Send code
        </PendingButton>
      </form>
    </AuthCard>
  )
}
