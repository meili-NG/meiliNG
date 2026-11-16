import { useEffect, useState, type FormEvent } from "react"
import { PlusIcon, XIcon } from "lucide-react"

import { SettingsSection } from "@/components/dashboard-shell"
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
import { Field, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Skeleton } from "@/components/ui/skeleton"
import { ApiError } from "@/lib/api"
import {
  getEmails,
  addEmail,
  removeEmail,
  getPhones,
  addPhone,
  removePhone,
  type UserEmail,
  type UserPhone,
} from "@/lib/users"

type ContactsViewProps = {
  userId: string
}

type RegisterKind = "email" | "phone" | null

export function ContactsView({ userId }: ContactsViewProps) {
  const [emails, setEmails] = useState<UserEmail[]>([])
  const [phones, setPhones] = useState<UserPhone[]>([])
  const [value, setValue] = useState("")
  const [registerKind, setRegisterKind] = useState<RegisterKind>(null)
  const [error, setError] = useState<string | null>(null)
  const [formError, setFormError] = useState<string | null>(null)
  const [pending, setPending] = useState(false)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    setLoading(true)
    Promise.all([getEmails(userId), getPhones(userId)])
      .then(([em, ph]) => {
        setEmails(em)
        setPhones(ph)
      })
      .catch((err) =>
        setError(
          err instanceof ApiError ? err.message : "Failed to load contacts",
        ),
      )
      .finally(() => setLoading(false))
  }, [userId])

  function openRegister(kind: Exclude<RegisterKind, null>) {
    setRegisterKind(kind)
    setValue("")
    setFormError(null)
  }

  function closeRegister() {
    setRegisterKind(null)
    setValue("")
    setFormError(null)
  }

  async function onRegister(event: FormEvent) {
    event.preventDefault()
    if (!registerKind) return
    setFormError(null)
    setPending(true)
    try {
      if (registerKind === "email") {
        await addEmail(userId, value)
        setEmails((prev) => [...prev, { email: value, verified: false }])
      } else {
        await addPhone(userId, value)
        setPhones((prev) => [...prev, { phone: value, verified: false }])
      }
      closeRegister()
    } catch (err) {
      setFormError(
        err instanceof ApiError
          ? err.message
          : registerKind === "email"
            ? "Failed to add email"
            : "Failed to add phone",
      )
    } finally {
      setPending(false)
    }
  }

  async function onRemoveEmail(email: string) {
    setError(null)
    try {
      await removeEmail(userId, email)
      setEmails((prev) => prev.filter((e) => e.email !== email))
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed to remove email")
    }
  }

  async function onRemovePhone(phone: string) {
    setError(null)
    try {
      await removePhone(userId, phone)
      setPhones((prev) => prev.filter((p) => p.phone !== phone))
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed to remove phone")
    }
  }

  if (loading) {
    return (
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        <Skeleton className="h-40 w-full" />
        <Skeleton className="h-40 w-full" />
      </div>
    )
  }

  return (
    <div className="flex flex-col gap-8">
      {error ? (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      ) : null}

      <div className="grid grid-cols-1 gap-8 md:grid-cols-2">
        <SettingsSection
          title="Emails"
          action={
            <Button
              type="button"
              variant="link"
              className="h-auto p-0 text-sm"
              onClick={() => openRegister("email")}
            >
              <PlusIcon data-icon="inline-start" />
              Register
            </Button>
          }
        >
          {emails.length > 0 ? (
            <ul className="flex flex-col gap-2">
              {emails.map((e) => (
                <li
                  key={e.email}
                  className="flex items-center justify-between gap-3"
                >
                  <div className="flex min-w-0 flex-wrap items-center gap-2">
                    <span className="truncate text-sm">{e.email}</span>
                    {e.verified ? (
                      <Badge variant="secondary">Verified</Badge>
                    ) : (
                      <Badge variant="outline">Unverified</Badge>
                    )}
                  </div>
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon-sm"
                    aria-label={`Remove ${e.email}`}
                    onClick={() => onRemoveEmail(e.email)}
                  >
                    <XIcon />
                  </Button>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-sm text-muted-foreground">None registered</p>
          )}
        </SettingsSection>

        <SettingsSection
          title="Phones"
          action={
            <Button
              type="button"
              variant="link"
              className="h-auto p-0 text-sm"
              onClick={() => openRegister("phone")}
            >
              <PlusIcon data-icon="inline-start" />
              Register
            </Button>
          }
        >
          {phones.length > 0 ? (
            <ul className="flex flex-col gap-2">
              {phones.map((p) => (
                <li
                  key={p.phone}
                  className="flex items-center justify-between gap-3"
                >
                  <div className="flex min-w-0 flex-wrap items-center gap-2">
                    <span className="truncate text-sm">{p.phone}</span>
                    {p.verified ? (
                      <Badge variant="secondary">Verified</Badge>
                    ) : (
                      <Badge variant="outline">Unverified</Badge>
                    )}
                  </div>
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon-sm"
                    aria-label={`Remove ${p.phone}`}
                    onClick={() => onRemovePhone(p.phone)}
                  >
                    <XIcon />
                  </Button>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-sm text-muted-foreground">None registered</p>
          )}
        </SettingsSection>
      </div>

      <Dialog
        open={registerKind !== null}
        onOpenChange={(open) => {
          if (!open) closeRegister()
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {registerKind === "phone" ? "Register phone" : "Register email"}
            </DialogTitle>
            <DialogDescription>
              {registerKind === "phone"
                ? "Add a phone number to this account."
                : "Add an email address to this account."}
            </DialogDescription>
          </DialogHeader>
          <form
            id="register-contact"
            className="flex flex-col gap-4"
            onSubmit={onRegister}
          >
            <Field>
              <FieldLabel htmlFor="register-value">
                {registerKind === "phone" ? "Phone number" : "Email address"}
              </FieldLabel>
              <Input
                id="register-value"
                type={registerKind === "phone" ? "tel" : "email"}
                required
                autoFocus
                value={value}
                onChange={(e) => setValue(e.target.value)}
              />
            </Field>
            {formError ? (
              <Alert variant="destructive">
                <AlertDescription>{formError}</AlertDescription>
              </Alert>
            ) : null}
          </form>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={closeRegister}>
              Cancel
            </Button>
            <Button type="submit" form="register-contact" disabled={pending}>
              {pending ? "Registering…" : "Register"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
