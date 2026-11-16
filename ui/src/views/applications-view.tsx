import { useEffect, useState, type FormEvent, type ReactNode } from "react"
import { KeyRoundIcon, PlusIcon } from "lucide-react"

import { EmptyState } from "@/components/app-shell"
import { DashboardSection } from "@/components/dashboard-shell"
import { Button } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
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
  getApplications,
  getApplication,
  createApplication,
  deleteApplication,
  type Application,
} from "@/lib/applications"
import {
  getSecrets,
  createSecret,
  deleteSecret,
  getRedirectUris,
  addRedirectUri,
  deleteRedirectUri,
  type ClientSecret,
  type ClientRedirectUri,
} from "@/lib/oauth2"

type ApplicationsViewProps = {
  userId: string
  onHeaderActionChange?: (action: ReactNode | null) => void
}

type DetailState = {
  app: Application
  secrets: ClientSecret[]
  redirectUris: ClientRedirectUri[]
}

export function ApplicationsView({ userId, onHeaderActionChange }: ApplicationsViewProps) {
  const [apps, setApps] = useState<Application[]>([])
  const [detail, setDetail] = useState<DetailState | null>(null)
  const [creating, setCreating] = useState(false)
  const [addingRedirect, setAddingRedirect] = useState(false)

  const [name, setName] = useState("")
  const [privacy, setPrivacy] = useState("")
  const [terms, setTerms] = useState("")
  const [redirectUri, setRedirectUri] = useState("")
  const [newRedirectUri, setNewRedirectUri] = useState("")

  const [error, setError] = useState<string | null>(null)
  const [pending, setPending] = useState(false)

  useEffect(() => {
    getApplications(true)
      .then((r) => setApps(r.data))
      .catch(() => {})
  }, [userId])

  useEffect(() => {
    if (!onHeaderActionChange) return
    if (detail) {
      onHeaderActionChange(null)
      return
    }
    onHeaderActionChange(
      <Button type="button" onClick={() => setCreating(true)}>
        <PlusIcon data-icon="inline-start" />
        New application
      </Button>,
    )
    return () => onHeaderActionChange(null)
  }, [detail, onHeaderActionChange])

  async function openDetail(appId: string) {
    const [app, secrets, uris] = await Promise.all([
      getApplication(appId),
      getSecrets(appId),
      getRedirectUris(appId),
    ])
    setDetail({ app, secrets, redirectUris: uris })
  }

  function resetCreateForm() {
    setName("")
    setPrivacy("")
    setTerms("")
    setRedirectUri("")
    setError(null)
  }

  async function onCreate(event: FormEvent) {
    event.preventDefault()
    setError(null)
    setPending(true)
    try {
      await createApplication(userId, {
        name,
        redirectURIs: redirectUri ? [redirectUri] : [],
        privacy,
        terms,
      })
      const refreshed = await getApplications(true)
      setApps(refreshed.data)
      setCreating(false)
      resetCreateForm()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed to create application")
    } finally {
      setPending(false)
    }
  }

  async function onDelete(appId: string) {
    await deleteApplication(appId)
    setApps((prev) => prev.filter((c) => c.id !== appId))
    setDetail(null)
  }

  async function onAddSecret(appId: string) {
    await createSecret(appId)
    const secrets = await getSecrets(appId)
    setDetail((d) => (d ? { ...d, secrets } : d))
  }

  async function onDeleteSecret(appId: string, secretId: string) {
    await deleteSecret(appId, secretId)
    setDetail((d) =>
      d ? { ...d, secrets: d.secrets.filter((s) => s.id !== secretId) } : d,
    )
  }

  async function onAddRedirectUri(event: FormEvent) {
    event.preventDefault()
    if (!detail || !newRedirectUri) return
    setPending(true)
    try {
      await addRedirectUri(detail.app.id, newRedirectUri)
      const uris = await getRedirectUris(detail.app.id)
      setDetail((d) => (d ? { ...d, redirectUris: uris } : d))
      setNewRedirectUri("")
      setAddingRedirect(false)
    } finally {
      setPending(false)
    }
  }

  async function onDeleteRedirectUri(uriId: string) {
    if (!detail) return
    await deleteRedirectUri(detail.app.id, uriId)
    setDetail((d) =>
      d
        ? { ...d, redirectUris: d.redirectUris.filter((u) => u.id !== uriId) }
        : d,
    )
  }

  const createDialog = (
    <Dialog
      open={creating}
      onOpenChange={(open) => {
        setCreating(open)
        if (!open) resetCreateForm()
      }}
    >
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>New application</DialogTitle>
          <DialogDescription>Register an application you own.</DialogDescription>
        </DialogHeader>
        <form id="create-app" className="flex flex-col gap-4" onSubmit={onCreate}>
          <FieldGroup>
            <Field data-invalid={error ? true : undefined}>
              <FieldLabel htmlFor="app-name">Application name</FieldLabel>
              <Input
                id="app-name"
                type="text"
                autoFocus
                required
                value={name}
                onChange={(e) => setName(e.target.value)}
              />
            </Field>
            <Field>
              <FieldLabel htmlFor="app-privacy">Privacy policy URL</FieldLabel>
              <Input
                id="app-privacy"
                type="url"
                required
                value={privacy}
                onChange={(e) => setPrivacy(e.target.value)}
              />
            </Field>
            <Field>
              <FieldLabel htmlFor="app-terms">Terms of service URL</FieldLabel>
              <Input
                id="app-terms"
                type="url"
                required
                value={terms}
                onChange={(e) => setTerms(e.target.value)}
              />
            </Field>
            <Field>
              <FieldLabel htmlFor="app-redirect">
                OAuth2 redirect URI (optional)
              </FieldLabel>
              <Input
                id="app-redirect"
                type="url"
                value={redirectUri}
                onChange={(e) => setRedirectUri(e.target.value)}
              />
              {error ? <FieldError>{error}</FieldError> : null}
            </Field>
          </FieldGroup>
        </form>
        <DialogFooter>
          <Button
            type="button"
            variant="outline"
            onClick={() => setCreating(false)}
          >
            Cancel
          </Button>
          <Button type="submit" form="create-app" disabled={pending}>
            {pending ? "Creating…" : "Create application"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )

  if (detail) {
    return (
      <div className="flex flex-col gap-6">
        <Card className="sm:col-span-2">
          <CardHeader>
            <CardTitle>{detail.app.name}</CardTitle>
            <CardDescription className="font-mono">
              Application ID (OAuth2 client ID): {detail.app.id}
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-6">
            <DashboardSection
              title="OAuth2 client secrets"
              action={
                <Button
                  type="button"
                  variant="link"
                  className="h-auto p-0 text-sm"
                  onClick={() => onAddSecret(detail.app.id)}
                >
                  Generate
                </Button>
              }
            >
              {detail.secrets.length > 0 ? (
                <ul className="flex flex-col gap-2">
                  {detail.secrets.map((s) => (
                    <li
                      key={s.id}
                      className="flex items-center justify-between rounded-lg border border-border p-2 text-sm"
                    >
                      <code className="max-w-xs truncate text-xs">
                        {s.client_secret}
                      </code>
                      <Button
                        type="button"
                        variant="ghost"
                        size="sm"
                        className="h-auto p-0 text-xs text-destructive"
                        onClick={() => onDeleteSecret(detail.app.id, s.id)}
                      >
                        Delete
                      </Button>
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="text-sm text-muted-foreground">No secrets</p>
              )}
            </DashboardSection>

            <DashboardSection
              title="OAuth2 redirect URIs"
              action={
                <Button
                  type="button"
                  variant="link"
                  className="h-auto p-0 text-sm"
                  onClick={() => setAddingRedirect(true)}
                >
                  Add
                </Button>
              }
            >
              {detail.redirectUris.length > 0 ? (
                <ul className="flex flex-col gap-2">
                  {detail.redirectUris.map((u) => (
                    <li
                      key={u.id}
                      className="flex items-center justify-between text-sm"
                    >
                      <code className="max-w-xs truncate text-xs">
                        {u.redirect_uri}
                      </code>
                      <Button
                        type="button"
                        variant="ghost"
                        size="sm"
                        className="h-auto p-0 text-xs text-destructive"
                        onClick={() => onDeleteRedirectUri(u.id)}
                      >
                        Delete
                      </Button>
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="text-sm text-muted-foreground">None</p>
              )}
            </DashboardSection>
          </CardContent>
          <CardFooter className="justify-between gap-2">
            <Button
              type="button"
              variant="outline"
              onClick={() => setDetail(null)}
            >
              Back to applications
            </Button>
            <Button
              type="button"
              variant="destructive"
              size="sm"
              onClick={() => onDelete(detail.app.id)}
            >
              Delete application
            </Button>
          </CardFooter>
        </Card>

        <Dialog
          open={addingRedirect}
          onOpenChange={(open) => {
            setAddingRedirect(open)
            if (!open) setNewRedirectUri("")
          }}
        >
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Add OAuth2 redirect URI</DialogTitle>
              <DialogDescription>
                Allowed callback URL for this application.
              </DialogDescription>
            </DialogHeader>
            <form
              id="add-redirect"
              className="flex flex-col gap-4"
              onSubmit={onAddRedirectUri}
            >
              <Field>
                <FieldLabel htmlFor="redirect-uri">Redirect URI</FieldLabel>
                <Input
                  id="redirect-uri"
                  type="url"
                  required
                  autoFocus
                  placeholder="https://example.com/callback"
                  value={newRedirectUri}
                  onChange={(e) => setNewRedirectUri(e.target.value)}
                />
              </Field>
            </form>
            <DialogFooter>
              <Button
                type="button"
                variant="outline"
                onClick={() => setAddingRedirect(false)}
              >
                Cancel
              </Button>
              <Button type="submit" form="add-redirect" disabled={pending}>
                {pending ? "Adding…" : "Add"}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>
    )
  }

  return (
    <div className="flex flex-col gap-6">
      {apps.length > 0 ? (
        <ul className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          {apps.map((c) => (
            <li key={c.id}>
              <button
                type="button"
                className="w-full rounded-lg border border-border p-4 text-left transition-colors hover:bg-muted/50 focus-visible:ring-2 focus-visible:ring-ring/50 focus-visible:outline-none"
                onClick={() => openDetail(c.id)}
              >
                <span className="text-sm font-medium">{c.name}</span>
                <span className="mt-0.5 block truncate text-xs text-muted-foreground">
                  {c.id}
                </span>
              </button>
            </li>
          ))}
        </ul>
      ) : (
        <EmptyState
          icon={KeyRoundIcon}
          title="No applications yet"
          description="Register an application to let it sign users in with this account."
        />
      )}
      {createDialog}
    </div>
  )
}
