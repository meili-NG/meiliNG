import { useCallback, useEffect, useState, type FormEvent } from "react"
import { PlusIcon, Trash2Icon } from "lucide-react"

import { AdminPageHeader } from "@/components/admin-panel"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { useToast } from "@/components/ui/toast"
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
  FieldDescription,
  FieldGroup,
  FieldLabel,
} from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Skeleton } from "@/components/ui/skeleton"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { ApiError } from "@/lib/api"
import {
  adminDeleteRegisteredAudience,
  adminListRegisteredAudiences,
  adminRegisterAudience,
} from "@/lib/admin"
import type { Audience } from "@/lib/oauth2"

export function AdminAudiencesView() {
  const { toast } = useToast()
  const [audiences, setAudiences] = useState<Audience[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [formError, setFormError] = useState<string | null>(null)
  const [pending, setPending] = useState(false)
  const [showCreate, setShowCreate] = useState(false)
  const [audience, setAudience] = useState("")
  const [description, setDescription] = useState("")

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      setAudiences(await adminListRegisteredAudiences())
    } catch (err) {
      setError(
        err instanceof ApiError ? err.message : "Failed to list audiences",
      )
      setAudiences([])
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void load()
  }, [load])

  function resetCreateForm() {
    setAudience("")
    setDescription("")
    setFormError(null)
  }

  async function onCreate(event: FormEvent) {
    event.preventDefault()
    setPending(true)
    setFormError(null)
    try {
      await adminRegisterAudience({
        audience: audience.trim(),
        description: description.trim(),
      })
      resetCreateForm()
      setShowCreate(false)
      await load()
      toast({ variant: "success", title: `Registered "${audience.trim()}"` })
    } catch (err) {
      setFormError(
        err instanceof ApiError ? err.message : "Failed to register audience",
      )
    } finally {
      setPending(false)
    }
  }

  async function onDelete(entry: Audience) {
    setError(null)
    try {
      await adminDeleteRegisteredAudience(entry.id)
      await load()
      toast({ variant: "success", title: "Audience deleted" })
    } catch (err) {
      const message =
        err instanceof ApiError ? err.message : "Failed to delete audience"
      setError(message)
      toast({
        variant: "destructive",
        title: "Delete failed",
        description: message,
      })
    }
  }

  return (
    <div className="flex flex-col gap-4">
      {error ? (
        <Alert variant="destructive">
          <AlertTitle>Error</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      ) : null}

      <AdminPageHeader
        title="OAuth2 audiences"
        description="Resource servers applications can be granted access to with the client_credentials grant. Assign them per application under Applications → OAuth2."
        action={
          <Button type="button" onClick={() => setShowCreate(true)}>
            <PlusIcon data-icon="inline-start" />
            Register audience
          </Button>
        }
      />

      {loading ? (
        <div className="flex flex-col gap-2 py-2">
          <Skeleton className="h-9 w-full" />
          <Skeleton className="h-9 w-full" />
        </div>
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Audience</TableHead>
              <TableHead>Description</TableHead>
              <TableHead className="w-24">Applications</TableHead>
              <TableHead className="w-12" />
            </TableRow>
          </TableHeader>
          <TableBody>
            {audiences.length === 0 ? (
              <TableRow>
                <TableCell
                  colSpan={4}
                  className="h-24 text-center text-muted-foreground"
                >
                  No audiences registered. Applications cannot use
                  client_credentials until one is registered and assigned.
                </TableCell>
              </TableRow>
            ) : (
              audiences.map((entry) => (
                <TableRow key={entry.id}>
                  <TableCell className="font-mono text-xs font-medium whitespace-normal break-all">
                    {entry.audience}
                  </TableCell>
                  <TableCell className="min-w-[12rem] whitespace-normal text-muted-foreground">
                    {entry.description || "—"}
                  </TableCell>
                  <TableCell className="text-muted-foreground">
                    {entry.client_count}
                  </TableCell>
                  <TableCell>
                    <Button
                      type="button"
                      variant="ghost"
                      size="icon-sm"
                      aria-label={`Delete ${entry.audience}`}
                      disabled={entry.client_count > 0}
                      onClick={() => void onDelete(entry)}
                    >
                      <Trash2Icon />
                    </Button>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      )}

      <Dialog
        open={showCreate}
        onOpenChange={(open) => {
          setShowCreate(open)
          if (!open) resetCreateForm()
        }}
      >
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Register audience</DialogTitle>
            <DialogDescription>
              Register a resource server so applications can be assigned to it.
            </DialogDescription>
          </DialogHeader>
          <form
            id="create-audience"
            className="flex flex-col gap-4"
            onSubmit={onCreate}
          >
            <FieldGroup>
              <Field>
                <FieldLabel htmlFor="audience-value">Audience</FieldLabel>
                <Input
                  id="audience-value"
                  required
                  value={audience}
                  onChange={(e) => setAudience(e.target.value)}
                  placeholder="https://api.example.com"
                />
                <FieldDescription>
                  The identifier tokens are issued for. Immutable once
                  registered.
                </FieldDescription>
              </Field>
              <Field>
                <FieldLabel htmlFor="audience-description">
                  Description
                </FieldLabel>
                <Input
                  id="audience-description"
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  placeholder="Billing API"
                />
              </Field>
            </FieldGroup>
            {formError ? (
              <Alert variant="destructive">
                <AlertDescription>{formError}</AlertDescription>
              </Alert>
            ) : null}
          </form>
          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => setShowCreate(false)}
            >
              Cancel
            </Button>
            <Button type="submit" form="create-audience" disabled={pending}>
              {pending ? "Registering…" : "Register"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
