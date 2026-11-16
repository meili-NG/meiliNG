import { useCallback, useEffect, useState, type FormEvent } from "react"
import {
  ChevronLeftIcon,
  ChevronRightIcon,
  ListChecksIcon,
  PlusIcon,
  SearchIcon,
} from "lucide-react"

import { AdminPageHeader } from "@/components/admin-panel"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
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
import { Textarea } from "@/components/ui/textarea"
import { CopyableId } from "@/components/ui/copyable-id"
import { ApiError } from "@/lib/api"
import { bulkCheckUsers, createUser, listAllUsers } from "@/lib/admin"
import type { UserSerialized } from "@/lib/users"

type AdminUsersViewProps = {
  onSelectUser: (userId: string) => void
}

const PAGE_SIZE = 20

export function AdminUsersView({ onSelectUser }: AdminUsersViewProps) {
  const [users, setUsers] = useState<UserSerialized[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [search, setSearch] = useState("")
  const [query, setQuery] = useState("")
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [formError, setFormError] = useState<string | null>(null)
  const [pending, setPending] = useState(false)
  const [showCreate, setShowCreate] = useState(false)
  const [showBulk, setShowBulk] = useState(false)
  const [bulkInput, setBulkInput] = useState("")
  const [bulkResult, setBulkResult] = useState<{
    found: string[]
    notFound: string[]
  } | null>(null)

  const [username, setUsername] = useState("")
  const [password, setPassword] = useState("")
  const [email, setEmail] = useState("")

  const load = useCallback(async (searchTerm: string, pageNum: number) => {
    setLoading(true)
    setError(null)
    try {
      const result = await listAllUsers({
        search: searchTerm || undefined,
        page: pageNum,
        size: PAGE_SIZE,
      })
      setUsers(result.data)
      setTotal(result.total)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed to list users")
      setUsers([])
      setTotal(0)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void load(query, page)
  }, [load, query, page])

  function resetCreateForm() {
    setUsername("")
    setPassword("")
    setEmail("")
    setFormError(null)
  }

  async function onSearch(event: FormEvent) {
    event.preventDefault()
    setPage(1)
    setQuery(search.trim())
  }

  async function onCreate(event: FormEvent) {
    event.preventDefault()
    setPending(true)
    setFormError(null)
    try {
      await createUser({
        username: username || undefined,
        password,
        emails: email ? [{ email }] : undefined,
      })
      resetCreateForm()
      setShowCreate(false)
      await load(query, page)
    } catch (err) {
      setFormError(
        err instanceof ApiError ? err.message : "Failed to create user",
      )
    } finally {
      setPending(false)
    }
  }

  async function onBulkCheck(event: FormEvent) {
    event.preventDefault()
    setPending(true)
    setFormError(null)
    setBulkResult(null)
    try {
      const ids = bulkInput
        .split(/[\s,]+/)
        .map((s) => s.trim())
        .filter(Boolean)
      const result = await bulkCheckUsers(ids)
      setBulkResult(result)
    } catch (err) {
      setFormError(
        err instanceof ApiError ? err.message : "Bulk check failed",
      )
    } finally {
      setPending(false)
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
        title="Users"
        description="Accounts on this instance."
        action={
          <div className="flex flex-wrap gap-2">
            <Button
              type="button"
              variant="outline"
              onClick={() => {
                setShowBulk(true)
                setBulkResult(null)
                setBulkInput("")
                setFormError(null)
              }}
            >
              <ListChecksIcon data-icon="inline-start" />
              Bulk check
            </Button>
            <Button type="button" onClick={() => setShowCreate(true)}>
              <PlusIcon data-icon="inline-start" />
              Create user
            </Button>
          </div>
        }
      />

      <form className="flex gap-2" onSubmit={onSearch}>
        <Input
          type="search"
          placeholder="Search name, email, or username"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        <Button type="submit" variant="outline">
          <SearchIcon data-icon="inline-start" />
          Search
        </Button>
      </form>

      {loading ? (
        <div className="flex flex-col gap-2 py-2">
          <Skeleton className="h-9 w-full" />
          <Skeleton className="h-9 w-full" />
          <Skeleton className="h-9 w-full" />
        </div>
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="hidden md:table-cell">ID</TableHead>
              <TableHead>Username</TableHead>
              <TableHead>Email</TableHead>
              <TableHead className="hidden md:table-cell">Name</TableHead>
              <TableHead>2FA</TableHead>
              <TableHead>Status</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {users.length === 0 ? (
              <TableRow>
                <TableCell
                  colSpan={6}
                  className="h-24 text-center text-muted-foreground"
                >
                  No users found.
                </TableCell>
              </TableRow>
            ) : (
              users.map((user) => (
                <TableRow
                  key={user.id}
                  className="cursor-pointer"
                  onClick={() => onSelectUser(user.id)}
                >
                  <TableCell className="hidden max-w-[12rem] md:table-cell">
                    <CopyableId value={user.id} truncate={12} />
                  </TableCell>
                  <TableCell>{user.usernames[0] || "—"}</TableCell>
                  <TableCell className="max-w-[10rem] truncate sm:max-w-[14rem]">
                    {user.emails[0] || "—"}
                  </TableCell>
                  <TableCell className="hidden md:table-cell">
                    {user.userData?.name || "—"}
                  </TableCell>
                  <TableCell>
                    {user.twoFactorEnabled ? (
                      <Badge variant="secondary">On</Badge>
                    ) : (
                      <span className="text-muted-foreground">Off</span>
                    )}
                  </TableCell>
                  <TableCell>
                    {user.deletedAt ? (
                      <Badge variant="destructive">Deleted</Badge>
                    ) : (
                      <span className="text-muted-foreground">Active</span>
                    )}
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      )}

      {total > 0 ? (
        <div className="flex items-center justify-between text-sm text-muted-foreground">
          <span>
            {(page - 1) * PAGE_SIZE + 1}–{Math.min(page * PAGE_SIZE, total)} of{" "}
            {total}
          </span>
          <div className="flex items-center gap-2">
            <Button
              type="button"
              variant="outline"
              size="sm"
              disabled={loading || page <= 1}
              onClick={() => setPage((p) => Math.max(1, p - 1))}
            >
              <ChevronLeftIcon data-icon="inline-start" />
              Previous
            </Button>
            <Button
              type="button"
              variant="outline"
              size="sm"
              disabled={loading || page * PAGE_SIZE >= total}
              onClick={() => setPage((p) => p + 1)}
            >
              Next
              <ChevronRightIcon data-icon="inline-end" />
            </Button>
          </div>
        </div>
      ) : null}

      <Dialog
        open={showCreate}
        onOpenChange={(open) => {
          setShowCreate(open)
          if (!open) resetCreateForm()
        }}
      >
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Create user</DialogTitle>
            <DialogDescription>
              Create an account on this instance.
            </DialogDescription>
          </DialogHeader>
          <form
            id="create-user"
            className="flex flex-col gap-4"
            onSubmit={onCreate}
          >
            <FieldGroup>
              <Field>
                <FieldLabel htmlFor="admin-username">Username</FieldLabel>
                <Input
                  id="admin-username"
                  type="text"
                  autoComplete="off"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                />
              </Field>
              <Field>
                <FieldLabel htmlFor="admin-email">Email</FieldLabel>
                <Input
                  id="admin-email"
                  type="email"
                  autoComplete="off"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                />
              </Field>
              <Field>
                <FieldLabel htmlFor="admin-password">Password</FieldLabel>
                <Input
                  id="admin-password"
                  type="password"
                  autoComplete="new-password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
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
            <Button type="submit" form="create-user" disabled={pending}>
              {pending ? "Creating…" : "Create"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog
        open={showBulk}
        onOpenChange={(open) => {
          setShowBulk(open)
          if (!open) {
            setBulkResult(null)
            setFormError(null)
          }
        }}
      >
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Bulk check users</DialogTitle>
            <DialogDescription>
              Paste user IDs separated by commas or whitespace.
            </DialogDescription>
          </DialogHeader>
          <form
            id="bulk-check"
            className="flex flex-col gap-4"
            onSubmit={onBulkCheck}
          >
            <Textarea
              rows={5}
              className="font-mono text-xs"
              value={bulkInput}
              onChange={(e) => setBulkInput(e.target.value)}
              placeholder="uuid-1&#10;uuid-2"
            />
            {formError ? (
              <Alert variant="destructive">
                <AlertDescription>{formError}</AlertDescription>
              </Alert>
            ) : null}
            {bulkResult ? (
              <div className="flex flex-col gap-2 text-sm">
                <p>
                  Found:{" "}
                  <span className="font-medium">{bulkResult.found.length}</span>
                </p>
                <p>
                  Missing:{" "}
                  <span className="font-medium">
                    {bulkResult.notFound.length}
                  </span>
                </p>
                {bulkResult.notFound.length > 0 ? (
                  <pre className="max-h-32 overflow-auto border border-border bg-muted/30 p-2 font-mono text-xs">
                    {bulkResult.notFound.join("\n")}
                  </pre>
                ) : null}
              </div>
            ) : null}
          </form>
          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => setShowBulk(false)}
            >
              Close
            </Button>
            <Button type="submit" form="bulk-check" disabled={pending}>
              {pending ? "Checking…" : "Check"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
