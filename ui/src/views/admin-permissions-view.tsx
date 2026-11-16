import {
  useCallback,
  useEffect,
  useMemo,
  useState,
  type FormEvent,
} from "react"
import {
  ChevronRightIcon,
  PencilIcon,
  PlusIcon,
  Trash2Icon,
} from "lucide-react"

import { AdminPageHeader } from "@/components/admin-panel"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { useToast } from "@/components/ui/toast"
import { Button } from "@/components/ui/button"
import { CopyableId } from "@/components/ui/copyable-id"
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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Skeleton } from "@/components/ui/skeleton"
import { ApiError } from "@/lib/api"
import {
  createPermission,
  deletePermission,
  listAllPermissions,
  updatePermission,
  type PermissionSerialized,
} from "@/lib/admin"
import {
  ancestorsOf,
  buildPermissionTree,
  descendantsOf,
  onTreeItemKeyDown,
} from "@/lib/permission-tree"
import { cn } from "@/lib/utils"

type Draft = {
  /** The permission being edited; null while creating. */
  editing: PermissionSerialized | null
  /** "" is top level. */
  parentId: string
  scope: string
  message: string
  isPublic: boolean
  isDefault: boolean
}

const emptyDraft: Draft = {
  editing: null,
  parentId: "",
  scope: "",
  message: "",
  isPublic: true,
  isDefault: false,
}

function narrower(count: number) {
  return `${count} narrower permission${count === 1 ? "" : "s"}`
}

function ScopeList({
  scopes,
  empty,
}: {
  scopes: PermissionSerialized[]
  empty: string
}) {
  if (scopes.length === 0) return <span>{empty}</span>
  return scopes.map((p) => (
    <Badge key={p.id} variant="outline" className="font-mono">
      {p.scope}
    </Badge>
  ))
}

export function AdminPermissionsView() {
  const { toast } = useToast()
  const [permissions, setPermissions] = useState<PermissionSerialized[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [formError, setFormError] = useState<string | null>(null)
  const [pending, setPending] = useState(false)
  const [dialog, setDialog] = useState<"form" | "delete" | null>(null)
  const [draft, setDraft] = useState<Draft>(emptyDraft)
  const [deleting, setDeleting] = useState<PermissionSerialized | null>(null)
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set())
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [focusedId, setFocusedId] = useState<string | null>(null)

  const tree = useMemo(() => buildPermissionTree(permissions), [permissions])

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      setPermissions(await listAllPermissions())
    } catch (err) {
      setError(
        err instanceof ApiError ? err.message : "Failed to list permissions",
      )
      setPermissions([])
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void load()
  }, [load])

  function openCreate(parent?: PermissionSerialized) {
    setDraft({
      editing: null,
      parentId: parent?.id ?? "",
      scope: parent ? `${parent.scope}.` : "",
      message: "",
      isPublic: parent?.isPublic ?? true,
      isDefault: false,
    })
    setFormError(null)
    setDialog("form")
  }

  function openEdit(permission: PermissionSerialized) {
    setDraft({
      editing: permission,
      parentId: tree.parent.get(permission.id) ?? "",
      scope: permission.scope,
      message: permission.message ?? "",
      isPublic: Boolean(permission.isPublic),
      isDefault: Boolean(permission.isDefault),
    })
    setFormError(null)
    setDialog("form")
  }

  function toggle(id: string) {
    setCollapsed((prev) => {
      const next = new Set(prev)
      if (!next.delete(id)) next.add(id)
      return next
    })
  }

  function select(id: string) {
    setSelectedId((prev) => (prev === id ? null : id))
  }

  async function onSubmit(event: FormEvent) {
    event.preventDefault()
    setPending(true)
    setFormError(null)
    try {
      if (draft.editing) {
        await updatePermission(draft.editing.id, {
          parentId: draft.parentId,
          isPublic: draft.isPublic,
          isDefault: draft.isDefault,
          message: draft.message,
        })
      } else {
        await createPermission({
          scope: draft.scope,
          isPublic: draft.isPublic,
          isDefault: draft.isDefault,
          parentId: draft.parentId || undefined,
          message: draft.message || undefined,
        })
      }
      setDialog(null)
      // The new or moved permission must be visible under its parent.
      setCollapsed((prev) => {
        const next = new Set(prev)
        next.delete(draft.parentId)
        for (const a of ancestorsOf(tree, draft.parentId)) next.delete(a.id)
        return next
      })
      await load()
      toast({
        variant: "success",
        title: `${draft.editing ? "Updated" : "Created"} "${draft.scope}"`,
      })
    } catch (err) {
      setFormError(
        err instanceof ApiError ? err.message : "Failed to save permission",
      )
    } finally {
      setPending(false)
    }
  }

  async function onDelete(permission: PermissionSerialized) {
    setPending(true)
    setError(null)
    try {
      await deletePermission(permission.id)
      await load()
      toast({ variant: "success", title: `Deleted "${permission.scope}"` })
    } catch (err) {
      const message =
        err instanceof ApiError ? err.message : "Failed to delete permission"
      setError(message)
      toast({
        variant: "destructive",
        title: "Delete failed",
        description: message,
      })
    } finally {
      setPending(false)
      setDialog(null)
    }
  }

  // Roving tabindex: exactly one row is in the tab order.
  // A row inside a collapsed branch is not rendered and cannot hold it.
  const focusedVisible =
    focusedId !== null &&
    tree.byId.has(focusedId) &&
    !ancestorsOf(tree, focusedId).some((a) => collapsed.has(a.id))
  const tabStopId = focusedVisible ? focusedId : tree.roots[0]?.id

  function renderNode(
    permission: PermissionSerialized,
    level: number,
    index: number,
    setSize: number,
  ) {
    const { id, scope } = permission
    const children = tree.children.get(id) ?? []
    const contained = descendantsOf(tree, id)
    const open = children.length > 0 && !collapsed.has(id)
    const selected = id === selectedId
    const deleteBlocked = contained.length > 0

    return (
      <li key={id} role="none">
        <div
          className={cn(
            "flex items-start gap-1 rounded-lg px-1 hover:bg-muted/50",
            selected && "bg-muted hover:bg-muted",
          )}
        >
          <div
            role="treeitem"
            aria-level={level}
            aria-posinset={index + 1}
            aria-setsize={setSize}
            aria-expanded={children.length > 0 ? open : undefined}
            aria-selected={selected}
            aria-owns={open ? `perm-group-${id}` : undefined}
            aria-describedby={selected ? "perm-detail" : undefined}
            tabIndex={id === tabStopId ? 0 : -1}
            onFocus={() => setFocusedId(id)}
            onClick={() => select(id)}
            onKeyDown={(e) =>
              onTreeItemKeyDown(e, {
                hasChildren: children.length > 0,
                open,
                toggle: () => toggle(id),
                activate: () => select(id),
              })
            }
            className="flex min-w-0 flex-1 cursor-pointer items-start gap-1 rounded-md py-1 outline-none focus-visible:ring-3 focus-visible:ring-ring/50"
          >
            {children.length > 0 ? (
              <span
                aria-hidden
                onClick={(e) => {
                  e.stopPropagation()
                  toggle(id)
                }}
                className="flex size-7 shrink-0 items-center justify-center rounded-md text-muted-foreground hover:bg-background hover:text-foreground"
              >
                <ChevronRightIcon
                  className={cn(
                    "size-4 transition-transform",
                    open && "rotate-90",
                  )}
                />
              </span>
            ) : (
              <span className="size-7 shrink-0" />
            )}
            <div className="flex min-w-0 flex-1 flex-col py-1">
              <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                <span className="font-mono text-sm font-medium break-all">
                  {scope}
                </span>
                {permission.isPublic ? (
                  <Badge variant="secondary">Public</Badge>
                ) : null}
                {permission.isDefault ? (
                  <Badge variant="outline">Default</Badge>
                ) : null}
                {contained.length > 0 ? (
                  <span className="text-xs text-muted-foreground">
                    contains {contained.length}
                  </span>
                ) : null}
              </div>
              {permission.message ? (
                <span className="text-xs break-words text-muted-foreground">
                  {permission.message}
                </span>
              ) : null}
            </div>
          </div>
          <div className="flex shrink-0 py-1">
            <Button
              type="button"
              variant="ghost"
              size="icon-sm"
              aria-label={`Add narrower permission under ${scope}`}
              title="Add narrower permission"
              onClick={() => openCreate(permission)}
            >
              <PlusIcon />
            </Button>
            <Button
              type="button"
              variant="ghost"
              size="icon-sm"
              aria-label={`Edit ${scope}`}
              title="Edit"
              onClick={() => openEdit(permission)}
            >
              <PencilIcon />
            </Button>
            <Button
              type="button"
              variant="ghost"
              size="icon-sm"
              // Stays focusable so the reason it is disabled can be reached.
              disabled={deleteBlocked}
              focusableWhenDisabled
              aria-label={`Delete ${scope}`}
              title={
                deleteBlocked
                  ? `Remove its ${narrower(contained.length)} first`
                  : "Delete"
              }
              className="aria-disabled:cursor-not-allowed aria-disabled:opacity-50"
              onClick={() => {
                setDeleting(permission)
                setDialog("delete")
              }}
            >
              <Trash2Icon />
            </Button>
          </div>
        </div>

        {selected ? (
          <div
            id="perm-detail"
            className="my-1 ml-9 flex flex-col gap-2 rounded-lg border bg-background p-3 text-sm"
          >
            <p className="flex flex-wrap items-center gap-1.5">
              <span>
                Granting <span className="font-mono font-medium">{scope}</span>{" "}
                also grants:
              </span>
              <ScopeList
                scopes={contained}
                empty="nothing else. It contains no narrower permissions."
              />
            </p>
            <p className="flex flex-wrap items-center gap-1.5">
              <span>Already granted by:</span>
              <ScopeList
                scopes={ancestorsOf(tree, id)}
                empty="nothing broader. It is a top-level permission."
              />
            </p>
            {deleteBlocked ? (
              <p className="text-muted-foreground">
                To delete it, remove its {narrower(contained.length)} first.
              </p>
            ) : null}
            <CopyableId value={id} className="self-start" />
          </div>
        ) : null}

        {open ? (
          <ul
            id={`perm-group-${id}`}
            role="group"
            className={cn(
              "ml-[1.125rem] border-l pl-1.5",
              selected && "border-primary",
            )}
          >
            {children.map((child, i) =>
              renderNode(child, level + 1, i, children.length),
            )}
          </ul>
        ) : null}
      </li>
    )
  }

  const draftParent = tree.byId.get(draft.parentId)
  // Moving a permission under itself or something it contains would make a cycle.
  const invalidParents = new Set(
    draft.editing
      ? [
          draft.editing.id,
          ...descendantsOf(tree, draft.editing.id).map((p) => p.id),
        ]
      : [],
  )
  const parentOptions = tree.roots
    .flatMap((root) => [root, ...descendantsOf(tree, root.id)])
    .filter((p) => !invalidParents.has(p.id))

  return (
    <div className="flex flex-col gap-4">
      {error ? (
        <Alert variant="destructive">
          <AlertTitle>Error</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      ) : null}

      <AdminPageHeader
        title="Permissions"
        description="A permission is what an application may receive about a user or do on their behalf; a broader permission contains the narrower ones under it."
        action={
          <Button type="button" onClick={() => openCreate()}>
            <PlusIcon data-icon="inline-start" />
            Add permission
          </Button>
        }
      />

      {loading && permissions.length === 0 ? (
        <div className="flex flex-col gap-2 py-2">
          <Skeleton className="h-9 w-full" />
          <Skeleton className="h-9 w-full" />
        </div>
      ) : permissions.length === 0 ? (
        <p className="py-8 text-center text-sm text-muted-foreground">
          No permissions found.
        </p>
      ) : (
        <ul
          role="tree"
          aria-label="Permissions"
          className="flex min-w-0 flex-col"
        >
          {tree.roots.map((root, i) =>
            renderNode(root, 1, i, tree.roots.length),
          )}
        </ul>
      )}

      <Dialog
        open={dialog === "form"}
        onOpenChange={(open) => {
          if (!open) setDialog(null)
        }}
      >
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>
              {draft.editing
                ? `Edit ${draft.scope}`
                : draftParent
                  ? "Add narrower permission"
                  : "Add permission"}
            </DialogTitle>
            <DialogDescription>
              {draftParent
                ? `Anyone granted ${draftParent.scope} is also granted this permission.`
                : "A top-level permission is not contained by any other."}
            </DialogDescription>
          </DialogHeader>
          <form
            id="permission-form"
            className="flex flex-col gap-4"
            onSubmit={onSubmit}
          >
            <FieldGroup>
              <Field>
                <FieldLabel htmlFor="perm-scope">Scope</FieldLabel>
                <Input
                  id="perm-scope"
                  required
                  disabled={draft.editing !== null}
                  className="font-mono"
                  value={draft.scope}
                  onChange={(e) =>
                    setDraft({ ...draft, scope: e.target.value })
                  }
                  // Typing continues after the pre-filled "<parent scope>." prefix.
                  onFocus={(e) => {
                    const end = e.currentTarget.value.length
                    e.currentTarget.setSelectionRange(end, end)
                  }}
                  placeholder="profile"
                />
                {draft.editing ? (
                  <FieldDescription>
                    The scope of an existing permission cannot be changed.
                  </FieldDescription>
                ) : null}
              </Field>
              <Field>
                <FieldLabel htmlFor="perm-parent">Contained by</FieldLabel>
                <Select
                  value={draft.parentId}
                  onValueChange={(value) =>
                    setDraft({ ...draft, parentId: value ?? "" })
                  }
                >
                  <SelectTrigger
                    id="perm-parent"
                    className="w-full data-placeholder:text-foreground"
                  >
                    <SelectValue>
                      {(value: string) =>
                        tree.byId.get(value)?.scope ?? "Nothing (top level)"
                      }
                    </SelectValue>
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="">Nothing (top level)</SelectItem>
                    {parentOptions.map((option) => (
                      <SelectItem key={option.id} value={option.id}>
                        <span
                          className="font-mono text-xs"
                          style={{
                            paddingLeft: `${ancestorsOf(tree, option.id).length * 0.75}rem`,
                          }}
                        >
                          {option.scope}
                        </span>
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                {draft.parentId ? (
                  <FieldDescription>
                    Everyone who already allowed{" "}
                    <span className="font-mono text-xs">
                      {tree.byId.get(draft.parentId)?.scope}
                    </span>{" "}
                    has allowed this too, without being asked again.
                  </FieldDescription>
                ) : null}
              </Field>
              <Field>
                <FieldLabel htmlFor="perm-message">Message</FieldLabel>
                <Input
                  id="perm-message"
                  value={draft.message}
                  onChange={(e) =>
                    setDraft({ ...draft, message: e.target.value })
                  }
                  placeholder="What the user is asked to allow"
                />
              </Field>
              <Field>
                <label className="flex items-center gap-2 text-sm">
                  <input
                    type="checkbox"
                    checked={draft.isPublic}
                    onChange={(e) =>
                      setDraft({ ...draft, isPublic: e.target.checked })
                    }
                  />
                  Public: listed for everyone, not only administrators
                </label>
              </Field>
              <Field>
                <label className="flex items-center gap-2 text-sm">
                  <input
                    type="checkbox"
                    aria-describedby="perm-default-help"
                    checked={draft.isDefault}
                    onChange={(e) =>
                      setDraft({ ...draft, isDefault: e.target.checked })
                    }
                  />
                  Allow to new applications
                </label>
                <FieldDescription id="perm-default-help">
                  Applications created from now on start allowed this and
                  everything under it. Existing applications are not changed.
                </FieldDescription>
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
              onClick={() => setDialog(null)}
            >
              Cancel
            </Button>
            <Button type="submit" form="permission-form" disabled={pending}>
              {pending ? "Saving…" : draft.editing ? "Save" : "Add"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog
        open={dialog === "delete"}
        onOpenChange={(open) => {
          if (!open) setDialog(null)
        }}
      >
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Delete {deleting?.scope}?</DialogTitle>
            <DialogDescription>
              Applications will no longer be able to request this permission.
              This cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => setDialog(null)}
            >
              Cancel
            </Button>
            <Button
              type="button"
              variant="destructive"
              disabled={pending}
              onClick={() => deleting && void onDelete(deleting)}
            >
              {pending ? "Deleting…" : "Delete"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
