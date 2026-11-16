import {
  useCallback,
  useEffect,
  useId,
  useMemo,
  useState,
  type FormEvent,
} from "react";
import {
  ArrowLeftIcon,
  ChevronRightIcon,
  GlobeIcon,
  LockIcon,
  PlusIcon,
  SearchIcon,
  Trash2Icon,
} from "lucide-react";

import {
  AdminField,
  AdminFieldGrid,
  AdminPageHeader,
  AdminPageTabs,
  AdminSection,
} from "@/components/admin-panel";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Field,
  FieldDescription,
  FieldGroup,
  FieldLabel,
} from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { CopyableId } from "@/components/ui/copyable-id";
import { useToast } from "@/components/ui/toast";
import { UserSelect } from "@/components/ui/user-select";
import { ApiError, apiJson } from "@/lib/api";
import {
  adminAddRedirectUri,
  adminAssignAudience,
  adminCreateSecret,
  adminDeleteApplication,
  adminDeleteRedirectUri,
  adminDeleteSecret,
  adminGetAudiences,
  adminGetApplication,
  adminGetApplicationPermissions,
  adminGetRedirectUris,
  adminGetSecrets,
  adminListRegisteredAudiences,
  adminSetApplicationPermissions,
  adminUnassignAudience,
  adminUpdateApplication,
  listAllApplications,
  listAllPermissions,
  type ApplicationPermissionLimit,
  type PermissionSerialized,
} from "@/lib/admin";
import { adminAuthHeaders } from "@/lib/admin-session";
import type { Application } from "@/lib/applications";
import type {
  Audience,
  ClientAudience,
  ClientRedirectUri,
  ClientSecret,
} from "@/lib/oauth2";
import {
  ancestorsOf,
  buildPermissionTree,
  descendantsOf,
  onTreeItemKeyDown,
} from "@/lib/permission-tree";
import { cn } from "@/lib/utils";

type AdminApplicationsViewProps = {
  selectedAppId?: string | null;
  onSelectApp: (appId: string | null) => void;
};

export function AdminApplicationsView({
  selectedAppId,
  onSelectApp,
}: AdminApplicationsViewProps) {
  if (selectedAppId) {
    return (
      <AdminApplicationDetail
        key={selectedAppId}
        appId={selectedAppId}
        onBack={() => onSelectApp(null)}
      />
    );
  }
  return <AdminApplicationsList onSelectApp={onSelectApp} />;
}

function AdminApplicationsList({
  onSelectApp,
}: {
  onSelectApp: (appId: string) => void;
}) {
  const [apps, setApps] = useState<Application[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [pending, setPending] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [ownerId, setOwnerId] = useState("");
  const [name, setName] = useState("");
  const [redirectUri, setRedirectUri] = useState("");
  const [filter, setFilter] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await listAllApplications({ page: 1, size: 50 });
      setApps(result.data ?? []);
    } catch (err) {
      setError(
        err instanceof ApiError ? err.message : "Failed to list applications",
      );
      setApps([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const filtered = filter
    ? apps.filter(
        (c) =>
          c.name.toLowerCase().includes(filter.toLowerCase()) ||
          c.id.includes(filter) ||
          (c.ownerId ?? "").includes(filter),
      )
    : apps;

  async function onCreate(event: FormEvent) {
    event.preventDefault();
    setPending(true);
    setFormError(null);
    try {
      // Owner is optional for admins: an empty user_id creates an
      // instance-owned (ownerless) application. Redirect URI is optional too
      // and is only sent when provided, so an application can be created and
      // configured later.
      const trimmedRedirect = redirectUri.trim();
      const query = ownerId ? `?user_id=${encodeURIComponent(ownerId)}` : "";
      await apiJson<unknown>(`/v2/apps/${query}`, {
        method: "POST",
        headers: adminAuthHeaders(),
        body: JSON.stringify({
          name,
          redirectURIs: trimmedRedirect ? [trimmedRedirect] : [],
          privacy: "https://example.com/privacy",
          terms: "https://example.com/terms",
          isPublicClient: false,
        }),
      });
      setShowCreate(false);
      setOwnerId("");
      setName("");
      setRedirectUri("");
      await load();
    } catch (err) {
      setFormError(
        err instanceof ApiError
          ? err.message
          : "Failed to create application",
      );
    } finally {
      setPending(false);
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
        title="Applications"
        description="Applications registered on this instance."
        action={
          <Button type="button" onClick={() => setShowCreate(true)}>
            <PlusIcon data-icon="inline-start" />
            Create application
          </Button>
        }
      />

      <div className="relative">
        <SearchIcon className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-muted-foreground" />
        <Input
          className="pl-9"
          placeholder="Filter by name, id, or owner"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
        />
      </div>

      {loading ? (
        <div className="flex flex-col gap-2 py-2">
          <Skeleton className="h-9 w-full" />
          <Skeleton className="h-9 w-full" />
        </div>
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Name</TableHead>
              <TableHead className="hidden md:table-cell">ID</TableHead>
              <TableHead className="hidden lg:table-cell">Owner</TableHead>
              <TableHead>OAuth2 client</TableHead>
              <TableHead>Flags</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {filtered.length === 0 ? (
              <TableRow>
                <TableCell
                  colSpan={5}
                  className="h-24 text-center text-muted-foreground"
                >
                  No applications found.
                </TableCell>
              </TableRow>
            ) : (
              filtered.map((app) => (
                <TableRow
                  key={app.id}
                  className="cursor-pointer"
                  onClick={() => onSelectApp(app.id)}
                >
                  <TableCell className="font-medium">{app.name}</TableCell>
                  <TableCell className="hidden max-w-[12rem] md:table-cell">
                    <CopyableId value={app.id} truncate={12} />
                  </TableCell>
                  <TableCell className="hidden max-w-[10rem] lg:table-cell">
                    {app.ownerId ? (
                      <CopyableId value={app.ownerId} truncate={12} />
                    ) : (
                      <span className="text-muted-foreground">Instance</span>
                    )}
                  </TableCell>
                  <TableCell>
                    <div className="flex flex-wrap items-center gap-1">
                      {app.isPublicClient ? "Public" : "Confidential"}
                    </div>
                  </TableCell>
                  <TableCell>
                    {app.isVerified ? (
                      <Badge variant="secondary">Verified</Badge>
                    ) : (
                      "—"
                    )}
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      )}

      <Dialog open={showCreate} onOpenChange={setShowCreate}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Create application</DialogTitle>
            <DialogDescription>
              Creates an application owned by the given user. It starts with
              the default permissions only; allow more under its Permissions
              tab.
            </DialogDescription>
          </DialogHeader>
          <form
            id="create-app"
            className="flex flex-col gap-4"
            onSubmit={onCreate}
          >
            <FieldGroup>
              <Field>
                <FieldLabel htmlFor="create-app-owner">Owner</FieldLabel>
                <UserSelect
                  id="create-app-owner"
                  value={ownerId}
                  onChange={(id) => setOwnerId(id)}
                />
                <FieldDescription>
                  Optional. Leave empty for an instance-owned application.
                </FieldDescription>
              </Field>
              <Field>
                <FieldLabel>Name</FieldLabel>
                <Input
                  required
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                />
              </Field>
              <Field>
                <FieldLabel>OAuth2 redirect URI</FieldLabel>
                <Input
                  type="url"
                  placeholder="https://app.example.com/callback"
                  value={redirectUri}
                  onChange={(e) => setRedirectUri(e.target.value)}
                />
                <FieldDescription>
                  Optional. You can add redirect URIs later.
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
              onClick={() => setShowCreate(false)}
            >
              Cancel
            </Button>
            <Button
              type="submit"
              form="create-app"
              disabled={pending || !name.trim()}
            >
              {pending ? "Creating…" : "Create"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

function AdminApplicationDetail({
  appId,
  onBack,
}: {
  appId: string;
  onBack: () => void;
}) {
  const { toast } = useToast();
  const [app, setApp] = useState<Application | null>(null);
  const [secrets, setSecrets] = useState<ClientSecret[]>([]);
  const [uris, setUris] = useState<ClientRedirectUri[]>([]);
  const [audiences, setAudiences] = useState<ClientAudience[]>([]);
  const [registeredAudiences, setRegisteredAudiences] = useState<Audience[]>(
    [],
  );
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [clientType, setClientType] = useState<"public" | "confidential">(
    "confidential",
  );
  const [newUri, setNewUri] = useState("");
  const [newAudience, setNewAudience] = useState("");
  const [showDelete, setShowDelete] = useState(false);

  const [tab, setTab] = useState("application");

  // Only the first load shows the skeleton; reloads after an action keep the
  // page, and the open tab, in place.
  const load = useCallback(async () => {
    setError(null);
    try {
      const [c, s, r, a, registered] = await Promise.all([
        adminGetApplication(appId),
        adminGetSecrets(appId).catch(() => [] as ClientSecret[]),
        adminGetRedirectUris(appId).catch(() => [] as ClientRedirectUri[]),
        adminGetAudiences(appId).catch(() => [] as ClientAudience[]),
        adminListRegisteredAudiences().catch(() => [] as Audience[]),
      ]);
      setApp(c);
      setName(c.name);
      setClientType(c.isPublicClient ? "public" : "confidential");
      setSecrets(s);
      setUris(r);
      setAudiences(a);
      setRegisteredAudiences(registered);
    } catch (err) {
      setError(
        err instanceof ApiError ? err.message : "Failed to load application",
      );
    } finally {
      setLoading(false);
    }
  }, [appId]);

  useEffect(() => {
    void load();
  }, [load]);

  const unassignedAudiences = useMemo(() => {
    const assigned = new Set(audiences.map((item) => item.audience_id));
    return registeredAudiences.filter((item) => !assigned.has(item.id));
  }, [audiences, registeredAudiences]);

  async function run(fn: () => Promise<void>, successMessage?: string) {
    setPending(true);
    setActionError(null);
    try {
      await fn();
      await load();
      if (successMessage) {
        toast({ variant: "success", title: successMessage });
      }
    } catch (err) {
      const message = err instanceof ApiError ? err.message : "Action failed";
      setActionError(message);
      toast({
        variant: "destructive",
        title: "Action failed",
        description: message,
      });
    } finally {
      setPending(false);
    }
  }

  if (loading) {
    return (
      <div className="flex flex-col gap-3">
        <Skeleton className="h-8 w-40" />
        <Skeleton className="h-32 w-full" />
      </div>
    );
  }

  if (error || !app) {
    return (
      <div className="flex flex-col gap-4">
        <Button
          type="button"
          variant="ghost"
          className="w-fit px-0"
          onClick={onBack}
        >
          <ArrowLeftIcon data-icon="inline-start" />
          Applications
        </Button>
        <Alert variant="destructive">
          <AlertDescription>{error ?? "Not found"}</AlertDescription>
        </Alert>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <Button
            type="button"
            variant="ghost"
            className="mb-1 h-auto w-fit px-0 py-0 text-muted-foreground"
            onClick={onBack}
          >
            <ArrowLeftIcon data-icon="inline-start" />
            Applications
          </Button>
          <h1 className="text-xl font-semibold tracking-tight">
            {app.name}
          </h1>
          <div className="mt-1">
            <CopyableId value={app.id} />
          </div>
        </div>
        <Button
          type="button"
          variant="destructive"
          size="sm"
          className="w-fit"
          onClick={() => setShowDelete(true)}
        >
          <Trash2Icon data-icon="inline-start" />
          Delete
        </Button>
      </div>

      {actionError ? (
        <Alert variant="destructive">
          <AlertDescription>{actionError}</AlertDescription>
        </Alert>
      ) : null}

      <Tabs value={tab} onValueChange={(v) => setTab(String(v))}>
        <AdminPageTabs
          tabs={[
            { value: "application", label: "Application" },
            { value: "permissions", label: "Permissions" },
            { value: "oauth2", label: "OAuth2" },
          ]}
        />

        <TabsContent
          value="application"
          className="mt-4 grid items-start gap-8 lg:grid-cols-2"
        >
          <AdminSection
            title="Application"
            action={
              <Button
                type="button"
                size="sm"
                disabled={pending || name === app.name}
                onClick={() =>
                  void run(
                    () => adminUpdateApplication(appId, { name }),
                    "Application saved",
                  )
                }
              >
                Save
              </Button>
            }
          >
            <AdminFieldGrid columns={1}>
              <AdminField label="Name">
                <Input value={name} onChange={(e) => setName(e.target.value)} />
              </AdminField>
              <AdminField label="Owner">
                {app.ownerId ? (
                  <CopyableId value={app.ownerId} />
                ) : (
                  <span className="text-muted-foreground">
                    Instance (no owner)
                  </span>
                )}
              </AdminField>
              <AdminField label="Verified">
                {app.isVerified ? "Yes" : "No"}
              </AdminField>
            </AdminFieldGrid>
          </AdminSection>
        </TabsContent>

        <TabsContent
          value="oauth2"
          className="mt-4 grid items-start gap-8 lg:grid-cols-2"
        >
          <AdminSection
            title="OAuth2 client"
            action={
              <Button
                type="button"
                size="sm"
                disabled={
                  pending ||
                  clientType ===
                    (app.isPublicClient ? "public" : "confidential")
                }
                onClick={() =>
                  void run(
                    () =>
                      adminUpdateApplication(appId, {
                        isPublicClient: clientType === "public",
                      }),
                    "OAuth2 client saved",
                  )
                }
              >
                Save
              </Button>
            }
          >
            <AdminFieldGrid columns={1}>
              <AdminField label="Type">
                <Tabs
                  value={clientType}
                  onValueChange={(v) =>
                    setClientType(v as "public" | "confidential")
                  }
                >
                  <TabsList className="grid w-full grid-cols-2">
                    <TabsTrigger value="confidential">
                      <LockIcon data-icon="inline-start" />
                      Confidential
                    </TabsTrigger>
                    <TabsTrigger value="public">
                      <GlobeIcon data-icon="inline-start" />
                      Public
                    </TabsTrigger>
                  </TabsList>
                </Tabs>
              </AdminField>
            </AdminFieldGrid>
          </AdminSection>

          <AdminSection title="Redirect URIs">
            <AddRow
              placeholder="https://…"
              value={newUri}
              onChange={setNewUri}
              disabled={pending}
              onAdd={() =>
                void run(async () => {
                  await adminAddRedirectUri(appId, newUri);
                  setNewUri("");
                })
              }
            />
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>URI</TableHead>
                  <TableHead className="w-20" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {uris.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={2} className="text-muted-foreground">
                      No redirect URIs.
                    </TableCell>
                  </TableRow>
                ) : (
                  uris.map((uri) => (
                    <TableRow key={uri.id}>
                      <TableCell className="font-mono text-xs whitespace-normal">
                        {uri.redirect_uri}
                      </TableCell>
                      <TableCell>
                        <Button
                          type="button"
                          variant="ghost"
                          size="sm"
                          disabled={pending}
                          onClick={() =>
                            void run(() =>
                              adminDeleteRedirectUri(appId, uri.id),
                            )
                          }
                        >
                          Remove
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </AdminSection>

          <AdminSection
            title="Client secrets"
            action={
              <Button
                type="button"
                size="sm"
                variant="outline"
                disabled={pending}
                onClick={() => void run(() => adminCreateSecret(appId))}
              >
                Create secret
              </Button>
            }
          >
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Secret</TableHead>
                  <TableHead className="w-20" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {secrets.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={2} className="text-muted-foreground">
                      No secrets.
                    </TableCell>
                  </TableRow>
                ) : (
                  secrets.map((secret) => (
                    <TableRow key={secret.id}>
                      <TableCell className="max-w-md">
                        <CopyableId
                          value={secret.client_secret || secret.id}
                          truncate={32}
                        />
                      </TableCell>
                      <TableCell>
                        <Button
                          type="button"
                          variant="ghost"
                          size="sm"
                          disabled={pending}
                          onClick={() =>
                            void run(() =>
                              adminDeleteSecret(appId, secret.id),
                            )
                          }
                        >
                          Revoke
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </AdminSection>

          <AdminSection
            title="Allowed audiences"
            description="Audiences this application may request with the client_credentials grant. Anything else is refused. Register an audience under OAuth2 audiences first."
          >
            <AssignAudienceRow
              options={unassignedAudiences}
              value={newAudience}
              onChange={setNewAudience}
              disabled={pending}
              onAssign={() =>
                void run(async () => {
                  await adminAssignAudience(appId, newAudience);
                  setNewAudience("");
                }, "Audience assigned")
              }
            />
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Audience</TableHead>
                  <TableHead className="w-20" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {audiences.length === 0 ? (
                  <TableRow>
                    <TableCell
                      colSpan={2}
                      className="whitespace-normal text-muted-foreground"
                    >
                      No audiences. This application cannot use client_credentials.
                    </TableCell>
                  </TableRow>
                ) : (
                  audiences.map((audience) => (
                    <TableRow key={audience.id}>
                      <TableCell className="whitespace-normal break-all">
                        <div className="font-mono text-xs">
                          {audience.audience}
                        </div>
                        {audience.description ? (
                          <div className="text-muted-foreground text-xs">
                            {audience.description}
                          </div>
                        ) : null}
                      </TableCell>
                      <TableCell>
                        <Button
                          type="button"
                          variant="ghost"
                          size="sm"
                          disabled={pending}
                          onClick={() =>
                            void run(() =>
                              adminUnassignAudience(appId, audience.id),
                            )
                          }
                        >
                          Remove
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </AdminSection>
        </TabsContent>

        {/* Kept mounted so unsaved choices survive a look at another tab. */}
        <TabsContent value="permissions" keepMounted className="mt-4">
          <ApplicationPermissionLimitSection appId={appId} />
        </TabsContent>
      </Tabs>

      <Dialog open={showDelete} onOpenChange={setShowDelete}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete application?</DialogTitle>
            <DialogDescription>
              Permanently deletes this application and its OAuth2 client.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => setShowDelete(false)}
            >
              Cancel
            </Button>
            <Button
              type="button"
              variant="destructive"
              disabled={pending}
              onClick={() =>
                void run(async () => {
                  await adminDeleteApplication(appId);
                  onBack();
                })
              }
            >
              Delete
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

const limitChoices = [
  {
    limited: false,
    title: "Any permission",
    text: "The application may ask users for every permission on this instance, including ones added later.",
  },
  {
    limited: true,
    title: "Only the selected permissions",
    text: "The application may ask only for what is checked below; default permissions are always included. A request for anything else is refused.",
  },
];

/** Which permissions the application may request: anything, or only a chosen part of the permission tree. */
function ApplicationPermissionLimitSection({ appId }: { appId: string }) {
  const { toast } = useToast();
  const choiceName = useId();
  const [permissions, setPermissions] = useState<PermissionSerialized[]>([]);
  const [saved, setSaved] = useState<ApplicationPermissionLimit | null>(null);
  const [limited, setLimited] = useState(false);
  // Only the explicitly checked permissions; what they contain is derived.
  const [checked, setChecked] = useState<Set<string>>(new Set());
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());
  const [focusedId, setFocusedId] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const tree = useMemo(() => buildPermissionTree(permissions), [permissions]);

  function show(limit: ApplicationPermissionLimit) {
    setSaved(limit);
    setLimited(limit.limited);
    setChecked(new Set(limit.permissions.map((p) => p.id)));
  }

  useEffect(() => {
    let stale = false;
    Promise.all([adminGetApplicationPermissions(appId), listAllPermissions()])
      .then(([limit, all]) => {
        if (stale) return;
        setPermissions(all);
        show(limit);
      })
      .catch((err) => {
        if (stale) return;
        setError(
          err instanceof ApiError ? err.message : "Failed to load permissions",
        );
      });
    return () => {
      stale = true;
    };
  }, [appId]);

  async function save() {
    setPending(true);
    setError(null);
    try {
      show(
        await adminSetApplicationPermissions(appId, {
          limited,
          permissionIds: [...checked],
        }),
      );
      toast({ variant: "success", title: "Permissions saved" });
    } catch (err) {
      setError(
        err instanceof ApiError ? err.message : "Failed to save permissions",
      );
    } finally {
      setPending(false);
    }
  }

  function toggleChecked(id: string) {
    setChecked((prev) => {
      const next = new Set(prev);
      if (!next.delete(id)) {
        next.add(id);
        // The broader permission now covers these, so they are no longer sent.
        for (const p of descendantsOf(tree, id)) next.delete(p.id);
      }
      return next;
    });
  }

  function toggleOpen(id: string) {
    setCollapsed((prev) => {
      const next = new Set(prev);
      if (!next.delete(id)) next.add(id);
      return next;
    });
  }

  if (!saved) {
    return (
      <AdminSection title="Permissions this application may request">
        {error ? (
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        ) : (
          <Skeleton className="h-24 w-full" />
        )}
      </AdminSection>
    );
  }

  const dirty =
    limited !== saved.limited ||
    checked.size !== saved.permissions.length ||
    saved.permissions.some((p) => !checked.has(p.id));
  const covered = (ids: string[]) =>
    ids.flatMap((id) => [id, ...descendantsOf(tree, id).map((p) => p.id)]);
  // Everything the application can request: what the checked permissions cover.
  const allowed = new Set(
    covered([...checked].filter((id) => tree.byId.has(id))),
  );
  const canSignIn = permissions.some(
    (p) => p.scope === "openid" && allowed.has(p.id),
  );
  // Roving tabindex, as on the Permissions page: a row in a collapsed branch is not rendered.
  const tabStopId =
    focusedId !== null &&
    tree.byId.has(focusedId) &&
    !ancestorsOf(tree, focusedId).some((a) => collapsed.has(a.id))
      ? focusedId
      : tree.roots[0]?.id;

  function renderNode(
    permission: PermissionSerialized,
    level: number,
    index: number,
    setSize: number,
    includedBy?: PermissionSerialized,
  ) {
    const { id, scope } = permission;
    const children = tree.children.get(id) ?? [];
    const open = children.length > 0 && !collapsed.has(id);
    const locked = includedBy !== undefined;
    const on = locked || checked.has(id);
    const checkedInside = on
      ? 0
      : descendantsOf(tree, id).filter((p) => checked.has(p.id)).length;

    return (
      <li key={id} role="none">
        <div
          role="treeitem"
          aria-level={level}
          aria-posinset={index + 1}
          aria-setsize={setSize}
          aria-expanded={children.length > 0 ? open : undefined}
          aria-checked={on}
          aria-disabled={locked || pending ? true : undefined}
          aria-owns={open ? `app-perm-group-${id}` : undefined}
          tabIndex={id === tabStopId ? 0 : -1}
          onFocus={() => setFocusedId(id)}
          onClick={() => {
            if (!locked && !pending) toggleChecked(id);
          }}
          onKeyDown={(e) =>
            onTreeItemKeyDown(e, {
              hasChildren: children.length > 0,
              open,
              toggle: () => toggleOpen(id),
              activate: () => {
                if (!locked && !pending) toggleChecked(id);
              },
            })
          }
          className={cn(
            "flex min-w-0 cursor-pointer items-start gap-1 rounded-lg px-1 py-1 outline-none hover:bg-muted/50 focus-visible:ring-3 focus-visible:ring-ring/50",
            locked && "cursor-default",
          )}
        >
          {children.length > 0 ? (
            <span
              aria-hidden
              onClick={(e) => {
                e.stopPropagation();
                toggleOpen(id);
              }}
              className="flex size-7 shrink-0 cursor-pointer items-center justify-center rounded-md text-muted-foreground hover:bg-background hover:text-foreground"
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
          {/* Shows the state only; the row is the control and carries aria-checked. */}
          <input
            type="checkbox"
            aria-hidden
            tabIndex={-1}
            readOnly
            checked={on}
            disabled={locked}
            className="pointer-events-none mt-[0.4375rem] shrink-0"
          />
          <div className="flex min-w-0 flex-1 flex-col py-1 pl-1">
            <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
              <span className="font-mono text-sm font-medium break-all">
                {scope}
              </span>
              {includedBy ? (
                <span className="text-xs text-muted-foreground">
                  included by{" "}
                  <span className="font-mono">{includedBy.scope}</span>
                </span>
              ) : checkedInside > 0 ? (
                <span className="text-xs text-muted-foreground">
                  {checkedInside} selected inside
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

        {open ? (
          <ul
            id={`app-perm-group-${id}`}
            role="group"
            className="ml-[1.125rem] border-l pl-1.5"
          >
            {children.map((child, i) =>
              renderNode(
                child,
                level + 1,
                i,
                children.length,
                includedBy ?? (on ? permission : undefined),
              ),
            )}
          </ul>
        ) : null}
      </li>
    );
  }

  return (
    <AdminSection
      title="Permissions this application may request"
      description="A permission is what an application may receive about a user or do on their behalf. Only administrators can change this."
      action={
        <Button
          type="button"
          size="sm"
          disabled={pending || !dirty}
          onClick={() => void save()}
        >
          {pending ? "Saving…" : "Save"}
        </Button>
      }
    >
      {error ? (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      ) : null}

      <fieldset className="grid gap-2 sm:grid-cols-2" disabled={pending}>
        <legend className="sr-only">
          Permissions this application may request
        </legend>
        {limitChoices.map((choice) => (
          <label
            key={choice.title}
            className={cn(
              "flex cursor-pointer items-start gap-2 rounded-lg border p-3 text-sm",
              limited === choice.limited && "border-primary bg-muted/50",
            )}
          >
            <input
              type="radio"
              name={choiceName}
              className="mt-0.5"
              checked={limited === choice.limited}
              onChange={() => setLimited(choice.limited)}
            />
            <span className="flex min-w-0 flex-col gap-0.5">
              <span className="font-medium">{choice.title}</span>
              <span className="text-xs text-muted-foreground">
                {choice.text}
              </span>
            </span>
          </label>
        ))}
      </fieldset>

      <div aria-live="polite" className="flex flex-col gap-1 text-sm">
        {limited && !canSignIn ? (
          <Alert variant="warning">
            <AlertDescription>
              This application cannot sign users in: what it can request does
              not include "openid".
            </AlertDescription>
          </Alert>
        ) : null}
        <p>
          {limited
            ? `This application can request ${allowed.size} of ${tree.byId.size} permission${tree.byId.size === 1 ? "" : "s"}.`
            : "This application can request any permission."}
        </p>
        {dirty ? (
          <p className="text-xs text-muted-foreground">Unsaved changes.</p>
        ) : null}
      </div>

      {!limited ? null : tree.roots.length === 0 ? (
        <p className="text-sm text-muted-foreground">
          No permissions exist yet. Add one under Permissions.
        </p>
      ) : (
        <ul
          role="tree"
          aria-label="Permissions this application may request"
          className="flex min-w-0 flex-col"
        >
          {tree.roots.map((root, i) =>
            renderNode(root, 1, i, tree.roots.length),
          )}
        </ul>
      )}
    </AdminSection>
  );
}

/** An input with an Add button that stacks on narrow screens. */
function AddRow({
  placeholder,
  value,
  onChange,
  disabled,
  onAdd,
}: {
  placeholder: string;
  value: string;
  onChange: (value: string) => void;
  disabled: boolean;
  onAdd: () => void;
}) {
  return (
    <form
      className="flex flex-col gap-2 sm:flex-row"
      onSubmit={(e) => {
        e.preventDefault();
        if (value.trim()) onAdd();
      }}
    >
      <Input
        className="sm:flex-1"
        placeholder={placeholder}
        value={value}
        onChange={(e) => onChange(e.target.value)}
      />
      <Button type="submit" size="sm" disabled={disabled || !value.trim()}>
        Add
      </Button>
    </form>
  );
}

function AssignAudienceRow({
  options,
  value,
  onChange,
  disabled,
  onAssign,
}: {
  options: Audience[];
  value: string;
  onChange: (value: string) => void;
  disabled: boolean;
  onAssign: () => void;
}) {
  if (options.length === 0) {
    return (
      <p className="text-muted-foreground text-sm">
        No more registered audiences to assign. Register one under OAuth2
        audiences.
      </p>
    );
  }

  return (
    <form
      className="flex flex-col gap-2 sm:flex-row"
      onSubmit={(e) => {
        e.preventDefault();
        if (value) onAssign();
      }}
    >
      <Select
        value={value}
        onValueChange={(selected) => onChange(selected ?? "")}
      >
        <SelectTrigger className="sm:flex-1">
          <SelectValue placeholder="Select a registered audience" />
        </SelectTrigger>
        <SelectContent>
          {options.map((option) => (
            <SelectItem key={option.id} value={option.id}>
              {option.audience}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      <Button type="submit" size="sm" disabled={disabled || !value}>
        Assign
      </Button>
    </form>
  );
}
