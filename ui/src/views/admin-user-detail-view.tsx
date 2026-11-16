import {
  useCallback,
  useEffect,
  useState,
  type FormEvent,
  type ReactNode,
} from "react"
import {
  ArrowLeftIcon,
  KeyRoundIcon,
  LockIcon,
  LockOpenIcon,
  LogOutIcon,
  ShieldOffIcon,
  Trash2Icon,
} from "lucide-react"

import {
  AdminField,
  AdminFieldGrid,
  AdminSection,
  AdminPageTabs,
} from "@/components/admin-panel"
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
import { Tabs, TabsContent } from "@/components/ui/tabs"
import { JsonEditor } from "@/components/ui/json-editor"
import { CopyableId } from "@/components/ui/copyable-id"
import { useToast } from "@/components/ui/toast"
import { ApiError } from "@/lib/api"
import {
  adminAddEmail,
  adminAddPhone,
  adminAddUsername,
  adminChangePassword,
  adminDeleteBackupCodes,
  adminDeleteUser,
  adminForceSignOut,
  adminGetBackupCodes,
  adminGetEmails,
  adminGetMetadata,
  adminGetPhones,
  adminGetSignInLogs,
  adminGetSignInStats,
  adminGetTOTPs,
  adminGetUser,
  adminGetUserData,
  adminGetUserDataLock,
  adminGetWebAuthn,
  adminListAuthorizedApps,
  adminListUserApplications,
  adminPutMetadata,
  adminRegenerateBackupCodes,
  adminRemoveEmail,
  adminRemovePhone,
  adminRemoveTOTP,
  adminRemoveUsername,
  adminRemoveWebAuthn,
  adminSetEmailVerified,
  adminSetPhoneVerified,
  adminSetUserDataLock,
  adminUnauthorizeApp,
  adminUpdateUser,
  adminUpdateUserData,
  type SignInCountryStat,
} from "@/lib/admin"
import { describeClient, formatLocation } from "@/lib/user-agent"
import type {
  SignInLog,
  TOTPEntry,
  UserData,
  UserEmail,
  UserPhone,
  UserSerialized,
  WebAuthnEntry,
} from "@/lib/users"
import type { Application } from "@/lib/applications"

type AdminUserDetailViewProps = {
  userId: string
  onBack: () => void
  onOpenApplication?: (appId: string) => void
}

/** Every profile field the API accepts a lock for. */
const PROFILE_FIELDS: {
  key: keyof UserData
  lockKey: string
  label: string
  placeholder?: string
  type?: "date"
}[] = [
  { key: "name", lockKey: "name", label: "Name" },
  { key: "displayName", lockKey: "display_name", label: "Display name" },
  { key: "firstName", lockKey: "first_name", label: "First name" },
  { key: "middleName", lockKey: "middle_name", label: "Middle name" },
  { key: "lastName", lockKey: "last_name", label: "Last name" },
  { key: "birthday", lockKey: "birthday", label: "Birthday", type: "date" },
  { key: "language", lockKey: "language", label: "Language", placeholder: "en" },
  { key: "timezone", lockKey: "timezone", label: "Timezone", placeholder: "UTC" },
]

/** Coerce the raw lock map (values may be nested/bool) into flat booleans. */
function normalizeLocks(raw: unknown): Record<string, boolean> {
  const out: Record<string, boolean> = {}
  if (raw && typeof raw === "object") {
    for (const [key, value] of Object.entries(raw as Record<string, unknown>)) {
      out[key] = value === true
    }
  }
  return out
}

function fmt(ts?: string) {
  if (!ts) return "—"
  try {
    return new Date(ts).toLocaleString()
  } catch {
    return ts
  }
}

/** One profile field with an inline lock toggle. */
function LockableField({
  label,
  locked,
  onToggleLock,
  disabled,
  children,
}: {
  label: string
  locked: boolean
  onToggleLock: () => void
  disabled?: boolean
  children: ReactNode
}) {
  return (
    <div className="flex min-w-0 flex-col gap-1">
      <div className="flex items-center justify-between gap-2">
        <span className="text-xs text-muted-foreground">{label}</span>
        <button
          type="button"
          disabled={disabled}
          onClick={onToggleLock}
          aria-pressed={locked}
          aria-label={locked ? `Unlock ${label}` : `Lock ${label}`}
          className={
            "inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-[11px] transition-colors disabled:opacity-50 " +
            (locked
              ? "text-amber-600 hover:bg-amber-500/10 dark:text-amber-500"
              : "text-muted-foreground hover:bg-muted")
          }
        >
          {locked ? (
            <LockIcon className="size-3" />
          ) : (
            <LockOpenIcon className="size-3" />
          )}
          {locked ? "Locked" : "Unlocked"}
        </button>
      </div>
      {children}
    </div>
  )
}

export function AdminUserDetailView({
  userId,
  onBack,
  onOpenApplication,
}: AdminUserDetailViewProps) {
  const { toast } = useToast()
  const [user, setUser] = useState<UserSerialized | null>(null)
  const [userData, setUserData] = useState<UserData>({})
  const [emails, setEmails] = useState<UserEmail[]>([])
  const [phones, setPhones] = useState<UserPhone[]>([])
  const [totps, setTotps] = useState<TOTPEntry[]>([])
  const [webauthn, setWebauthn] = useState<WebAuthnEntry[]>([])
  const [logs, setLogs] = useState<SignInLog[]>([])
  const [stats, setStats] = useState<SignInCountryStat[]>([])
  const [backupRemaining, setBackupRemaining] = useState(0)
  const [ownedApps, setOwnedApps] = useState<Application[]>([])
  const [authorizedApps, setAuthorizedApps] = useState<Application[]>([])
  const [metadataText, setMetadataText] = useState("{}")
  const [locks, setLocks] = useState<Record<string, boolean>>({})
  const [initialLocks, setInitialLocks] = useState<Record<string, unknown>>({})
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [actionError, setActionError] = useState<string | null>(null)
  const [pending, setPending] = useState(false)

  const [showEmail, setShowEmail] = useState(false)
  const [showPhone, setShowPhone] = useState(false)
  const [showPassword, setShowPassword] = useState(false)
  const [showDelete, setShowDelete] = useState(false)
  const [showResetTwoFactor, setShowResetTwoFactor] = useState(false)
  const [showSignOutAll, setShowSignOutAll] = useState(false)
  const [newEmail, setNewEmail] = useState("")
  const [newPhone, setNewPhone] = useState("")
  const [addUsername, setAddUsername] = useState("")
  const [newPassword, setNewPassword] = useState("")
  const [showBackupCodes, setShowBackupCodes] = useState(false)
  const [generatedCodes, setGeneratedCodes] = useState<string[] | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const [u, ud, em, ph, tp, wa, lg, cl, md, lock, st, bc, apps] =
        await Promise.all([
          adminGetUser(userId),
          adminGetUserData(userId).catch(() => ({}) as UserData),
          adminGetEmails(userId).catch(() => [] as UserEmail[]),
          adminGetPhones(userId).catch(() => [] as UserPhone[]),
          adminGetTOTPs(userId).catch(() => [] as TOTPEntry[]),
          adminGetWebAuthn(userId).catch(() => [] as WebAuthnEntry[]),
          adminGetSignInLogs(userId, { page: 1, size: 25 }).catch(() => ({
            data: [] as SignInLog[],
            total: 0,
            page: 1,
            size: 25,
          })),
          adminListUserApplications(userId).catch(() => [] as Application[]),
          adminGetMetadata(userId).catch(() => ({})),
          adminGetUserDataLock(userId).catch(() => ({})),
          adminGetSignInStats(userId).catch(() => [] as SignInCountryStat[]),
          adminGetBackupCodes(userId).catch(() => ({ remaining: 0 })),
          adminListAuthorizedApps(userId).catch(() => [] as Application[]),
        ])
      setUser(u)
      setUserData(ud)
      setEmails(em)
      setPhones(ph)
      setTotps(tp)
      setWebauthn(wa)
      setLogs(lg.data)
      setStats(st)
      setBackupRemaining(bc.remaining)
      setOwnedApps(cl)
      setAuthorizedApps(apps)
      setMetadataText(JSON.stringify(md, null, 2))
      setInitialLocks((lock ?? {}) as Record<string, unknown>)
      setLocks(normalizeLocks(lock))
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed to load user")
    } finally {
      setLoading(false)
    }
  }, [userId])

  useEffect(() => {
    void load()
  }, [load])

  async function run(fn: () => Promise<void>, successMessage?: string) {
    setPending(true)
    setActionError(null)
    try {
      await fn()
      await load()
      if (successMessage) {
        toast({ variant: "success", title: successMessage })
      }
    } catch (err) {
      const message = err instanceof ApiError ? err.message : "Action failed"
      setActionError(message)
      toast({ variant: "destructive", title: "Action failed", description: message })
    } finally {
      setPending(false)
    }
  }

  const locksChanged = PROFILE_FIELDS.some(
    (f) => Boolean(locks[f.lockKey]) !== (initialLocks[f.lockKey] === true),
  )

  async function saveProfile(event: FormEvent) {
    event.preventDefault()
    await run(async () => {
      await adminUpdateUserData(userId, userData)
      if (locksChanged) {
        await adminSetUserDataLock(
          userId,
          Object.fromEntries(
            PROFILE_FIELDS.filter((f) => locks[f.lockKey]).map((f) => [
              f.lockKey,
              true,
            ]),
          ),
        )
      }
    }, "Profile saved")
  }

  function toggleLock(lockKey: string) {
    setLocks((prev) => ({ ...prev, [lockKey]: !prev[lockKey] }))
  }

  // One-click account recovery: strip every second factor (authenticator apps
  // and passkeys) and turn 2FA off, so a locked-out user can sign in with just
  // their password. This is the common "lost my authenticator" support task,
  // which otherwise means visiting the Security tab and deleting each entry.
  async function resetTwoFactor() {
    await run(async () => {
      for (const t of totps) await adminRemoveTOTP(userId, t.id)
      for (const w of webauthn) await adminRemoveWebAuthn(userId, w.id)
      if (user?.twoFactorEnabled) {
        await adminUpdateUser(userId, { twoFactorEnabled: false })
      }
      setShowResetTwoFactor(false)
    }, "Two-factor reset")
  }

  // Regenerate backup codes and surface them once — they can't be retrieved
  // again after this, so the admin must hand them to the user now.
  async function regenerateBackupCodes() {
    setPending(true)
    setActionError(null)
    try {
      const { codes } = await adminRegenerateBackupCodes(userId)
      setGeneratedCodes(codes)
      await load()
    } catch (err) {
      setActionError(err instanceof ApiError ? err.message : "Action failed")
    } finally {
      setPending(false)
    }
  }

  const primaryEmail = emails.find((e) => e.verified) ?? emails[0]
  const authenticatorCount = totps.length + webauthn.length
  const activeSessions = logs.filter((l) => !l.signedOutAt).length
  const displayName =
    user?.userData?.name ||
    user?.usernames[0] ||
    primaryEmail?.email ||
    user?.id

  if (loading) {
    return (
      <div className="flex flex-col gap-3">
        <Skeleton className="h-8 w-48" />
        <Skeleton className="h-40 w-full" />
      </div>
    )
  }

  if (error || !user) {
    return (
      <div className="flex flex-col gap-4">
        <Button type="button" variant="ghost" className="w-fit px-0" onClick={onBack}>
          <ArrowLeftIcon data-icon="inline-start" />
          Users
        </Button>
        <Alert variant="destructive">
          <AlertTitle>Error</AlertTitle>
          <AlertDescription>{error ?? "User not found"}</AlertDescription>
        </Alert>
      </div>
    )
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
            Users
          </Button>
          <h1 className="text-xl font-semibold tracking-tight">
            {displayName}
          </h1>
          <div className="mt-1">
            <CopyableId value={user.id} />
          </div>
          <div className="mt-2 flex flex-wrap gap-2">
            {user.twoFactorEnabled ? (
              <Badge variant="secondary">2FA on</Badge>
            ) : (
              <Badge variant="outline">2FA off</Badge>
            )}
            {user.deletedAt ? (
              <Badge variant="destructive">Deleted</Badge>
            ) : null}
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
          Delete user
        </Button>
      </div>

      {actionError ? (
        <Alert variant="destructive">
          <AlertDescription>{actionError}</AlertDescription>
        </Alert>
      ) : null}

      <Tabs defaultValue="overview">
        <AdminPageTabs
          tabs={[
            { value: "overview", label: "Overview" },
            { value: "basic", label: "Profile" },
            { value: "contact", label: "Contact" },
            { value: "security", label: "Security" },
            { value: "activity", label: "Activity" },
            { value: "applications", label: "Applications" },
            { value: "metadata", label: "Metadata" },
          ]}
        />

        <TabsContent value="overview" className="mt-4">
          <div className="grid gap-8 lg:grid-cols-[1fr_18rem]">
          <AdminSection title="Status">
            <AdminFieldGrid columns={2}>
              <AdminField label="Username">
                {user.usernames[0] || "Not set"}
              </AdminField>
              <AdminField label="Primary email">
                {primaryEmail ? (
                  <span className="inline-flex items-center gap-2">
                    {primaryEmail.email}
                    {primaryEmail.verified ? (
                      <Badge variant="secondary">Verified</Badge>
                    ) : (
                      <Badge variant="warning">Unverified</Badge>
                    )}
                  </span>
                ) : (
                  "Not set"
                )}
              </AdminField>
              <AdminField label="Two-factor">
                {user.twoFactorEnabled ? (
                  <Badge variant="secondary">On</Badge>
                ) : (
                  <Badge variant="outline">Off</Badge>
                )}
              </AdminField>
              <AdminField label="Authenticators">
                {authenticatorCount
                  ? `${totps.length} TOTP, ${webauthn.length} passkey`
                  : "None"}
              </AdminField>
              <AdminField label="Backup codes">
                {backupRemaining > 0 ? `${backupRemaining} remaining` : "None"}
              </AdminField>
              <AdminField label="Active sessions">
                {String(activeSessions)}
              </AdminField>
              <AdminField label="Last sign-in">
                {fmt(logs[0]?.signedInAt)}
              </AdminField>
            </AdminFieldGrid>
          </AdminSection>

          <AdminSection
            title="Account recovery"
            description="Common support actions. Each confirms first."
          >
            <div className="flex flex-col gap-2">
              <Button
                type="button"
                variant="outline"
                size="sm"
                className="justify-start"
                onClick={() => setShowPassword(true)}
              >
                <KeyRoundIcon data-icon="inline-start" />
                Reset password
              </Button>
              <Button
                type="button"
                variant="outline"
                size="sm"
                className="justify-start"
                disabled={pending || (!user.twoFactorEnabled && authenticatorCount === 0)}
                onClick={() => setShowResetTwoFactor(true)}
              >
                <ShieldOffIcon data-icon="inline-start" />
                Reset 2FA
              </Button>
              <Button
                type="button"
                variant="outline"
                size="sm"
                className="justify-start"
                disabled={pending}
                onClick={() => {
                  setGeneratedCodes(null)
                  setShowBackupCodes(true)
                }}
              >
                <KeyRoundIcon data-icon="inline-start" />
                Regenerate backup codes
              </Button>
              <Button
                type="button"
                variant="outline"
                size="sm"
                className="justify-start"
                disabled={pending || activeSessions === 0}
                onClick={() => setShowSignOutAll(true)}
              >
                <LogOutIcon data-icon="inline-start" />
                Sign out all{activeSessions ? ` (${activeSessions})` : ""}
              </Button>
            </div>
          </AdminSection>
          </div>
        </TabsContent>

        <TabsContent value="basic" className="mt-4 grid items-start gap-8 lg:grid-cols-2">
          <AdminSection
            title="Profile"
            action={
              <Button
                type="submit"
                form="user-profile"
                size="sm"
                disabled={pending}
              >
                Save
              </Button>
            }
          >
            <form id="user-profile" onSubmit={saveProfile}>
              <AdminFieldGrid>
                {PROFILE_FIELDS.map((field) => {
                  const locked = Boolean(locks[field.lockKey])
                  return (
                    <LockableField
                      key={field.key}
                      label={field.label}
                      locked={locked}
                      disabled={pending}
                      onToggleLock={() => toggleLock(field.lockKey)}
                    >
                      <Input
                        type={field.type}
                        value={
                          field.type === "date"
                            ? (userData[field.key] ?? "").slice(0, 10)
                            : (userData[field.key] ?? "")
                        }
                        placeholder={field.placeholder}
                        onChange={(e) => {
                          const value = e.target.value
                          // The API takes a birthday as a timestamp and has no way to clear one.
                          const date = value ? `${value}T00:00:00Z` : undefined
                          setUserData((d) => ({
                            ...d,
                            [field.key]: field.type === "date" ? date : value,
                          }))
                        }}
                      />
                    </LockableField>
                  )
                })}
              </AdminFieldGrid>
              <p className="mt-3 text-xs text-muted-foreground">
                Locked fields can't be changed by the user themselves, only by
                an admin. Locking the name also locks the display name, which
                applications receive in its place.
              </p>
            </form>
          </AdminSection>

          <AdminSection
            title="Usernames"
            description="A user can hold more than one username; the first is primary."
          >
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Username</TableHead>
                  <TableHead className="w-20" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {user.usernames.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={2} className="text-muted-foreground">
                      No usernames.
                    </TableCell>
                  </TableRow>
                ) : (
                  user.usernames.map((uname, idx) => (
                    <TableRow key={uname}>
                      <TableCell className="font-medium">
                        {uname}
                        {idx === 0 ? (
                          <Badge variant="secondary" className="ml-2">
                            Primary
                          </Badge>
                        ) : null}
                      </TableCell>
                      <TableCell>
                        <Button
                          type="button"
                          variant="ghost"
                          size="sm"
                          disabled={pending || user.usernames.length <= 1}
                          onClick={() =>
                            void run(
                              () => adminRemoveUsername(userId, uname),
                              "Username removed",
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
            <form
              className="flex gap-2"
              onSubmit={(e) => {
                e.preventDefault()
                const value = addUsername.trim()
                if (!value) return
                void run(async () => {
                  await adminAddUsername(userId, value)
                  setAddUsername("")
                }, "Username added")
              }}
            >
              <Input
                placeholder="Add another username"
                value={addUsername}
                onChange={(e) => setAddUsername(e.target.value)}
              />
              <Button
                type="submit"
                variant="outline"
                disabled={pending || !addUsername.trim()}
              >
                Add
              </Button>
            </form>
          </AdminSection>
        </TabsContent>

        <TabsContent value="contact" className="mt-4 grid gap-8 lg:grid-cols-2">
          <AdminSection
            title="Emails"
            action={
              <Button
                type="button"
                size="sm"
                variant="outline"
                onClick={() => setShowEmail(true)}
              >
                Add email
              </Button>
            }
          >
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Email</TableHead>
                  <TableHead>Verified</TableHead>
                  <TableHead className="w-40" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {emails.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={3} className="text-muted-foreground">
                      No emails.
                    </TableCell>
                  </TableRow>
                ) : (
                  emails.map((item) => (
                    <TableRow key={item.email}>
                      <TableCell>{item.email}</TableCell>
                      <TableCell>
                        {item.verified ? (
                          <Badge variant="success">Verified</Badge>
                        ) : (
                          <Badge variant="warning">Unverified</Badge>
                        )}
                      </TableCell>
                      <TableCell>
                        <div className="flex justify-end gap-1">
                          <Button
                            type="button"
                            variant="ghost"
                            size="sm"
                            disabled={pending}
                            onClick={() =>
                              void run(
                                () =>
                                  adminSetEmailVerified(
                                    userId,
                                    item.email,
                                    !item.verified,
                                  ),
                                item.verified
                                  ? "Email marked unverified"
                                  : "Email marked verified",
                              )
                            }
                          >
                            {item.verified ? "Unverify" : "Verify"}
                          </Button>
                          <Button
                            type="button"
                            variant="ghost"
                            size="sm"
                            disabled={pending}
                            onClick={() =>
                              void run(
                                () => adminRemoveEmail(userId, item.email),
                                "Email removed",
                              )
                            }
                          >
                            Remove
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </AdminSection>

          <AdminSection
            title="Phones"
            action={
              <Button
                type="button"
                size="sm"
                variant="outline"
                onClick={() => setShowPhone(true)}
              >
                Add phone
              </Button>
            }
          >
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Phone</TableHead>
                  <TableHead>Verified</TableHead>
                  <TableHead className="w-40" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {phones.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={3} className="text-muted-foreground">
                      No phones.
                    </TableCell>
                  </TableRow>
                ) : (
                  phones.map((item) => (
                    <TableRow key={item.phone}>
                      <TableCell>{item.phone}</TableCell>
                      <TableCell>
                        {item.verified ? (
                          <Badge variant="success">Verified</Badge>
                        ) : (
                          <Badge variant="warning">Unverified</Badge>
                        )}
                      </TableCell>
                      <TableCell>
                        <div className="flex justify-end gap-1">
                          <Button
                            type="button"
                            variant="ghost"
                            size="sm"
                            disabled={pending}
                            onClick={() =>
                              void run(
                                () =>
                                  adminSetPhoneVerified(
                                    userId,
                                    item.phone,
                                    !item.verified,
                                  ),
                                item.verified
                                  ? "Phone marked unverified"
                                  : "Phone marked verified",
                              )
                            }
                          >
                            {item.verified ? "Unverify" : "Verify"}
                          </Button>
                          <Button
                            type="button"
                            variant="ghost"
                            size="sm"
                            disabled={pending}
                            onClick={() =>
                              void run(
                                () => adminRemovePhone(userId, item.phone),
                                "Phone removed",
                              )
                            }
                          >
                            Remove
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </AdminSection>
        </TabsContent>

        <TabsContent value="security" className="mt-4 flex flex-col gap-8">
          <AdminSection
            title="Two-factor"
            action={
              <div className="flex flex-wrap gap-2">
                <Button
                  type="button"
                  size="sm"
                  variant="outline"
                  disabled={pending}
                  onClick={() =>
                    void run(() =>
                      adminUpdateUser(userId, {
                        twoFactorEnabled: !user.twoFactorEnabled,
                      }),
                    )
                  }
                >
                  {user.twoFactorEnabled ? "Disable 2FA" : "Enable 2FA"}
                </Button>
                <Button
                  type="button"
                  size="sm"
                  variant="outline"
                  onClick={() => setShowPassword(true)}
                >
                  Set password
                </Button>
              </div>
            }
          >
            <AdminFieldGrid>
              <AdminField label="Status">
                {user.twoFactorEnabled ? "Enabled" : "Disabled"}
              </AdminField>
            </AdminFieldGrid>
          </AdminSection>

          <div className="grid gap-8 lg:grid-cols-2">
          <AdminSection title="TOTP">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Note</TableHead>
                  <TableHead>ID</TableHead>
                  <TableHead className="w-20" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {totps.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={3} className="text-muted-foreground">
                      None
                    </TableCell>
                  </TableRow>
                ) : (
                  totps.map((item) => (
                    <TableRow key={item.id}>
                      <TableCell>{item.note || "—"}</TableCell>
                      <TableCell>
                        <CopyableId value={item.id} truncate={12} />
                      </TableCell>
                      <TableCell>
                        <Button
                          type="button"
                          variant="ghost"
                          size="sm"
                          disabled={pending}
                          onClick={() =>
                            void run(() => adminRemoveTOTP(userId, item.id))
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

          <AdminSection title="Passkeys">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Note</TableHead>
                  <TableHead>ID</TableHead>
                  <TableHead className="w-20" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {webauthn.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={3} className="text-muted-foreground">
                      None
                    </TableCell>
                  </TableRow>
                ) : (
                  webauthn.map((item) => (
                    <TableRow key={item.id}>
                      <TableCell>{item.note || "—"}</TableCell>
                      <TableCell>
                        <CopyableId value={item.id} truncate={12} />
                      </TableCell>
                      <TableCell>
                        <Button
                          type="button"
                          variant="ghost"
                          size="sm"
                          disabled={pending}
                          onClick={() =>
                            void run(() =>
                              adminRemoveWebAuthn(userId, item.id),
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
          </div>

          <AdminSection
            title="Backup codes"
            description={
              backupRemaining > 0
                ? `${backupRemaining} unused code${backupRemaining === 1 ? "" : "s"} remaining.`
                : "No backup codes generated."
            }
            action={
              <div className="flex flex-wrap gap-2">
                <Button
                  type="button"
                  size="sm"
                  variant="outline"
                  disabled={pending}
                  onClick={() => {
                    setGeneratedCodes(null)
                    setShowBackupCodes(true)
                  }}
                >
                  Regenerate
                </Button>
                <Button
                  type="button"
                  size="sm"
                  variant="ghost"
                  disabled={pending || backupRemaining === 0}
                  onClick={() =>
                    void run(() => adminDeleteBackupCodes(userId))
                  }
                >
                  Clear
                </Button>
              </div>
            }
          >
            <p className="text-xs text-muted-foreground">
              Regenerating invalidates any existing codes and shows the new set
              once. Hand them to the user immediately.
            </p>
          </AdminSection>
        </TabsContent>

        <TabsContent value="activity" className="mt-4 flex flex-col gap-8">
          <AdminSection
            title="Sign-in history"
            action={
              <Button
                type="button"
                size="sm"
                variant="outline"
                disabled={pending || activeSessions === 0}
                onClick={() => setShowSignOutAll(true)}
              >
                Sign out all
              </Button>
            }
          >
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Status</TableHead>
                  <TableHead>Signed in</TableHead>
                  <TableHead>Client</TableHead>
                  <TableHead>IP</TableHead>
                  <TableHead>Location</TableHead>
                  <TableHead className="w-24" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {logs.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={6} className="text-muted-foreground">
                      No sessions.
                    </TableCell>
                  </TableRow>
                ) : (
                  logs.map((log) => {
                    const client = describeClient(log.userAgent)
                    const active = !log.signedOutAt
                    return (
                      <TableRow key={log.id}>
                        <TableCell>
                          <Badge variant={active ? "secondary" : "outline"}>
                            {active ? "Active" : "Ended"}
                          </Badge>
                        </TableCell>
                        <TableCell className="whitespace-nowrap">
                          {fmt(log.signedInAt)}
                        </TableCell>
                        <TableCell>{client.label}</TableCell>
                        <TableCell className="font-mono text-xs">
                          {log.ip || "—"}
                        </TableCell>
                        <TableCell>{formatLocation(log) || "—"}</TableCell>
                        <TableCell>
                          {active ? (
                            <Button
                              type="button"
                              size="sm"
                              variant="ghost"
                              disabled={pending}
                              onClick={() =>
                                void run(() =>
                                  adminForceSignOut(userId, log.id),
                                )
                              }
                            >
                              Sign out
                            </Button>
                          ) : null}
                        </TableCell>
                      </TableRow>
                    )
                  })
                )}
              </TableBody>
            </Table>
          </AdminSection>

          {stats.length > 0 ? (
            <AdminSection
              title="Sign-ins by country"
              description="Where this account has signed in from."
            >
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Country</TableHead>
                    <TableHead className="w-24 text-right">Sign-ins</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {stats.map((s) => (
                    <TableRow key={s.countryCode || s.country}>
                      <TableCell>
                        {s.country}
                        {s.countryCode ? (
                          <span className="ml-2 font-mono text-xs text-muted-foreground">
                            {s.countryCode}
                          </span>
                        ) : null}
                      </TableCell>
                      <TableCell className="text-right tabular-nums">
                        {s.count}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </AdminSection>
          ) : null}
        </TabsContent>

        <TabsContent
          value="applications"
          className="mt-4 grid gap-8 lg:grid-cols-2"
        >
          <AdminSection
            title="Owned applications"
            description="Applications this user created and administers."
          >
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>ID</TableHead>
                  <TableHead className="w-20" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {ownedApps.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={3} className="text-muted-foreground">
                      No applications.
                    </TableCell>
                  </TableRow>
                ) : (
                  ownedApps.map((app) => (
                    <TableRow key={app.id}>
                      <TableCell className="font-medium">{app.name}</TableCell>
                      <TableCell>
                        <CopyableId value={app.id} truncate={12} />
                      </TableCell>
                      <TableCell>
                        {onOpenApplication ? (
                          <Button
                            type="button"
                            variant="ghost"
                            size="sm"
                            onClick={() => onOpenApplication(app.id)}
                          >
                            Open
                          </Button>
                        ) : null}
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </AdminSection>

          <AdminSection
            title="Authorized applications"
            description="Third-party applications this user has granted access to."
          >
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>ID</TableHead>
                  <TableHead className="w-24" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {authorizedApps.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={3} className="text-muted-foreground">
                      No authorized applications.
                    </TableCell>
                  </TableRow>
                ) : (
                  authorizedApps.map((app) => (
                    <TableRow key={app.id}>
                      <TableCell className="font-medium">{app.name}</TableCell>
                      <TableCell>
                        <CopyableId value={app.id} truncate={12} />
                      </TableCell>
                      <TableCell>
                        <Button
                          type="button"
                          variant="ghost"
                          size="sm"
                          disabled={pending}
                          onClick={() =>
                            void run(
                              () => adminUnauthorizeApp(app.id, userId),
                              `Revoked access for ${app.name}`,
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
        </TabsContent>

        <TabsContent value="metadata" className="mt-4">
          <AdminSection
            title="Metadata"
            description="Admin-only user metadata JSON."
            action={
              <Button
                type="button"
                size="sm"
                disabled={pending}
                onClick={() =>
                  void run(async () => {
                    const parsed = JSON.parse(metadataText) as Record<
                      string,
                      unknown
                    >
                    await adminPutMetadata(userId, parsed)
                  }, "Metadata saved")
                }
              >
                Save
              </Button>
            }
          >
            <JsonEditor
              value={metadataText}
              onChange={setMetadataText}
              height={320}
              aria-label="User metadata JSON"
            />
          </AdminSection>
        </TabsContent>
      </Tabs>

      <Dialog open={showEmail} onOpenChange={setShowEmail}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Add email</DialogTitle>
          </DialogHeader>
          <Field>
            <FieldLabel>Email</FieldLabel>
            <Input
              type="email"
              value={newEmail}
              onChange={(e) => setNewEmail(e.target.value)}
            />
          </Field>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => setShowEmail(false)}>
              Cancel
            </Button>
            <Button
              type="button"
              disabled={pending || !newEmail}
              onClick={() =>
                void run(async () => {
                  await adminAddEmail(userId, newEmail, true)
                  setShowEmail(false)
                  setNewEmail("")
                })
              }
            >
              Add
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={showPhone} onOpenChange={setShowPhone}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Add phone</DialogTitle>
          </DialogHeader>
          <Field>
            <FieldLabel>Phone</FieldLabel>
            <Input
              value={newPhone}
              onChange={(e) => setNewPhone(e.target.value)}
            />
          </Field>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => setShowPhone(false)}>
              Cancel
            </Button>
            <Button
              type="button"
              disabled={pending || !newPhone}
              onClick={() =>
                void run(async () => {
                  await adminAddPhone(userId, newPhone, true)
                  setShowPhone(false)
                  setNewPhone("")
                })
              }
            >
              Add
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={showPassword} onOpenChange={setShowPassword}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Set password</DialogTitle>
            <DialogDescription>
              Immediately sets a new password for this user.
            </DialogDescription>
          </DialogHeader>
          <Field>
            <FieldLabel>New password</FieldLabel>
            <Input
              type="password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
            />
          </Field>
          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => setShowPassword(false)}
            >
              Cancel
            </Button>
            <Button
              type="button"
              disabled={pending || !newPassword}
              onClick={() =>
                void run(async () => {
                  await adminChangePassword(userId, newPassword)
                  setShowPassword(false)
                  setNewPassword("")
                }, "Password reset")
              }
            >
              Save
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={showResetTwoFactor} onOpenChange={setShowResetTwoFactor}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Reset two-factor?</DialogTitle>
            <DialogDescription>
              Removes {totps.length} authenticator app
              {totps.length === 1 ? "" : "s"} and {webauthn.length} passkey
              {webauthn.length === 1 ? "" : "s"}, and turns 2FA off. The user
              will be able to sign in with just their password. Use this when
              they've lost their authenticator.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => setShowResetTwoFactor(false)}
            >
              Cancel
            </Button>
            <Button
              type="button"
              variant="destructive"
              disabled={pending}
              onClick={() => void resetTwoFactor()}
            >
              Reset 2FA
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog
        open={showBackupCodes}
        onOpenChange={(open) => {
          setShowBackupCodes(open)
          if (!open) setGeneratedCodes(null)
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {generatedCodes ? "New backup codes" : "Regenerate backup codes?"}
            </DialogTitle>
            <DialogDescription>
              {generatedCodes
                ? "Copy these now — they won't be shown again. Any previous codes no longer work."
                : "This invalidates any existing backup codes and generates a new set. The codes are shown once."}
            </DialogDescription>
          </DialogHeader>
          {generatedCodes ? (
            <div className="grid grid-cols-2 gap-2 rounded-md border border-border bg-muted/20 p-3 font-mono text-sm">
              {generatedCodes.map((code) => (
                <span key={code}>{code}</span>
              ))}
            </div>
          ) : null}
          <DialogFooter>
            {generatedCodes ? (
              <Button
                type="button"
                onClick={() => {
                  setShowBackupCodes(false)
                  setGeneratedCodes(null)
                }}
              >
                Done
              </Button>
            ) : (
              <>
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => setShowBackupCodes(false)}
                >
                  Cancel
                </Button>
                <Button
                  type="button"
                  disabled={pending}
                  onClick={() => void regenerateBackupCodes()}
                >
                  Regenerate
                </Button>
              </>
            )}
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={showSignOutAll} onOpenChange={setShowSignOutAll}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Sign out all sessions?</DialogTitle>
            <DialogDescription>
              Ends all {activeSessions} active session
              {activeSessions === 1 ? "" : "s"} for this user. They'll need to
              sign in again everywhere.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => setShowSignOutAll(false)}
            >
              Cancel
            </Button>
            <Button
              type="button"
              variant="destructive"
              disabled={pending}
              onClick={() =>
                void run(async () => {
                  await adminForceSignOut(userId)
                  setShowSignOutAll(false)
                }, "Signed out all sessions")
              }
            >
              Sign out all
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={showDelete} onOpenChange={setShowDelete}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete user?</DialogTitle>
            <DialogDescription>
              This soft-deletes the account. This action cannot be undone from
              the UI.
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
                  await adminDeleteUser(userId)
                  onBack()
                })
              }
            >
              Delete
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
