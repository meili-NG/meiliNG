import { useEffect, useMemo, useState, type FormEvent } from "react"

import { SettingsRow, SettingsSection } from "@/components/dashboard-shell"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  InputGroup,
  InputGroupAddon,
  InputGroupInput,
  InputGroupText,
} from "@/components/ui/input-group"
import { Input } from "@/components/ui/input"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Skeleton } from "@/components/ui/skeleton"
import { ApiError, apiJson } from "@/lib/api"
import { authHeaders } from "@/lib/session"
import {
  getUser,
  getUserData,
  updateUserData,
  getEmails,
  getPhones,
  changeUsername,
  type UserSerialized,
  type UserData,
  type UserEmail,
  type UserPhone,
} from "@/lib/users"

type AccountViewProps = {
  userId: string
  onSignOut: () => void
  onManageContacts: () => void
}

const COMMON_TIMEZONES = [
  "Etc/UTC",
  "America/New_York",
  "America/Chicago",
  "America/Denver",
  "America/Los_Angeles",
  "America/Sao_Paulo",
  "Europe/London",
  "Europe/Paris",
  "Europe/Berlin",
  "Asia/Tokyo",
  "Asia/Seoul",
  "Asia/Shanghai",
  "Asia/Singapore",
  "Australia/Sydney",
]

export function AccountView({
  userId,
  onSignOut,
  onManageContacts,
}: AccountViewProps) {
  const [user, setUser] = useState<UserSerialized | null>(null)
  const [userData, setUserData] = useState<UserData>({})
  const [emails, setEmails] = useState<UserEmail[]>([])
  const [phones, setPhones] = useState<UserPhone[]>([])

  const [editName, setEditName] = useState("")
  const [editUsername, setEditUsername] = useState("")
  const [editTimezone, setEditTimezone] = useState("")
  const [editLanguage, setEditLanguage] = useState("")

  const [error, setError] = useState<string | null>(null)
  const [pending, setPending] = useState(false)
  const [confirmDelete, setConfirmDelete] = useState(false)

  const timezones = useMemo(() => {
    const detected =
      typeof Intl !== "undefined"
        ? Intl.DateTimeFormat().resolvedOptions().timeZone
        : undefined
    const all = new Set(COMMON_TIMEZONES)
    if (detected) all.add(detected)
    if (userData.timezone) all.add(userData.timezone)
    return Array.from(all).sort()
  }, [userData.timezone])

  useEffect(() => {
    Promise.all([
      getUser(userId),
      getUserData(userId),
      getEmails(userId),
      getPhones(userId),
    ]).then(([u, ud, em, ph]) => {
      setUser(u)
      setUserData(ud)
      setEditName(ud.name ?? "")
      setEditUsername(u.usernames[0] ?? "")
      setEditTimezone(ud.timezone ?? "")
      setEditLanguage(ud.language ?? "")
      setEmails(em)
      setPhones(ph)
    })
  }, [userId])

  async function saveProfile(event: FormEvent) {
    event.preventDefault()
    setError(null)
    setPending(true)
    try {
      if (editUsername && editUsername !== user?.usernames[0]) {
        await changeUsername(userId, editUsername)
        setUser((u) => (u ? { ...u, usernames: [editUsername] } : u))
      }
      await updateUserData(userId, {
        name: editName,
        timezone: editTimezone || undefined,
        language: editLanguage || undefined,
      })
      setUserData((d) => ({
        ...d,
        name: editName,
        timezone: editTimezone || undefined,
        language: editLanguage || undefined,
      }))
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed to save profile")
    } finally {
      setPending(false)
    }
  }

  async function onDeleteAccount() {
    setError(null)
    try {
      await apiJson<unknown>(`/v2/users/${userId}/`, {
        method: "DELETE",
        headers: authHeaders(),
      })
      onSignOut()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed to delete account")
    }
  }

  if (!user) {
    return (
      <div className="flex flex-col gap-4">
        <Skeleton className="h-16 w-full" />
        <Skeleton className="h-64 w-full" />
      </div>
    )
  }

  const profileDirty =
    editName !== (userData.name ?? "") ||
    editUsername !== (user.usernames[0] ?? "") ||
    editTimezone !== (userData.timezone ?? "") ||
    editLanguage !== (userData.language ?? "")

  return (
    <div className="flex flex-col gap-8">
      {error ? (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      ) : null}

      <div className="grid grid-cols-1 gap-8 md:grid-cols-2">
        <form className="flex flex-col gap-6" onSubmit={saveProfile}>
          <SettingsSection
            title="Profile"
            action={
              profileDirty ? (
                <Button type="submit" disabled={pending}>
                  {pending ? "Saving…" : "Save"}
                </Button>
              ) : null
            }
          >
            <SettingsRow label="Name">
              <Input
                id="profile-name"
                type="text"
                autoComplete="name"
                value={editName}
                onChange={(e) => setEditName(e.target.value)}
              />
            </SettingsRow>

            <SettingsRow label="Username">
              <InputGroup>
                <InputGroupAddon align="inline-start">
                  <InputGroupText>@</InputGroupText>
                </InputGroupAddon>
                <InputGroupInput
                  type="text"
                  autoComplete="username"
                  required
                  value={editUsername}
                  onChange={(e) => setEditUsername(e.target.value)}
                />
              </InputGroup>
            </SettingsRow>

            <SettingsRow label="Language">
              <Select
                value={editLanguage || undefined}
                onValueChange={(value) => setEditLanguage(value ?? "")}
              >
                <SelectTrigger className="w-full">
                  <SelectValue placeholder="Select language" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="en">English</SelectItem>
                  <SelectItem value="ko">한국어</SelectItem>
                  <SelectItem value="ja">日本語</SelectItem>
                  <SelectItem value="zh">中文</SelectItem>
                  <SelectItem value="es">Español</SelectItem>
                  <SelectItem value="de">Deutsch</SelectItem>
                  <SelectItem value="fr">Français</SelectItem>
                </SelectContent>
              </Select>
            </SettingsRow>

            <SettingsRow label="Time zone">
              <Select
                value={editTimezone || undefined}
                onValueChange={(value) => setEditTimezone(value ?? "")}
              >
                <SelectTrigger className="w-full">
                  <SelectValue placeholder="Select time zone" />
                </SelectTrigger>
                <SelectContent>
                  {timezones.map((tz) => (
                    <SelectItem key={tz} value={tz}>
                      {tz}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </SettingsRow>
          </SettingsSection>
        </form>

        <SettingsSection title="Contacts">
          <SettingsRow label="Emails">
            {emails.length > 0 ? (
              <ul className="flex flex-col gap-2">
                {emails.map((e) => (
                  <li
                    key={e.email}
                    className="flex min-w-0 flex-wrap items-center gap-2 text-sm"
                  >
                    <span className="truncate">{e.email}</span>
                    {e.verified ? (
                      <Badge variant="secondary">Verified</Badge>
                    ) : null}
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-sm text-muted-foreground">None</p>
            )}
          </SettingsRow>

          <SettingsRow label="Phones">
            {phones.length > 0 ? (
              <ul className="flex flex-col gap-2">
                {phones.map((p) => (
                  <li
                    key={p.phone}
                    className="flex min-w-0 flex-wrap items-center gap-2 text-sm"
                  >
                    <span className="truncate">{p.phone}</span>
                    {p.verified ? (
                      <Badge variant="secondary">Verified</Badge>
                    ) : null}
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-sm text-muted-foreground">None</p>
            )}
          </SettingsRow>

          <Button
            type="button"
            variant="outline"
            className="self-start"
            onClick={onManageContacts}
          >
            Manage contacts
          </Button>
        </SettingsSection>
      </div>

      <SettingsSection
        variant="destructive"
        title="Delete account"
        description="Permanently delete your account and associated data. This cannot be undone."
        action={
          confirmDelete ? (
            <div className="flex flex-wrap gap-2">
              <Button
                type="button"
                variant="ghost"
                onClick={() => setConfirmDelete(false)}
              >
                Cancel
              </Button>
              <Button
                type="button"
                variant="destructive"
                onClick={onDeleteAccount}
              >
                Confirm deletion
              </Button>
            </div>
          ) : (
            <Button
              type="button"
              variant="destructive"
              onClick={() => setConfirmDelete(true)}
            >
              Delete account
            </Button>
          )
        }
      />
    </div>
  )
}
