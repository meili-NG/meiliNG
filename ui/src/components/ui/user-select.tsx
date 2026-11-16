import { useCallback, useEffect, useRef, useState } from "react"
import { SearchIcon, XIcon } from "lucide-react"

import { Input } from "@/components/ui/input"
import { Spinner } from "@/components/ui/spinner"
import { listAllUsers } from "@/lib/admin"
import type { UserSerialized } from "@/lib/users"
import { cn } from "@/lib/utils"

/** A concise label for a user: username, else email, else short id. */
export function userLabel(user: UserSerialized): string {
  return user.usernames[0] || user.emails[0] || user.id.slice(0, 8)
}

type UserSelectProps = {
  /** Selected user id (controlled). */
  value: string
  onChange: (userId: string, user?: UserSerialized) => void
  placeholder?: string
  id?: string
}

/**
 * Searchable user picker. Instead of pasting a raw UUID, the admin types a
 * username/email/name; matches are queried live and shown in a dropdown. The
 * chosen user is surfaced as a chip and the underlying id is emitted via
 * onChange. autoComplete/data attributes suppress password-manager autofill,
 * which otherwise mistakes the field for a login.
 */
export function UserSelect({
  value,
  onChange,
  placeholder = "Search by username, email, or name",
  id,
}: UserSelectProps) {
  const [query, setQuery] = useState("")
  const [results, setResults] = useState<UserSerialized[]>([])
  const [selected, setSelected] = useState<UserSerialized | null>(null)
  const [open, setOpen] = useState(false)
  const [loading, setLoading] = useState(false)
  const [active, setActive] = useState(0)
  const containerRef = useRef<HTMLDivElement>(null)

  // Clear the local chip if the controlled value is reset externally.
  useEffect(() => {
    if (!value) setSelected(null)
  }, [value])

  // Debounced search. Empty query lists the first page so the dropdown is
  // useful immediately on focus.
  useEffect(() => {
    if (selected) return
    let cancelled = false
    setLoading(true)
    const handle = setTimeout(async () => {
      try {
        const res = await listAllUsers({
          search: query.trim() || undefined,
          page: 1,
          size: 8,
        })
        if (!cancelled) {
          setResults(res.data)
          setActive(0)
        }
      } catch {
        if (!cancelled) setResults([])
      } finally {
        if (!cancelled) setLoading(false)
      }
    }, 250)
    return () => {
      cancelled = true
      clearTimeout(handle)
    }
  }, [query, selected])

  // Close the dropdown on outside click.
  useEffect(() => {
    function onDocClick(e: MouseEvent) {
      if (!containerRef.current?.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener("mousedown", onDocClick)
    return () => document.removeEventListener("mousedown", onDocClick)
  }, [])

  const choose = useCallback(
    (user: UserSerialized) => {
      setSelected(user)
      setOpen(false)
      setQuery("")
      onChange(user.id, user)
    },
    [onChange],
  )

  const clear = useCallback(() => {
    setSelected(null)
    setQuery("")
    setOpen(true)
    onChange("")
  }, [onChange])

  if (selected) {
    return (
      <div className="flex items-center justify-between gap-2 rounded-md border border-border bg-muted/30 px-3 py-2">
        <div className="flex min-w-0 flex-col">
          <span className="truncate text-sm font-medium">
            {userLabel(selected)}
          </span>
          <span className="truncate font-mono text-xs text-muted-foreground">
            {selected.id}
          </span>
        </div>
        <button
          type="button"
          aria-label="Clear selection"
          className="shrink-0 rounded-sm text-muted-foreground transition-colors hover:text-foreground focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring"
          onClick={clear}
        >
          <XIcon className="size-4" />
        </button>
      </div>
    )
  }

  return (
    <div ref={containerRef} className="relative">
      <div className="relative">
        <SearchIcon className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-muted-foreground" />
        <Input
          id={id}
          type="text"
          role="combobox"
          aria-expanded={open}
          aria-autocomplete="list"
          autoComplete="off"
          autoCorrect="off"
          autoCapitalize="off"
          spellCheck={false}
          data-1p-ignore
          data-lpignore="true"
          className="pl-9"
          placeholder={placeholder}
          value={query}
          onChange={(e) => {
            setQuery(e.target.value)
            setOpen(true)
          }}
          onFocus={() => setOpen(true)}
          onKeyDown={(e) => {
            if (!open) return
            if (e.key === "ArrowDown") {
              e.preventDefault()
              setActive((a) => Math.min(a + 1, results.length - 1))
            } else if (e.key === "ArrowUp") {
              e.preventDefault()
              setActive((a) => Math.max(a - 1, 0))
            } else if (e.key === "Enter" && results[active]) {
              e.preventDefault()
              choose(results[active])
            } else if (e.key === "Escape") {
              setOpen(false)
            }
          }}
        />
      </div>
      {open ? (
        <div className="absolute z-50 mt-1 max-h-64 w-full overflow-auto rounded-md border border-border bg-popover p-1 shadow-md">
          {loading ? (
            <div className="flex items-center gap-2 px-2 py-3 text-sm text-muted-foreground">
              <Spinner className="size-4" />
              Searching…
            </div>
          ) : results.length === 0 ? (
            <div className="px-2 py-3 text-sm text-muted-foreground">
              No users found.
            </div>
          ) : (
            results.map((user, idx) => (
              <button
                key={user.id}
                type="button"
                className={cn(
                  "flex w-full flex-col items-start gap-0.5 rounded-sm px-2 py-1.5 text-left",
                  idx === active ? "bg-accent" : "hover:bg-accent/60",
                )}
                onMouseEnter={() => setActive(idx)}
                onClick={() => choose(user)}
              >
                <span className="text-sm font-medium">{userLabel(user)}</span>
                <span className="font-mono text-xs text-muted-foreground">
                  {user.emails[0] ? `${user.emails[0]} · ` : ""}
                  {user.id.slice(0, 8)}
                </span>
              </button>
            ))
          )}
        </div>
      ) : null}
    </div>
  )
}
