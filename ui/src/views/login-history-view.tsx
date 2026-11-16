import { useEffect, useState } from "react"
import {
  ChevronLeftIcon,
  ChevronRightIcon,
  HelpCircleIcon,
  MonitorIcon,
  SmartphoneIcon,
  TabletIcon,
} from "lucide-react"

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
import { Skeleton } from "@/components/ui/skeleton"
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip"
import { ApiError } from "@/lib/api"
import {
  describeClient,
  formatDateTime,
  formatLocation,
  type DeviceKind,
} from "@/lib/user-agent"
import {
  forceSignOut,
  getSignInLogs,
  type SignInLog,
} from "@/lib/users"

type LoginHistoryViewProps = {
  userId: string
}

const PAGE_SIZE = 25

function DeviceIcon({ kind }: { kind: DeviceKind }) {
  const className = "size-4 text-muted-foreground"
  switch (kind) {
    case "mobile":
      return <SmartphoneIcon className={className} aria-hidden />
    case "tablet":
      return <TabletIcon className={className} aria-hidden />
    case "desktop":
      return <MonitorIcon className={className} aria-hidden />
    default:
      return <HelpCircleIcon className={className} aria-hidden />
  }
}

function MetaLine({ log }: { log: SignInLog }) {
  const location = formatLocation(log)
  const bits = [
    formatDateTime(log.signedInAt),
    log.ip || null,
    location !== "—" ? location : null,
  ].filter(Boolean)

  return (
    <p className="truncate text-xs text-muted-foreground">{bits.join(" · ")}</p>
  )
}

export function LoginHistoryView({ userId }: LoginHistoryViewProps) {
  const [logs, setLogs] = useState<SignInLog[]>([])
  const [page, setPage] = useState(1)
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [pendingId, setPendingId] = useState<string | "all" | null>(null)
  const [signOutAllOpen, setSignOutAllOpen] = useState(false)

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE))

  useEffect(() => {
    setLoading(true)
    setError(null)
    getSignInLogs(userId, { page, size: PAGE_SIZE })
      .then((result) => {
        setLogs(result.data)
        setTotal(result.total)
      })
      .catch((err) =>
        setError(
          err instanceof ApiError ? err.message : "Failed to load login history",
        ),
      )
      .finally(() => setLoading(false))
  }, [userId, page])

  async function revoke(logId?: string) {
    setPendingId(logId ?? "all")
    setError(null)
    try {
      await forceSignOut(userId, logId)
      const result = await getSignInLogs(userId, { page, size: PAGE_SIZE })
      setLogs(result.data)
      setTotal(result.total)
      if (!logId) setSignOutAllOpen(false)
    } catch (err) {
      setError(
        err instanceof ApiError ? err.message : "Failed to sign out session",
      )
    } finally {
      setPendingId(null)
    }
  }

  if (loading) {
    return (
      <div className="flex flex-col divide-y divide-border">
        {Array.from({ length: 5 }).map((_, i) => (
          <div key={i} className="flex items-start gap-3 py-4">
            <Skeleton className="size-10 shrink-0 rounded-lg" />
            <div className="flex flex-1 flex-col gap-2">
              <Skeleton className="h-4 w-48" />
              <Skeleton className="h-3 w-72" />
              <Skeleton className="h-3 w-56" />
            </div>
          </div>
        ))}
      </div>
    )
  }

  if (error && logs.length === 0) {
    return (
      <Alert variant="destructive">
        <AlertDescription>{error}</AlertDescription>
      </Alert>
    )
  }

  if (logs.length === 0) {
    return <p className="text-sm text-muted-foreground">No login history.</p>
  }

  return (
    <div className="flex flex-col gap-4">
      {error ? (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      ) : null}

      <div className="flex justify-end">
        <Button
          type="button"
          variant="outline"
          size="sm"
          className="border-destructive/40 text-destructive hover:bg-destructive/10 hover:text-destructive"
          onClick={() => setSignOutAllOpen(true)}
        >
          Sign out all
        </Button>
      </div>

      <TooltipProvider delay={150}>
        <ul className="flex flex-col divide-y divide-border">
          {logs.map((log) => {
            const client = describeClient(log.userAgent)
            const active = !log.signedOutAt

            return (
              <li
                key={log.id}
                className="flex items-start gap-3 py-4 first:pt-0 last:pb-0"
              >
                <div className="flex size-10 shrink-0 items-center justify-center rounded-lg bg-muted">
                  <DeviceIcon kind={client.device} />
                </div>

                <div className="flex min-w-0 flex-1 flex-col gap-1.5">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="truncate text-sm font-medium">
                      {client.label}
                    </span>
                    {active ? (
                      <Badge variant="secondary">Active</Badge>
                    ) : (
                      <Badge variant="outline">Ended</Badge>
                    )}
                  </div>

                  <MetaLine log={log} />

                  <div className="flex flex-wrap gap-x-3 gap-y-1 text-xs text-muted-foreground">
                    {log.signedOutAt ? (
                      <span>Signed out {formatDateTime(log.signedOutAt)}</span>
                    ) : null}
                    {log.expiresAt ? (
                      <span>Expires {formatDateTime(log.expiresAt)}</span>
                    ) : null}
                    {log.userAgent ? (
                      <Tooltip>
                        <TooltipTrigger
                          render={
                            <button
                              type="button"
                              className="max-w-full truncate text-left underline-offset-2 hover:underline"
                            />
                          }
                        >
                          {client.summary}
                        </TooltipTrigger>
                        <TooltipContent side="bottom" className="max-w-sm">
                          <span className="block break-all text-left text-[11px] leading-snug">
                            {log.userAgent}
                          </span>
                        </TooltipContent>
                      </Tooltip>
                    ) : null}
                  </div>
                </div>

                {active ? (
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    className="shrink-0"
                    disabled={pendingId === log.id}
                    onClick={() => revoke(log.id)}
                  >
                    {pendingId === log.id ? "…" : "Sign out"}
                  </Button>
                ) : null}
              </li>
            )
          })}
        </ul>
      </TooltipProvider>

      {totalPages > 1 ? (
        <div className="flex flex-col items-center justify-between gap-3 sm:flex-row">
          <p className="text-sm text-muted-foreground">
            Page {page} of {totalPages}
          </p>
          <div className="flex items-center gap-1">
            <Button
              type="button"
              variant="outline"
              size="icon-sm"
              disabled={page <= 1}
              aria-label="Previous page"
              onClick={() => setPage((p) => Math.max(1, p - 1))}
            >
              <ChevronLeftIcon />
            </Button>
            <Button
              type="button"
              variant="outline"
              size="icon-sm"
              disabled={page >= totalPages}
              aria-label="Next page"
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
            >
              <ChevronRightIcon />
            </Button>
          </div>
        </div>
      ) : null}

      <Dialog open={signOutAllOpen} onOpenChange={setSignOutAllOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Sign out all sessions</DialogTitle>
            <DialogDescription>
              This ends every active session for this account, including this
              one.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => setSignOutAllOpen(false)}
              disabled={pendingId === "all"}
            >
              Cancel
            </Button>
            <Button
              type="button"
              variant="destructive"
              disabled={pendingId === "all"}
              onClick={() => revoke()}
            >
              {pendingId === "all" ? "Signing out…" : "Sign out all"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
