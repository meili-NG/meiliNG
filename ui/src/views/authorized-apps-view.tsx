import { useEffect, useState } from "react"
import { LayoutGridIcon } from "lucide-react"

import { EmptyState } from "@/components/app-shell"
import { Button } from "@/components/ui/button"
import { apiJson } from "@/lib/api"
import { appPath, type Application } from "@/lib/applications"
import { authHeaders } from "@/lib/session"

type AuthorizedAppsViewProps = {
  userId: string
}

export function AuthorizedAppsView({ userId }: AuthorizedAppsViewProps) {
  const [apps, setApps] = useState<Application[]>([])

  useEffect(() => {
    apiJson<{ data: Application[] }>(
      `/v2/apps/?authorized=true&user_id=${encodeURIComponent(userId)}`,
      { headers: authHeaders() },
    )
      .then((r) => setApps(r.data))
      .catch(() => {})
  }, [userId])

  async function onRevoke(appId: string) {
    await apiJson<unknown>(
      appPath(appId, `unauthorize?user_id=${encodeURIComponent(userId)}`),
      { method: "POST", headers: authHeaders() },
    )
    setApps((prev) => prev.filter((a) => a.id !== appId))
  }

  if (apps.length === 0) {
    return (
      <EmptyState
        icon={LayoutGridIcon}
        title="No authorized applications"
        description="Applications you allow to access your account will show up here, and you can revoke them at any time."
      />
    )
  }

  return (
    <ul className="flex flex-col divide-y rounded-lg border">
      {apps.map((app) => (
        <li
          key={app.id}
          className="flex items-center justify-between gap-4 px-4 py-3"
        >
          <div className="flex min-w-0 flex-col gap-1">
            <span className="truncate text-sm font-medium">{app.name}</span>
            <span className="truncate font-mono text-xs text-muted-foreground">
              {app.id}
            </span>
          </div>
          <Button
            type="button"
            variant="outline"
            size="sm"
            className="shrink-0 text-destructive hover:text-destructive"
            onClick={() => onRevoke(app.id)}
          >
            Revoke
          </Button>
        </li>
      ))}
    </ul>
  )
}
