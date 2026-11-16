import { useCallback, useEffect, useState, type ReactNode } from "react"
import {
  AppWindowIcon,
  BugIcon,
  KeySquareIcon,
  LogOutIcon,
  ServerIcon,
  UsersIcon,
} from "lucide-react"

import { TooltipProvider } from "@/components/ui/tooltip"
import { ToastProvider } from "@/components/ui/toast"
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarInset,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarProvider,
  SidebarRail,
} from "@/components/ui/sidebar"
import {
  InstanceMark,
  MobileTopBar,
  SidebarNavButton,
} from "@/components/app-shell"
import { fetchInstanceName } from "@/lib/branding"
import { verifyAdminAuth } from "@/lib/admin"
import {
  clearAdminAuth,
  getAdminAuth,
} from "@/lib/admin-session"
import {
  adminPanelPath,
  adminScreenPath,
  isAdminSignInRoute,
  parseAdminRoute,
} from "@/lib/paths"
import { AdminApplicationsView } from "@/views/admin-applications-view"
import { AdminAudiencesView } from "@/views/admin-audiences-view"
import { AdminGateView } from "@/views/admin-gate-view"
import { AdminPermissionsView } from "@/views/admin-permissions-view"
import { AdminTokenDebugView } from "@/views/admin-token-debug-view"
import { AdminUserDetailView } from "@/views/admin-user-detail-view"
import { AdminUsersView } from "@/views/admin-users-view"

export type AdminScreen =
  | "users"
  | "permissions"
  | "apps"
  | "audiences"
  | "token-debug"

const NAV: {
  id: AdminScreen
  label: string
  icon: typeof UsersIcon
}[] = [
  { id: "users", label: "Users", icon: UsersIcon },
  { id: "permissions", label: "Permissions", icon: KeySquareIcon },
  { id: "apps", label: "Applications", icon: AppWindowIcon },
  { id: "audiences", label: "OAuth2 audiences", icon: ServerIcon },
  { id: "token-debug", label: "Token debug", icon: BugIcon },
]

function AdminShell({
  instanceName,
  active,
  onNav,
  onLeave,
  children,
}: {
  instanceName: string
  active: AdminScreen
  onNav: (screen: AdminScreen) => void
  onLeave: () => void
  children: ReactNode
}) {
  return (
    <SidebarProvider>
      <Sidebar collapsible="icon">
        <SidebarHeader>
          <SidebarMenu>
            <SidebarMenuItem>
              <SidebarMenuButton size="lg" tooltip={instanceName}>
                <InstanceMark />
                <div className="grid flex-1 text-left text-sm leading-tight">
                  <span className="truncate font-medium">{instanceName}</span>
                  <span className="truncate text-xs text-muted-foreground">
                    Admin
                  </span>
                </div>
              </SidebarMenuButton>
            </SidebarMenuItem>
          </SidebarMenu>
        </SidebarHeader>

        <SidebarContent>
          <SidebarGroup>
            <SidebarGroupLabel>Administration</SidebarGroupLabel>
            <SidebarGroupContent>
              <SidebarMenu>
                {NAV.map((item) => (
                  <SidebarMenuItem key={item.id}>
                    <SidebarNavButton
                      isActive={active === item.id}
                      tooltip={item.label}
                      onClick={() => onNav(item.id)}
                    >
                      <item.icon />
                      <span>{item.label}</span>
                    </SidebarNavButton>
                  </SidebarMenuItem>
                ))}
              </SidebarMenu>
            </SidebarGroupContent>
          </SidebarGroup>
        </SidebarContent>

        <SidebarFooter>
          <SidebarMenu>
            <SidebarMenuItem>
              <SidebarMenuButton tooltip="Leave admin" onClick={onLeave}>
                <LogOutIcon />
                <span>Leave admin</span>
              </SidebarMenuButton>
            </SidebarMenuItem>
          </SidebarMenu>
        </SidebarFooter>
        <SidebarRail />
      </Sidebar>

      <SidebarInset>
        <MobileTopBar instanceName={instanceName} subtitle="Admin" />
        <div className="mx-auto flex w-full max-w-7xl flex-1 flex-col gap-6 px-4 pt-6 pb-12 md:px-8 md:pt-8">
          {children}
        </div>
      </SidebarInset>
    </SidebarProvider>
  )
}

export function AdminApp() {
  const [instanceName, setInstanceName] = useState("meiliNG")
  const [ready, setReady] = useState(false)
  const [authed, setAuthed] = useState(false)
  // The current screen and any selected detail id are derived from the URL, so
  // each admin page is deep-linkable and back/forward works. `route` is kept in
  // sync with window.location via pushState (navigation) and popstate.
  const [route, setRoute] = useState(() => parseAdminRoute())
  const { screen, userId: selectedUserId, appId: selectedAppId } = route

  useEffect(() => {
    const onPop = () => setRoute(parseAdminRoute())
    window.addEventListener("popstate", onPop)
    return () => window.removeEventListener("popstate", onPop)
  }, [])

  useEffect(() => {
    fetchInstanceName()
      .then((name) => {
        setInstanceName(name)
        document.title = `${name} Admin`
      })
      .catch(() => {
        document.title = "meiliNG Admin"
      })
  }, [])

  useEffect(() => {
    let cancelled = false
    ;(async () => {
      if (getAdminAuth() && (await verifyAdminAuth())) {
        if (!cancelled) {
          setAuthed(true)
          setReady(true)
        }
        return
      }

      if (!cancelled) {
        setAuthed(false)
        setReady(true)
      }
    })()
    return () => {
      cancelled = true
    }
  }, [])

  // Navigate to an admin URL via pushState and sync local route state, so the
  // address bar reflects the page without a full reload.
  const navigate = useCallback(
    (screen: AdminScreen, id?: string | null, replace = false) => {
      const path = adminScreenPath(screen, id)
      if (replace) history.replaceState(null, "", path)
      else history.pushState(null, "", path)
      setRoute(parseAdminRoute())
    },
    [],
  )

  const handleAuthed = useCallback(() => {
    // The sign-in link lives at …/admin/signin; once authenticated, replace it
    // with the resolved screen URL so a reload lands on the panel, not the gate.
    if (isAdminSignInRoute()) {
      history.replaceState(null, "", adminScreenPath(parseAdminRoute().screen))
      setRoute(parseAdminRoute())
    }
    setAuthed(true)
  }, [])

  const handleLeave = useCallback(() => {
    clearAdminAuth()
    setAuthed(false)
    if (isAdminSignInRoute()) {
      history.replaceState(null, "", adminPanelPath())
    }
  }, [])

  const handleNav = useCallback(
    (next: AdminScreen) => navigate(next),
    [navigate],
  )

  if (!ready) return null

  if (!authed) {
    return (
      <ToastProvider>
        <AdminGateView instanceName={instanceName} onAuthed={handleAuthed} />
      </ToastProvider>
    )
  }

  return (
    <ToastProvider>
    <TooltipProvider>
      <AdminShell
        instanceName={instanceName}
        active={screen}
        onNav={handleNav}
        onLeave={handleLeave}
      >
        {screen === "users" ? (
          selectedUserId ? (
            <AdminUserDetailView
              userId={selectedUserId}
              onBack={() => navigate("users")}
              onOpenApplication={(appId) => navigate("apps", appId)}
            />
          ) : (
            <AdminUsersView
              onSelectUser={(id) => navigate("users", id)}
            />
          )
        ) : null}
        {screen === "permissions" ? <AdminPermissionsView /> : null}
        {screen === "apps" ? (
          <AdminApplicationsView
            selectedAppId={selectedAppId}
            onSelectApp={(id) => navigate("apps", id)}
          />
        ) : null}
        {screen === "audiences" ? <AdminAudiencesView /> : null}
        {screen === "token-debug" ? <AdminTokenDebugView /> : null}
      </AdminShell>
    </TooltipProvider>
    </ToastProvider>
  )
}
