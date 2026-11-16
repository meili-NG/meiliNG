import { useCallback, useEffect, useState, type ReactNode } from "react"

import {
  DashboardShell,
  type DashboardScreen,
  type SessionAccount,
} from "@/components/dashboard-shell"
import { TooltipProvider } from "@/components/ui/tooltip"
import { fetchInstanceName } from "@/lib/branding"
import { isAdminRoute } from "@/lib/paths"
import {
  ensureSession,
  clearToken,
  createSession,
  signOut,
  getToken,
  validateSession,
} from "@/lib/session"
import { listSessionUsers, type UserSerialized } from "@/lib/users"

import { ForgotPasswordView } from "@/views/forgot-password-view"
import { SignInView } from "@/views/sign-in-view"
import { SignUpView } from "@/views/sign-up-view"
import { SignOutView } from "@/views/sign-out-view"
import { EndSessionView } from "@/views/end-session-view"
import { AccountView } from "@/views/account-view"
import { ContactsView } from "@/views/contacts-view"
import { SecurityView } from "@/views/security-view"
import { LoginHistoryView } from "@/views/login-history-view"
import { ApplicationsView } from "@/views/applications-view"
import { AuthorizedAppsView } from "@/views/authorized-apps-view"
import { OAuth2ConsentView } from "@/views/oauth2-consent-view"
import { AdminApp } from "@/views/admin-app"

type Screen =
  | "sign-in"
  | "sign-up"
  | "forgot-password"
  | "sign-out"
  | "end-session"
  | DashboardScreen
  | "oauth2-consent"

const DASHBOARD_SCREENS = new Set<Screen>([
  "account",
  "contacts",
  "security",
  "login-history",
  "authorized-apps",
  "apps",
])

function accountLabel(user: UserSerialized): string {
  return (
    user.usernames[0] ||
    user.emails[0] ||
    user.userData?.name ||
    user.id.slice(0, 8)
  )
}

export default function App() {
  if (isAdminRoute()) {
    return <AdminApp />
  }

  return <AccountApp />
}

function AccountApp() {
  const [screen, setScreen] = useState<Screen>("sign-in")
  const [instanceName, setInstanceName] = useState("meiliNG")
  const [userId, setUserId] = useState<string | null>(null)
  const [accounts, setAccounts] = useState<SessionAccount[]>([])
  const [headerAction, setHeaderAction] = useState<ReactNode>(null)
  const [ready, setReady] = useState(false)
  const [prefillEmail, setPrefillEmail] = useState<string | undefined>()

  useEffect(() => {
    fetchInstanceName()
      .then((name) => {
        setInstanceName(name)
        document.title = name
      })
      .catch(() => {
        document.title = "meiliNG"
      })
  }, [])

  const refreshAccounts = useCallback(async (preferUserId?: string | null) => {
    const users = await listSessionUsers()
    const nextAccounts = users.map((u) => ({
      id: u.id,
      label: accountLabel(u),
    }))
    setAccounts(nextAccounts)

    if (nextAccounts.length === 0) {
      setUserId(null)
      return null
    }

    const preferred =
      (preferUserId &&
        nextAccounts.find((a) => a.id === preferUserId)?.id) ||
      (userId && nextAccounts.find((a) => a.id === userId)?.id) ||
      nextAccounts[0].id

    setUserId(preferred)
    return preferred
  }, [userId])

  useEffect(() => {
    ;(async () => {
      try {
        const params = new URLSearchParams(window.location.search)
        // An application asked to sign the user out (RP-initiated logout).
        // Checked first: the request may carry client_id too.
        if (params.get("end_session") === "1") {
          await ensureSession()
          setScreen("end-session")
          return
        }
        if (params.has("client_id") || params.has("response_type")) {
          await ensureSession()
          // A stored session token may be stale (e.g. expired, or the server
          // restarted). Validate it and start a fresh anonymous session if it
          // is no longer accepted, otherwise the sign-in call below fails with
          // "invalid token".
          if (getToken() && !(await validateSession())) {
            clearToken()
            try {
              await ensureSession()
            } catch {
              /* ignore */
            }
          }
          try {
            const selected = await refreshAccounts()
            if (selected) {
              setScreen("oauth2-consent")
            } else {
              setScreen("sign-in")
            }
          } catch {
            setScreen("sign-in")
          }
          return
        }

        await ensureSession()
        if (getToken()) {
          const valid = await validateSession()
          if (valid) {
            try {
              const selected = await refreshAccounts()
              if (selected) {
                setScreen("account")
              }
            } catch {
              /* no users in session */
            }
          } else {
            clearToken()
            try {
              await ensureSession()
            } catch {
              /* ignore */
            }
          }
        }
      } catch {
        // Session bootstrap can fail (origin mismatch, server down)
      } finally {
        setReady(true)
      }
    })()
    // eslint-disable-next-line react-hooks/exhaustive-deps -- bootstrap once
  }, [])

  const handleSignedIn = useCallback(async () => {
    try {
      await createSession()
    } catch {
      /* renewal may fail, token might still work */
    }
    try {
      const selected = await refreshAccounts()
      if (selected) {
        // If an OAuth2 authorization is in progress (client_id in the URL),
        // continue to the consent screen instead of the account dashboard.
        const params = new URLSearchParams(window.location.search)
        if (params.has("client_id") || params.has("response_type")) {
          setScreen("oauth2-consent")
        } else {
          setScreen("account")
        }
      }
    } catch {
      /* ignore */
    }
  }, [refreshAccounts])

  const [frontchannelLogoutUris, setFrontchannelLogoutUris] = useState<string[]>([])

  const handleSignOut = useCallback(async () => {
    setFrontchannelLogoutUris(await signOut())
    await ensureSession()
    setUserId(null)
    setAccounts([])
    setScreen("sign-out")
  }, [])

  const handleSwitchAccount = useCallback((id: string) => {
    setUserId(id)
    setScreen("account")
  }, [])

  const handleAddAccount = useCallback(() => {
    setPrefillEmail(undefined)
    sessionStorage.removeItem("meiling_prefill_email")
    setScreen("sign-in")
  }, [])

  const handleSignUpDone = useCallback((email?: string) => {
    if (email) {
      setPrefillEmail(email)
      sessionStorage.setItem("meiling_prefill_email", email)
    }
    setScreen("sign-in")
  }, [])

  const nav = useCallback((s: DashboardScreen) => {
    setHeaderAction(null)
    setScreen(s)
  }, [])

  if (!ready) return null

  if (screen === "forgot-password") {
    return (
      <ForgotPasswordView
        instanceName={instanceName}
        onBack={() => setScreen("sign-in")}
      />
    )
  }

  if (screen === "sign-up") {
    return (
      <SignUpView
        instanceName={instanceName}
        onSignIn={() => setScreen("sign-in")}
        onDone={handleSignUpDone}
        onSignedIn={handleSignedIn}
      />
    )
  }

  if (screen === "end-session") {
    // Leave the logout request's parameters behind once it is handled.
    const leave = (next: Screen) => {
      history.replaceState(null, "", window.location.pathname)
      setScreen(next)
    }
    return (
      <EndSessionView
        instanceName={instanceName}
        onSignedOut={() => {
          setUserId(null)
          setAccounts([])
          leave("sign-out")
        }}
        onCancel={() =>
          void refreshAccounts()
            .then((selected) => leave(selected ? "account" : "sign-in"))
            .catch(() => leave("sign-in"))
        }
      />
    )
  }

  if (screen === "sign-out") {
    return (
      <SignOutView
        instanceName={instanceName}
        onSignIn={() => setScreen("sign-in")}
        frontchannelLogoutUris={frontchannelLogoutUris}
      />
    )
  }

  if (screen === "oauth2-consent") {
    if (!userId) {
      setScreen("sign-in")
      return null
    }
    return (
      <OAuth2ConsentView
        instanceName={instanceName}
        userId={userId}
        accountLabel={accounts.find((a) => a.id === userId)?.label}
        onNav={(s) => setScreen(s as Screen)}
      />
    )
  }

  if (DASHBOARD_SCREENS.has(screen) && userId) {
    const active = screen as DashboardScreen
    return (
      <TooltipProvider>
        <DashboardShell
          instanceName={instanceName}
          active={active}
          userId={userId}
          accounts={
            accounts.length > 0
              ? accounts
              : [{ id: userId, label: userId.slice(0, 8) }]
          }
          headerAction={active === "apps" ? headerAction : null}
          onNav={nav}
          onSwitchAccount={handleSwitchAccount}
          onAddAccount={handleAddAccount}
          onSignOut={handleSignOut}
        >
          {active === "account" ? (
            <AccountView
              userId={userId}
              onSignOut={handleSignOut}
              onManageContacts={() => setScreen("contacts")}
            />
          ) : null}
          {active === "contacts" ? <ContactsView userId={userId} /> : null}
          {active === "security" ? <SecurityView userId={userId} /> : null}
          {active === "login-history" ? (
            <LoginHistoryView userId={userId} />
          ) : null}
          {active === "authorized-apps" ? (
            <AuthorizedAppsView userId={userId} />
          ) : null}
          {active === "apps" ? (
            <ApplicationsView
              userId={userId}
              onHeaderActionChange={setHeaderAction}
            />
          ) : null}
        </DashboardShell>
      </TooltipProvider>
    )
  }

  if (DASHBOARD_SCREENS.has(screen) && !userId) {
    setScreen("sign-in")
    return null
  }

  const email =
    prefillEmail ??
    sessionStorage.getItem("meiling_prefill_email") ??
    undefined

  return (
    <SignInView
      instanceName={instanceName}
      onForgotPassword={() => setScreen("forgot-password")}
      onSignUp={() => setScreen("sign-up")}
      onSignedIn={handleSignedIn}
      prefillEmail={email}
    />
  )
}
