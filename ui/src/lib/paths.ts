/** Path helpers for the UI mount (default `/ui`, optional `/`). */

function pathnameParts(): string[] {
  return window.location.pathname.split("/").filter(Boolean)
}

/** True when the current URL is under the admin panel (`…/admin` or `…/admin/…`). */
export function isAdminRoute(): boolean {
  return pathnameParts().includes("admin")
}

/** True when the current URL is the admin sign-in page (`…/admin/signin`). */
export function isAdminSignInRoute(): boolean {
  const parts = pathnameParts()
  const adminIdx = parts.indexOf("admin")
  return adminIdx >= 0 && parts[adminIdx + 1] === "signin"
}

/**
 * Absolute path to the admin sign-in page, preserving the UI mount prefix.
 * Examples: `/ui/admin/signin`, `/admin/signin`
 */
export function adminSignInPath(): string {
  return adminPanelPath() + "signin"
}

/**
 * Absolute path to the admin panel entry, preserving the UI mount prefix.
 * Examples: `/ui/admin/`, `/admin/`
 */
export function adminPanelPath(): string {
  const parts = pathnameParts()
  const adminIdx = parts.indexOf("admin")
  if (adminIdx >= 0) {
    return `/${[...parts.slice(0, adminIdx + 1), ""].join("/")}`
  }

  const uiIdx = parts.indexOf("ui")
  if (uiIdx >= 0) {
    return `/${[...parts.slice(0, uiIdx + 1), "admin", ""].join("/")}`
  }

  // Mounted at domain root (or unknown prefix): use /admin/
  return "/admin/"
}

/** Absolute path back to the account UI root. */
export function accountUiPath(): string {
  const parts = pathnameParts()
  const adminIdx = parts.indexOf("admin")
  if (adminIdx > 0) {
    return `/${[...parts.slice(0, adminIdx), ""].join("/")}`
  }
  if (adminIdx === 0) {
    return "/"
  }

  const uiIdx = parts.indexOf("ui")
  if (uiIdx >= 0) {
    return `/${[...parts.slice(0, uiIdx + 1), ""].join("/")}`
  }

  return "/"
}

/** The admin screens that map to their own URL path segment. */
export type AdminRouteScreen =
  | "users"
  | "permissions"
  | "apps"
  | "audiences"
  | "token-debug"

const ADMIN_SCREENS: AdminRouteScreen[] = [
  "users",
  "permissions",
  "apps",
  "audiences",
  "token-debug",
]

export type AdminRoute = {
  screen: AdminRouteScreen
  /** Selected user id when on `users/:id`. */
  userId: string | null
  /** Selected application id when on `apps/:id`. */
  appId: string | null
}

/** Returns the URL segments after the `admin` prefix, e.g. ["users", ":id"]. */
function adminSubParts(): string[] {
  const parts = pathnameParts()
  const adminIdx = parts.indexOf("admin")
  if (adminIdx < 0) return []
  return parts.slice(adminIdx + 1)
}

/**
 * Parse the current URL into an admin route. Unknown or empty sub-paths fall
 * back to the users screen, so `…/admin/` lands on the default page.
 */
export function parseAdminRoute(): AdminRoute {
  const [first, second] = adminSubParts()
  const screen = ADMIN_SCREENS.find((s) => s === first) ?? "users"
  return {
    screen,
    userId: screen === "users" ? (second ?? null) : null,
    appId: screen === "apps" ? (second ?? null) : null,
  }
}

/**
 * Absolute path for an admin screen, optionally with a detail id, preserving
 * the UI mount prefix. Examples: `/ui/admin/users`, `/ui/admin/users/:id`.
 */
export function adminScreenPath(
  screen: AdminRouteScreen,
  id?: string | null,
): string {
  const base = adminPanelPath() + screen
  return id ? `${base}/${encodeURIComponent(id)}` : base
}

export function goAdminPanel() {
  window.location.assign(adminPanelPath())
}

export function goAccountUi() {
  window.location.assign(accountUiPath())
}
