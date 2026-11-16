import type { ReactNode } from "react"
import { cva, type VariantProps } from "class-variance-authority"
import {
  CheckIcon,
  ChevronsUpDownIcon,
  ContactIcon,
  HistoryIcon,
  KeyRoundIcon,
  LayoutGridIcon,
  LifeBuoyIcon,
  LogOutIcon,
  PlusIcon,
  ShieldIcon,
  UserIcon,
} from "lucide-react"

import { Avatar, AvatarFallback } from "@/components/ui/avatar"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
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
  useSidebar,
} from "@/components/ui/sidebar"
import {
  InstanceMark,
  MobileTopBar,
  SidebarNavButton,
} from "@/components/app-shell"
import { useBranding } from "@/lib/branding"
import { cn } from "@/lib/utils"

export type DashboardScreen =
  | "account"
  | "contacts"
  | "security"
  | "login-history"
  | "authorized-apps"
  | "apps"

export type SessionAccount = {
  id: string
  label: string
}

const NAV_GROUPS: {
  label: string
  items: {
    id: DashboardScreen
    label: string
    icon: typeof UserIcon
  }[]
}[] = [
  {
    label: "Account",
    items: [
      { id: "account", label: "My Profile", icon: UserIcon },
      { id: "contacts", label: "Contacts", icon: ContactIcon },
      { id: "security", label: "Security", icon: ShieldIcon },
      { id: "login-history", label: "Login history", icon: HistoryIcon },
    ],
  },
  {
    label: "Applications",
    items: [
      {
        id: "authorized-apps",
        label: "Authorized applications",
        icon: LayoutGridIcon,
      },
      { id: "apps", label: "Your applications", icon: KeyRoundIcon },
    ],
  },
]

const PAGE_META: Record<DashboardScreen, { title: string }> = {
  account: { title: "My Profile" },
  contacts: { title: "Contacts" },
  security: { title: "Security" },
  "login-history": { title: "Login history" },
  "authorized-apps": { title: "Authorized applications" },
  apps: { title: "Your applications" },
}

function initialsFrom(label: string) {
  return (
    label
      .split(/[\s@._-]+/)
      .filter(Boolean)
      .slice(0, 2)
      .map((part) => part[0]?.toUpperCase() ?? "")
      .join("") || "U"
  )
}

type DashboardShellProps = {
  instanceName: string
  active: DashboardScreen
  userId: string
  accounts: SessionAccount[]
  headerAction?: ReactNode
  onNav: (screen: DashboardScreen) => void
  onSwitchAccount: (userId: string) => void
  onAddAccount: () => void
  onSignOut: () => void
  children: ReactNode
}

function AccountSwitcher({
  accounts,
  userId,
  onSwitchAccount,
  onAddAccount,
  onSignOut,
}: {
  accounts: SessionAccount[]
  userId: string
  onSwitchAccount: (userId: string) => void
  onAddAccount: () => void
  onSignOut: () => void
}) {
  const { isMobile } = useSidebar()
  const { supportUrl } = useBranding()
  const current = accounts.find((a) => a.id === userId) ?? accounts[0]
  const label = current?.label ?? "User"

  return (
    <SidebarMenu>
      <SidebarMenuItem>
        <DropdownMenu>
          <DropdownMenuTrigger
            render={
              <SidebarMenuButton
                size="lg"
                className="data-open:bg-sidebar-accent data-open:text-sidebar-accent-foreground"
                tooltip={label}
              />
            }
          >
            <Avatar className="size-8 rounded-lg">
              <AvatarFallback className="rounded-lg">
                {initialsFrom(label)}
              </AvatarFallback>
            </Avatar>
            <div className="grid flex-1 text-left text-sm leading-tight">
              <span className="truncate font-medium">{label}</span>
              <span className="truncate text-xs text-muted-foreground">
                {accounts.length > 1
                  ? `${accounts.length} accounts`
                  : "Signed in"}
              </span>
            </div>
            <ChevronsUpDownIcon className="ml-auto" />
          </DropdownMenuTrigger>
          <DropdownMenuContent
            className="min-w-56 rounded-lg"
            side={isMobile ? "bottom" : "right"}
            align="end"
            sideOffset={4}
          >
            <DropdownMenuGroup>
              <DropdownMenuLabel className="text-xs text-muted-foreground">
                Accounts
              </DropdownMenuLabel>
              {accounts.map((account) => (
                <DropdownMenuItem
                  key={account.id}
                  onClick={() => onSwitchAccount(account.id)}
                >
                  <Avatar className="size-6 rounded-md">
                    <AvatarFallback className="rounded-md text-xs">
                      {initialsFrom(account.label)}
                    </AvatarFallback>
                  </Avatar>
                  <span className="truncate">{account.label}</span>
                  {account.id === userId ? (
                    <CheckIcon className="ml-auto" />
                  ) : null}
                </DropdownMenuItem>
              ))}
            </DropdownMenuGroup>
            <DropdownMenuSeparator />
            <DropdownMenuGroup>
              <DropdownMenuItem onClick={onAddAccount}>
                <PlusIcon />
                Add account
              </DropdownMenuItem>
              {supportUrl ? (
                <DropdownMenuItem
                  onClick={() =>
                    window.open(supportUrl, "_blank", "noopener,noreferrer")
                  }
                >
                  <LifeBuoyIcon />
                  Help
                </DropdownMenuItem>
              ) : null}
              <DropdownMenuItem onClick={onSignOut}>
                <LogOutIcon />
                Sign out all
              </DropdownMenuItem>
            </DropdownMenuGroup>
          </DropdownMenuContent>
        </DropdownMenu>
      </SidebarMenuItem>
    </SidebarMenu>
  )
}

export function DashboardShell({
  instanceName,
  active,
  userId,
  accounts,
  headerAction,
  onNav,
  onSwitchAccount,
  onAddAccount,
  onSignOut,
  children,
}: DashboardShellProps) {
  const meta = PAGE_META[active]

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
                </div>
              </SidebarMenuButton>
            </SidebarMenuItem>
          </SidebarMenu>
        </SidebarHeader>

        <SidebarContent>
          {NAV_GROUPS.map((group) => (
            <SidebarGroup key={group.label}>
              <SidebarGroupLabel>{group.label}</SidebarGroupLabel>
              <SidebarGroupContent>
                <SidebarMenu>
                  {group.items.map((item) => (
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
          ))}
        </SidebarContent>

        <SidebarFooter>
          <AccountSwitcher
            accounts={accounts}
            userId={userId}
            onSwitchAccount={onSwitchAccount}
            onAddAccount={onAddAccount}
            onSignOut={onSignOut}
          />
        </SidebarFooter>
        <SidebarRail />
      </Sidebar>

      <SidebarInset>
        <MobileTopBar instanceName={instanceName} />
        <div className="mx-auto flex w-full max-w-5xl flex-1 flex-col gap-8 px-4 pt-6 pb-12 md:px-8 md:pt-10">
          <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-3">
            <h1 className="text-2xl font-semibold tracking-tight">
              {meta.title}
            </h1>
            {headerAction ? (
              <div className="shrink-0">{headerAction}</div>
            ) : null}
          </div>
          {children}
        </div>
      </SidebarInset>
    </SidebarProvider>
  )
}

type SettingsRowProps = {
  label: string
  description?: string
  badge?: ReactNode
  action?: ReactNode
  children: ReactNode
}

export function SettingsRow({
  label,
  description,
  badge,
  action,
  children,
}: SettingsRowProps) {
  return (
    <div className="flex flex-col gap-2">
      <div className="flex items-start justify-between gap-3">
        <div className="flex min-w-0 flex-col gap-1">
          <div className="flex flex-wrap items-center gap-2">
            <p className="text-sm font-medium">{label}</p>
            {badge}
          </div>
          {description ? (
            <p className="text-sm text-muted-foreground">{description}</p>
          ) : null}
        </div>
        {action ? <div className="shrink-0">{action}</div> : null}
      </div>
      <div className="min-w-0">{children}</div>
    </div>
  )
}

const settingsSectionVariants = cva("flex flex-col gap-6", {
  variants: {
    variant: {
      default: "",
      destructive:
        "rounded-xl border border-destructive/25 bg-destructive/5 p-4 sm:p-6",
    },
  },
  defaultVariants: {
    variant: "default",
  },
})

const settingsSectionTitleVariants = cva("text-base font-semibold", {
  variants: {
    variant: {
      default: "",
      destructive: "text-destructive",
    },
  },
  defaultVariants: {
    variant: "default",
  },
})

export function SettingsSection({
  title,
  description,
  action,
  variant = "default",
  className,
  children,
}: {
  title: string
  description?: string
  action?: ReactNode
  className?: string
  children?: ReactNode
} & VariantProps<typeof settingsSectionVariants>) {
  return (
    <section className={cn(settingsSectionVariants({ variant }), className)}>
      <div
        className={cn(
          "flex items-center justify-between gap-4",
          variant === "destructive" &&
            "flex-col items-start sm:flex-row sm:items-center",
        )}
      >
        <div className="flex min-w-0 flex-col gap-1">
          <h2 className={cn(settingsSectionTitleVariants({ variant }))}>
            {title}
          </h2>
          {description ? (
            <p className="text-sm text-muted-foreground">{description}</p>
          ) : null}
        </div>
        {action ? <div className="shrink-0">{action}</div> : null}
      </div>
      {children ? (
        <div className="flex flex-col gap-6">{children}</div>
      ) : null}
    </section>
  )
}

export function DashboardSection({
  title,
  description,
  action,
  children,
}: {
  title: string
  description?: string
  action?: ReactNode
  children: ReactNode
}) {
  return (
    <section className="flex flex-col gap-3">
      <div className="flex items-start justify-between gap-4">
        <div className="flex flex-col gap-1">
          <h2 className="text-base font-medium">{title}</h2>
          {description ? (
            <p className="text-sm text-muted-foreground">{description}</p>
          ) : null}
        </div>
        {action}
      </div>
      {children}
    </section>
  )
}
