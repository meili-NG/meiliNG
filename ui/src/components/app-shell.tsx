import type { ComponentProps, ReactNode } from "react"
import { KeyRoundIcon, type LucideIcon } from "lucide-react"

import {
  Empty,
  EmptyContent,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
} from "@/components/ui/empty"
import {
  SidebarMenuButton,
  SidebarTrigger,
  useSidebar,
} from "@/components/ui/sidebar"
import { useBranding } from "@/lib/branding"
import { cn } from "@/lib/utils"

/**
 * A sidebar navigation button that also closes the mobile sheet, so picking a
 * page on a phone shows that page instead of leaving the menu over it.
 */
export function SidebarNavButton({
  onClick,
  ...props
}: ComponentProps<typeof SidebarMenuButton>) {
  const { isMobile, setOpenMobile } = useSidebar()
  return (
    <SidebarMenuButton
      {...props}
      onClick={(event) => {
        onClick?.(event)
        if (isMobile) setOpenMobile(false)
      }}
    />
  )
}

/**
 * The instance mark shown in the sidebar header and the mobile top bar: the
 * configured logo (instance.logoUrl), or a key icon when none is set.
 */
export function InstanceMark({ className }: { className?: string }) {
  const { logoUrl } = useBranding()
  const base =
    className ??
    "flex aspect-square size-8 items-center justify-center rounded-lg bg-sidebar-primary text-sidebar-primary-foreground"

  if (logoUrl) {
    return (
      <div className={cn(base, "overflow-hidden bg-transparent")}>
        <img src={logoUrl} alt="" className="size-full object-contain" />
      </div>
    )
  }
  return (
    <div className={base}>
      <KeyRoundIcon className="size-4" />
    </div>
  )
}

/**
 * The top bar shown below the md breakpoint, where the sidebar collapses into a
 * sheet. It carries the menu trigger and the instance name; the page title
 * stays in the page body so it is not repeated.
 */
export function MobileTopBar({
  instanceName,
  subtitle,
}: {
  instanceName: string
  subtitle?: string
}) {
  return (
    <header className="sticky top-0 z-20 flex h-14 shrink-0 items-center gap-3 border-b bg-background/85 px-3 backdrop-blur supports-[backdrop-filter]:bg-background/70 md:hidden">
      <SidebarTrigger className="size-9" />
      <div className="flex min-w-0 items-center gap-2">
        <InstanceMark className="flex size-7 shrink-0 items-center justify-center rounded-md bg-primary text-primary-foreground" />
        <span className="truncate text-sm font-semibold">{instanceName}</span>
        {subtitle ? (
          <span className="shrink-0 rounded-md bg-muted px-1.5 py-0.5 text-xs text-muted-foreground">
            {subtitle}
          </span>
        ) : null}
      </div>
    </header>
  )
}

/**
 * A bordered placeholder for a list with nothing in it yet.
 */
export function EmptyState({
  icon: Icon,
  title,
  description,
  action,
}: {
  icon: LucideIcon
  title: string
  description?: string
  action?: ReactNode
}) {
  return (
    <Empty className="flex-none border py-10">
      <EmptyHeader>
        <EmptyMedia variant="icon">
          <Icon />
        </EmptyMedia>
        <EmptyTitle>{title}</EmptyTitle>
        {description ? (
          <EmptyDescription>{description}</EmptyDescription>
        ) : null}
      </EmptyHeader>
      {action ? <EmptyContent>{action}</EmptyContent> : null}
    </Empty>
  )
}
