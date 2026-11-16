import type { ReactNode } from "react"

import { TabsList, TabsTrigger } from "@/components/ui/tabs"
import { cn } from "@/lib/utils"

/** Flat admin section header — no bordered card shell. */
export function AdminSection({
  title,
  description,
  action,
  className,
  children,
}: {
  title?: string
  description?: string
  action?: ReactNode
  className?: string
  children?: ReactNode
}) {
  return (
    <section className={cn("flex flex-col gap-3", className)}>
      {title || action || description ? (
        <div className="flex items-start justify-between gap-4">
          <div className="flex min-w-0 flex-col gap-0.5">
            {title ? (
              <p className="text-sm font-medium tracking-tight">{title}</p>
            ) : null}
            {description ? (
              <p className="text-xs text-muted-foreground">{description}</p>
            ) : null}
          </div>
          {action ? <div className="shrink-0">{action}</div> : null}
        </div>
      ) : null}
      {children}
    </section>
  )
}

/**
 * Page-level header for admin list screens: title + description stacked on the
 * left, a primary action aligned to the right. Replaces the shell's standalone
 * h1 so the heading, description, and action read as one band.
 */
export function AdminPageHeader({
  title,
  description,
  action,
  className,
}: {
  title: string
  description?: string
  action?: ReactNode
  className?: string
}) {
  return (
    <div
      className={cn(
        "flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between sm:gap-4",
        className,
      )}
    >
      <div className="flex min-w-0 flex-col gap-1">
        <h1 className="text-xl font-semibold tracking-tight">{title}</h1>
        {description ? (
          <p className="text-sm text-muted-foreground">{description}</p>
        ) : null}
      </div>
      {action ? <div className="shrink-0">{action}</div> : null}
    </div>
  )
}

export function AdminToolbar({
  className,
  children,
}: {
  className?: string
  children: ReactNode
}) {
  return (
    <div
      className={cn(
        "flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between",
        className,
      )}
    >
      {children}
    </div>
  )
}

export function AdminFieldGrid({
  columns = 2,
  className,
  children,
}: {
  columns?: 1 | 2 | 3
  className?: string
  children: ReactNode
}) {
  return (
    <dl
      className={cn(
        "grid gap-x-8 gap-y-3",
        columns === 1 && "grid-cols-1",
        columns === 2 && "grid-cols-1 sm:grid-cols-2",
        columns === 3 && "grid-cols-1 sm:grid-cols-2 lg:grid-cols-3",
        className,
      )}
    >
      {children}
    </dl>
  )
}

export function AdminField({
  label,
  mono,
  className,
  children,
}: {
  label: string
  mono?: boolean
  className?: string
  children: ReactNode
}) {
  return (
    <div className={cn("flex min-w-0 flex-col gap-1", className)}>
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd
        className={cn(
          "min-w-0 text-sm break-words",
          mono && "font-mono text-xs",
        )}
      >
        {children || "—"}
      </dd>
    </div>
  )
}

/**
 * Underlined page tabs that scroll sideways when they do not fit, instead of
 * wrapping onto a second row over the content on narrow screens.
 */
export function AdminPageTabs({
  tabs,
}: {
  tabs: { value: string; label: string }[]
}) {
  return (
    <div className="-mx-4 overflow-x-auto border-b px-4 [scrollbar-width:none] md:mx-0 md:px-0 [&::-webkit-scrollbar]:hidden">
      <TabsList
        variant="line"
        className="w-max gap-1 p-0 group-data-horizontal/tabs:h-10"
      >
        {tabs.map((tab) => (
          <TabsTrigger
            key={tab.value}
            value={tab.value}
            className="flex-none px-3 group-data-horizontal/tabs:after:bottom-0"
          >
            {tab.label}
          </TabsTrigger>
        ))}
      </TabsList>
    </div>
  )
}
