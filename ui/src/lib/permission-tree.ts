import type { KeyboardEvent } from "react"

import type { PermissionSerialized } from "@/lib/admin"

export type PermissionTree = {
  byId: Map<string, PermissionSerialized>
  /** Top-level permissions, by scope. */
  roots: PermissionSerialized[]
  /** Direct children of a permission id, by scope. */
  children: Map<string, PermissionSerialized[]>
  /** Parent id of a permission id; absent for top level. */
  parent: Map<string, string>
}

/**
 * Builds the containment forest from each permission's parentId. A missing,
 * unknown or self parent puts the permission at top level, and the result is
 * always acyclic, so the walks below terminate on any input.
 */
export function buildPermissionTree(
  permissions: PermissionSerialized[],
): PermissionTree {
  const byId = new Map(permissions.map((p) => [p.id, p]))
  const sorted = [...byId.values()].sort((a, b) =>
    a.scope.localeCompare(b.scope),
  )

  const parent = new Map<string, string>()
  for (const p of sorted) {
    if (p.parentId && p.parentId !== p.id && byId.has(p.parentId)) {
      parent.set(p.id, p.parentId)
    }
  }
  // Corrupt data: a parent cycle has no top-level member and would never render, so cut it at one member.
  for (const p of sorted) {
    const seen = new Set<string>()
    for (
      let at = parent.get(p.id);
      at && !seen.has(at);
      at = parent.get(at)
    ) {
      if (at === p.id) {
        parent.delete(p.id)
        break
      }
      seen.add(at)
    }
  }

  const roots: PermissionSerialized[] = []
  const children = new Map<string, PermissionSerialized[]>()
  for (const p of sorted) {
    const parentId = parent.get(p.id)
    if (!parentId) roots.push(p)
    else children.set(parentId, [...(children.get(parentId) ?? []), p])
  }
  return { byId, roots, children, parent }
}

/** Everything a permission contains, depth first. */
export function descendantsOf(
  tree: PermissionTree,
  id: string,
): PermissionSerialized[] {
  return (tree.children.get(id) ?? []).flatMap((child) => [
    child,
    ...descendantsOf(tree, child.id),
  ])
}

/** Every broader permission that contains this one, nearest first. */
export function ancestorsOf(
  tree: PermissionTree,
  id: string,
): PermissionSerialized[] {
  const out: PermissionSerialized[] = []
  for (let at = tree.parent.get(id); at; at = tree.parent.get(at)) {
    out.push(tree.byId.get(at)!)
  }
  return out
}

/**
 * Keyboard handling for one role="treeitem" row inside a role="tree" whose
 * nested rows sit in a role="group" next to their parent row.
 */
export function onTreeItemKeyDown(
  event: KeyboardEvent<HTMLElement>,
  row: {
    hasChildren: boolean
    open: boolean
    toggle: () => void
    /** Enter or Space. */
    activate: () => void
  },
) {
  const item = event.currentTarget
  const items = Array.from(
    item
      .closest('[role="tree"]')
      ?.querySelectorAll<HTMLElement>('[role="treeitem"]') ?? [],
  )
  const index = items.indexOf(item)
  let target: HTMLElement | null | undefined
  switch (event.key) {
    case "ArrowDown":
      target = items[index + 1]
      break
    case "ArrowUp":
      target = items[index - 1]
      break
    case "Home":
      target = items[0]
      break
    case "End":
      target = items.at(-1)
      break
    case "ArrowRight":
      if (row.open) target = items[index + 1]
      else if (row.hasChildren) row.toggle()
      break
    case "ArrowLeft":
      if (row.open) row.toggle()
      else {
        target = item
          .closest('[role="group"]')
          ?.parentElement?.querySelector<HTMLElement>('[role="treeitem"]')
      }
      break
    case "Enter":
    case " ":
      row.activate()
      break
    default:
      return
  }
  event.preventDefault()
  target?.focus()
}
