import { lazy, Suspense } from "react"

import { Skeleton } from "@/components/ui/skeleton"
import { cn } from "@/lib/utils"
import type { JsonEditorProps } from "./json-editor-types"

// Monaco is heavy, so its implementation (and the editor core + workers) is
// code-split into a separate chunk and only fetched when a JSON editor first
// renders. It is self-hosted from the bundled monaco-editor package, so it
// still works offline in the embedded single-binary UI.
const JsonEditorImpl = lazy(() => import("./json-editor-impl"))

export type { JsonEditorProps }

export function JsonEditor(props: JsonEditorProps) {
  const height = props.height ?? 320
  return (
    <Suspense
      fallback={
        <Skeleton
          className={cn("w-full rounded-md", props.className)}
          style={{ height }}
        />
      }
    >
      <JsonEditorImpl {...props} />
    </Suspense>
  )
}
