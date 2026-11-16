import { useCallback, useEffect, useState } from "react"
import * as monaco from "monaco-editor-workers/editor/editor.api.js"
import "monaco-editor-workers/language/json/monaco.contribution.js"
import editorWorker from "monaco-editor-workers/editor/editor.worker.js?worker"
import jsonWorker from "monaco-editor-workers/language/json/json.worker.js?worker"
import Editor, { loader, type OnMount } from "@monaco-editor/react"

import type { JsonEditorProps } from "./json-editor-types"
import { cn } from "@/lib/utils"

// Self-host Monaco from the bundled package instead of the default CDN, so the
// editor works offline inside meiliNG's embedded single-binary UI. The workers
// are imported through the "monaco-editor-workers" alias (see vite.config.ts)
// because the package "exports" map blocks deep "monaco-editor/esm/..."
// specifiers under Rolldown. Vite emits each worker as its own chunk; only the
// JSON language worker is wired up here.
self.MonacoEnvironment = {
  getWorker(_workerId, label) {
    if (label === "json") return new jsonWorker()
    return new editorWorker()
  },
}
loader.config({ monaco })

/** Tracks whether the app is in dark mode (via `.dark` class or system pref). */
function useIsDark(): boolean {
  const [dark, setDark] = useState(() => {
    if (typeof document === "undefined") return false
    return (
      document.documentElement.classList.contains("dark") ||
      window.matchMedia?.("(prefers-color-scheme: dark)").matches
    )
  })

  useEffect(() => {
    const mql = window.matchMedia("(prefers-color-scheme: dark)")
    const update = () =>
      setDark(
        document.documentElement.classList.contains("dark") || mql.matches,
      )
    update()
    mql.addEventListener("change", update)
    const observer = new MutationObserver(update)
    observer.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ["class"],
    })
    return () => {
      mql.removeEventListener("change", update)
      observer.disconnect()
    }
  }, [])

  return dark
}

export default function JsonEditorImpl({
  value,
  onChange,
  readOnly = false,
  height = 320,
  className,
  "aria-label": ariaLabel,
}: JsonEditorProps) {
  const isDark = useIsDark()

  const handleMount: OnMount = useCallback(
    (editor) => {
      if (ariaLabel) editor.updateOptions({ ariaLabel })
    },
    [ariaLabel],
  )

  return (
    <div
      className={cn(
        "overflow-hidden rounded-md border border-border bg-muted/20",
        className,
      )}
    >
      <Editor
        language="json"
        theme={isDark ? "vs-dark" : "light"}
        height={height}
        value={value}
        onChange={(next) => onChange?.(next ?? "")}
        onMount={handleMount}
        options={{
          readOnly,
          domReadOnly: readOnly,
          minimap: { enabled: false },
          lineNumbers: "on",
          folding: true,
          scrollBeyondLastLine: false,
          fontSize: 12,
          fontFamily:
            "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace",
          tabSize: 2,
          automaticLayout: true,
          wordWrap: "on",
          scrollbar: { alwaysConsumeMouseWheel: false },
          renderLineHighlight: readOnly ? "none" : "line",
          overviewRulerLanes: 0,
        }}
      />
    </div>
  )
}
