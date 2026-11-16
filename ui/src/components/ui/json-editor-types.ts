export type JsonEditorProps = {
  value: string
  onChange?: (value: string) => void
  /** Read-only viewer mode (used for API response dumps). */
  readOnly?: boolean
  /** Editor height in pixels. */
  height?: number
  className?: string
  "aria-label"?: string
}
