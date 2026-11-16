import { fileURLToPath, URL } from "node:url";
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

function withTrailingSlash(path: string): string {
  return path.endsWith("/") ? path : `${path}/`;
}

const apiOrigin = process.env.MEILING_ORIGIN || "http://localhost:8080";
// Paths the server owns; everything else is a client-side route. Keep in sync
// with reservedPrefixes in pkg/server/webui/webui.go.
const apiPrefixes = [
  "/v1",
  "/v2",
  "/.well-known",
  "/health",
  "/docs",
  "/openapi",
  "/schemas",
  "/swagger-ui",
];
const devBase = withTrailingSlash(process.env.MEILING_WEBUI__BASE_PATH || "/ui");

// Production uses a relative base so the same ui/dist can be mounted at /ui,
// /, or a custom prefix. Go rewrites ./asset URLs in index.html to the mount.
// A static build hosted apart from the API has no Go to rewrite it, so it sets
// WEBUI_STATIC_BASE to its absolute mount path (usually "/").
// The dev server keeps an absolute base so http://localhost:5173/ui/ matches
// production's default path. The server-owned paths are proxied to Meiling.
export default defineConfig(({ command }) => ({
  base:
    command === "build" ? process.env.WEBUI_STATIC_BASE || "./" : devBase,
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      "@": fileURLToPath(new URL("./src", import.meta.url)),
      // Alias to Monaco's ESM tree so worker subpaths resolve directly. The
      // package "exports" map otherwise blocks deep "monaco-editor/esm/..."
      // specifiers under Rolldown. Self-hosting these keeps the editor working
      // offline in the embedded single-binary UI.
      "monaco-editor-workers": fileURLToPath(
        new URL("./node_modules/monaco-editor/esm/vs", import.meta.url),
      ),
    },
  },
  server: {
    proxy: Object.fromEntries(apiPrefixes.map((prefix) => [prefix, apiOrigin])),
  },
  // Keep Monaco and its workers out of dev dependency pre-bundling. The
  // optimizer bundles the aliased "?worker" imports through esbuild, which
  // drops their default export (the Worker constructor) and breaks worker
  // instantiation in dev. Excluding the exact aliased specifiers leaves Vite's
  // own "?worker" transform in charge. Production builds are unaffected.
  optimizeDeps: {
    exclude: [
      "monaco-editor",
      "@monaco-editor/react",
      "monaco-editor-workers/editor/editor.worker.js?worker",
      "monaco-editor-workers/language/json/json.worker.js?worker",
    ],
  },
}));
