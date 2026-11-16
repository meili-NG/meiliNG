#!/usr/bin/env sh
#
# Runs Meiling locally with the Vite dev server for the web UI, so editing a
# file hot-reloads without rebuilding the Go binary. The API stays on PORT;
# the UI is at http://localhost:5173$MOUNT/.
#
# Usage:
#   ./webui-dev.sh              # UI http://localhost:5173/ui/  API :8080
#   PORT=9000 ./webui-dev.sh    # pick another API port
#   MOUNT=/ ./webui-dev.sh      # serve the UI at the domain root (Vite + Go)
#
# State lives in .devdata/ and is safe to delete.

set -eu

PORT="${PORT:-8080}"
MOUNT="${MOUNT:-/ui}"
VITE_PORT="${VITE_PORT:-5173}"

repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
cd "$repo_root"

ui_dir="$repo_root/ui"
data_dir="$repo_root/.devdata"
mkdir -p "$data_dir"

if [ ! -f "$ui_dir/package.json" ]; then
  echo "error: web UI not found at $ui_dir" >&2
  exit 1
fi

if command -v lsof >/dev/null 2>&1 && lsof -nP -iTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; then
  echo "error: port $PORT is already in use. Set PORT to something else." >&2
  exit 1
fi

if command -v lsof >/dev/null 2>&1 && lsof -nP -iTCP:"$VITE_PORT" -sTCP:LISTEN >/dev/null 2>&1; then
  echo "error: Vite port $VITE_PORT is already in use. Set VITE_PORT to something else." >&2
  exit 1
fi

if [ ! -d "$ui_dir/node_modules" ]; then
  echo "installing UI dependencies..."
  (cd "$ui_dir" && npm ci)
fi

base_url="http://localhost:$PORT"
ui_path="$MOUNT"
case "$ui_path" in
  /) ui_url="http://localhost:$VITE_PORT/" ;;
  *) ui_url="http://localhost:$VITE_PORT$ui_path/" ;;
esac

echo "building meiling..."
go build -o "$data_dir/meiling-dev" ./cmd/meiling

echo "starting Vite..."
(cd "$ui_dir" && MEILING_ORIGIN="$base_url" MEILING_WEBUI__BASE_PATH="$MOUNT" npm run dev -- --host 127.0.0.1 --port "$VITE_PORT") &
vite_pid=$!
trap 'kill "$vite_pid" 2>/dev/null || true' EXIT INT TERM

cat <<BANNER

  web UI     $ui_url
  API        $base_url
  API docs   $base_url/docs

  Sign-up is enabled and email verification is off, so you can create an
  account without a mail server. Verification codes, if any are sent, are
  printed to this log rather than emailed.

  Press Ctrl-C to stop.

BANNER

# Vite proxies the server-owned paths to this process. debug.enabled surfaces verbose errors.
MEILING_WEBUI__ENABLE=true \
MEILING_WEBUI__BASE_PATH="$MOUNT" \
MEILING_SERVER__LISTEN=":$PORT" \
MEILING_SERVER__PUBLIC_URL="$base_url" \
MEILING_SERVER__FRONTEND_ORIGINS="$base_url,http://localhost:$VITE_PORT,http://127.0.0.1:$VITE_PORT" \
MEILING_INSTANCE__NAME="${MEILING_INSTANCE__NAME:-meiliNG dev}" \
MEILING_DATABASE__TYPE=sqlite \
MEILING_DATABASE__DSN="$data_dir/dev.sqlite" \
MEILING_TOKEN__JWT__PRIVATE_KEY_PATH="$data_dir/jwt.key" \
MEILING_AUTH__SIGNUP__ALLOW_SIGN_UP=true \
MEILING_AUTH__SIGNUP__EMAIL_REQUIRED=false \
MEILING_AUTH__SIGNUP__EMAIL_VERIFICATION_REQUIRED=false \
MEILING_DEBUG__ENABLED=true \
MEILING_DEBUG__PRINT_STACK_TRACE=true \
exec "$data_dir/meiling-dev" serve
