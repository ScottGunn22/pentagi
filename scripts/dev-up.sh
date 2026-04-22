#!/usr/bin/env bash
# dev-up.sh — Bring up the PentAGI stack (feature/scanner-ingestion) for hands-on testing.
#
# Safe to re-run: it preserves an existing .env, doesn't force-rebuild images that are already
# up, and polls healthchecks before returning. Flip FORCE_REBUILD=1 to rebuild the pentagi
# image after backend changes.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

FORCE_REBUILD="${FORCE_REBUILD:-0}"
WITH_GRAPHITI="${WITH_GRAPHITI:-1}"   # Neo4j + Graphiti enabled by default
WITH_OBS="${WITH_OBS:-0}"             # Grafana/Loki/Jaeger stack (heavy) — opt in

say()  { printf '\033[1;34m[dev-up]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[dev-up]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[dev-up]\033[0m %s\n' "$*" >&2; exit 1; }

# --- Sanity ------------------------------------------------------------------

command -v docker >/dev/null 2>&1 || die "docker not on PATH"
docker compose version >/dev/null 2>&1 || die "docker compose plugin not installed"

CURRENT_BRANCH="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo '?')"
if [[ "${CURRENT_BRANCH}" != "feature/scanner-ingestion" ]]; then
    warn "current branch is '${CURRENT_BRANCH}' (expected 'feature/scanner-ingestion'). Continuing anyway."
fi

# --- .env --------------------------------------------------------------------

if [[ ! -f .env ]]; then
    say "no .env found — seeding from .env.example"
    cp .env.example .env
    warn "New .env written. You MUST fill in at least one LLM provider key before agents will run."
    warn "Common ones: OPEN_AI_KEY, ANTHROPIC_API_KEY, GEMINI_API_KEY."
    warn "Scanner ingestion itself works without any LLM key — but flow execution will not."
fi

# Ensure the ingestion storage dir exists + is writable.
# Default is ./data/ingestion (matches Phase 7's config default).
STORAGE_DIR="$(grep -E '^INGESTION_STORAGE_DIR=' .env 2>/dev/null | cut -d= -f2- | tr -d '"' | tr -d "'" || true)"
if [[ -z "${STORAGE_DIR}" ]]; then
    STORAGE_DIR="./data/ingestion"
    echo "INGESTION_STORAGE_DIR=${STORAGE_DIR}" >> .env
    say "appended INGESTION_STORAGE_DIR=${STORAGE_DIR} to .env"
fi
mkdir -p "${STORAGE_DIR}"
say "storage dir ready: $(readlink -f "${STORAGE_DIR}")"

# --- Compose file assembly ---------------------------------------------------

COMPOSE_FILES=(-f docker-compose.yml)
if [[ "${WITH_GRAPHITI}" == "1" ]]; then
    COMPOSE_FILES+=(-f docker-compose-graphiti.yml)
fi
if [[ "${WITH_OBS}" == "1" ]]; then
    COMPOSE_FILES+=(-f docker-compose-observability.yml)
fi

say "compose files: ${COMPOSE_FILES[*]}"

# --- Build / up --------------------------------------------------------------

BUILD_FLAGS=()
if [[ "${FORCE_REBUILD}" == "1" ]]; then
    say "FORCE_REBUILD=1 → rebuilding pentagi image"
    BUILD_FLAGS=(--build)
fi

say "starting stack (detached)"
docker compose "${COMPOSE_FILES[@]}" up -d "${BUILD_FLAGS[@]}"

# --- Healthcheck polling -----------------------------------------------------

say "waiting for pgvector to accept connections"
for i in $(seq 1 60); do
    if docker compose exec -T pgvector pg_isready -U postgres >/dev/null 2>&1; then
        say "pgvector healthy"
        break
    fi
    sleep 1
    if [[ "$i" == 60 ]]; then die "pgvector didn't come up in 60s"; fi
done

say "waiting for pentagi HTTP endpoint"
PORT="$(grep -E '^PENTAGI_LISTEN_PORT=' .env 2>/dev/null | cut -d= -f2- | tr -d '"' || echo 8443)"
[[ -z "${PORT}" ]] && PORT=8443

for i in $(seq 1 90); do
    # The HTTPS endpoint uses a self-signed cert; curl -k to ignore.
    if curl -ksf "https://127.0.0.1:${PORT}/api/v1/info" >/dev/null 2>&1 \
       || curl -ksf "https://127.0.0.1:${PORT}/" >/dev/null 2>&1; then
        say "pentagi HTTPS up on port ${PORT}"
        break
    fi
    sleep 2
    if [[ "$i" == 90 ]]; then
        warn "pentagi didn't respond within 180s — check 'docker compose logs pentagi'"
        break
    fi
done

# --- Summary -----------------------------------------------------------------

cat <<BANNER

---------------------------------------------------------------------
PentAGI feature/scanner-ingestion is up.

  UI + API:          https://127.0.0.1:${PORT}
  GraphQL playground https://127.0.0.1:${PORT}/graphql
  Swagger:           https://127.0.0.1:${PORT}/swagger/index.html
  Ingestion storage: $(readlink -f "${STORAGE_DIR}")

Next steps for hands-on ingestion testing:

  1. Open the UI, log in with the seeded admin (see ADMIN_EMAIL in .env).
  2. Sidebar → Engagements → + New Engagement.
  3. Add a scope rule (e.g. cidr 192.168.1.0/24 include).
  4. Reports tab → drop a real scan output OR the bundled fixture:

     curl -kF "source_type=nmap" \\
          -F "file=@backend/pkg/ingestion/parsers/testdata/nmap/minimal.xml" \\
          -b cookies.txt -c cookies.txt \\
          https://127.0.0.1:${PORT}/api/v1/engagements/<ID>/reports

  5. Watch findings populate in the Findings tab.
  6. Start an engagement-aware flow via GraphQL (UI flow-form integration is a v2 follow-up):

     mutation {
       createFlow(
         modelProvider: "openai"
         input: "Scan and verify engagement findings."
         engagementId: "1"
         flowType: NEW_TEST
       ) { id title }
     }

Useful ops commands:

  docker compose logs -f pentagi              # tail app logs
  docker compose exec pgvector psql -U postgres -d pentagidb
  docker compose down                         # stop everything (keeps volumes)
  FORCE_REBUILD=1 ./scripts/dev-up.sh         # rebuild after backend code changes
  WITH_OBS=1       ./scripts/dev-up.sh        # + Grafana/Loki/Jaeger stack

---------------------------------------------------------------------
BANNER
