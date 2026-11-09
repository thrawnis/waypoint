#!/usr/bin/env bash
set -euo pipefail

BRANCH="main"
REPO="$(cd "$(dirname "$0")" && pwd)"
COMPOSE_FILE="$REPO/docker-compose.yml"
IMAGE="waypoint:latest"

# --pull-base-images: opt-in registry check for a newer base image (FROM ...).
# Off by default — pulling the base on every rebuild is slow for basically no
# benefit; run it manually now and then to pick up upstream base updates.
# --force: rebuild/restart even if the pull brought in no new commits.
PULL_BASE_IMAGES=0
FORCE=0
for arg in "$@"; do
  case "$arg" in
    --pull-base-images) PULL_BASE_IMAGES=1 ;;
    --force) FORCE=1 ;;
    -h|--help)
      echo "Usage: $(basename "$0") [--pull-base-images] [--force]"
      exit 0 ;;
    *) echo "Unknown option: $arg" >&2; exit 2 ;;
  esac
done

echo "==> Switching to branch: $BRANCH"
git -C "$REPO" checkout "$BRANCH"

echo "==> Discarding any local changes..."
git -C "$REPO" reset --hard

BEFORE=$(git -C "$REPO" rev-parse HEAD)

echo "==> Pulling latest code..."
git -C "$REPO" pull origin "$BRANCH"

AFTER=$(git -C "$REPO" rev-parse HEAD)

if [ "$BEFORE" = "$AFTER" ] && [ "$FORCE" -eq 0 ] && [ "$PULL_BASE_IMAGES" -eq 0 ]; then
  echo "==> No new commits on $BRANCH — nothing to rebuild. (use --force to rebuild anyway)"
  exit 0
fi

# Ensure host-side data subdirs exist before Docker mounts them
echo "==> Creating data directories..."
mkdir -p "$REPO/data/media" "$REPO/data/staticfiles" "$REPO/data/postgres"

COMMIT=$(git -C "$REPO" rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Build the image directly with buildx so BuildKit is guaranteed. Compose's
# buildx detection is unreliable on this server and can silently fall back to the
# legacy (non-BuildKit) builder, which fails outright on the BuildKit-only
# Dockerfile (`# syntax=...`, RUN --mount=type=cache). --load makes the built
# image available to the local Docker daemon so Compose can pick it up.
#
# NOTE: use --tag (long form), never -t. On this host -t has tripped a bogus
# "unknown shorthand flag" error even though `docker buildx build` works fine.
echo "==> Building image $IMAGE with buildx (commit: $COMMIT)..."
BUILD_ARGS=(--tag "$IMAGE" --build-arg GIT_COMMIT="$COMMIT" --load)
if [ "$PULL_BASE_IMAGES" -eq 1 ]; then
  echo "    (--pull-base-images set: forcing a base-image registry check)"
  BUILD_ARGS+=(--pull)
fi
docker buildx build "${BUILD_ARGS[@]}" "$REPO"

echo "==> Restarting containers..."
docker compose -f "$COMPOSE_FILE" down
# --no-build: Compose must use the image buildx just built, never build its own
# (its unreliable builder is exactly the problem we're routing around).
docker compose -f "$COMPOSE_FILE" up -d --no-build

echo "==> Done. Containers are running."
docker compose -f "$COMPOSE_FILE" ps
