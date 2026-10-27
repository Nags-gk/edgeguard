#!/bin/bash
# Build the runtime image from a host `dotnet publish` (for networks where `docker build`
# cannot reach NuGet). Produces the same final stage as the Dockerfile.
set -euo pipefail
cd "$(dirname "$0")/.."
ctx=$(mktemp -d)
dotnet publish src/EdgeGuard.Authz -c Release -o "$ctx/out" >/dev/null
cp -r envoy deploy "$ctx/"
sed -n '/^FROM envoyproxy/,$p' Dockerfile | sed 's|COPY --from=build /out ./|COPY out/ ./|' > "$ctx/Dockerfile"
docker build -q -t "${IMAGE:-edgeguard:local}" "$ctx"
rm -rf "$ctx"
