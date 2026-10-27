#!/bin/bash
# Start the authz service, wait until it is healthy, then start Envoy. If either process
# exits, stop the other and exit non-zero so the platform restarts the container.
set -u
dotnet /app/EdgeGuard.Authz.dll &
AUTHZ=$!
for _ in $(seq 1 100); do
  (exec 3<>/dev/tcp/127.0.0.1/9002) 2>/dev/null && break
  sleep 0.1
done
envoy -c /etc/envoy/envoy.yaml --log-level warn --concurrency "${ENVOY_CONCURRENCY:-2}" &
ENVOY=$!
trap 'kill -TERM $AUTHZ $ENVOY 2>/dev/null' TERM INT
wait -n $AUTHZ $ENVOY
code=$?
kill -TERM $AUTHZ $ENVOY 2>/dev/null
exit $code
