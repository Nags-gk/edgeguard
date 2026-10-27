# Benchmarks

Measured on 2026-10-27 with k6 (constant arrival rate) against the container image built from this repo.

**Setup:** gateway container limited to `--cpus=1.5`; k6 ran on the same 2-vCPU sandbox (so the load
generator competes for CPU with the gateway: treat these as conservative). Identity mix: Alice → HR Portal
(group + MFA + compliant-device policy), Bob → Wiki (group policy), Dave → `github.com` (web content
filtering). Session-velocity risk thresholds were raised for the run so a single load-test identity is not
contained by the risk engine; every other check ran as in production. Decision logging stayed on.

## Overhead of identity-aware authorization (500 rps, 30 s, 15,004 requests each)

| Configuration | p50 | p95 | p99 | Errors |
|---|---|---|---|---|
| Envoy only, ext_authz removed (baseline) | 0.63 ms | 0.83 ms | 1.47 ms | 0 |
| EdgeGuard, token-validation cache on | 1.31 ms | 1.89 ms | 4.64 ms | 0 |
| EdgeGuard, token-validation cache off | 1.35 ms | 2.17 ms | 5.91 ms | 0 |

Authorization adds **~0.7 ms at p50** end to end. Inside the service, the `Check` call took
**0.105 ms p50 / 0.178 ms p99** with the cache on, and 0.140 ms p50 / 0.242 ms p99 with it off
(the cache skips RSA signature verification on repeat tokens; about 25% faster per check).

## Capacity (steady state, 20 s each)

| Offered load | p50 | p95 | p99 | Errors |
|---|---|---|---|---|
| 1,000 rps | 1.8 ms | 7.2 ms | 16.6 ms | 0 / 20,004 |
| 1,500 rps | 4.3 ms | 17.3 ms | 39.4 ms | 0 / 30,003 |
| 1,900 rps | 10.4 ms | 56.6 ms | 90.0 ms | 0 / 37,976 (29 iterations dropped by k6) |

The ingress token bucket is 2,000 rps per instance, so 1,900 rps is close to the configured ceiling.

## Reproduce

```bash
scripts/build-local.sh          # or: docker build -t edgeguard:local .
docker run -d --name eg --cpus=1.5 -p 8080:8080 \
  -e EdgeGuard__Risk__MediumRequestsPer10s=10000000 -e EdgeGuard__Risk__HighRequestsPer10s=10000000 edgeguard:local
docker run --rm --network host -v $PWD/loadtest:/s grafana/k6 run -e RATE=500 -e DURATION=30s /s/k6.js
```
For the baseline, mount an `envoy.yaml` with the `envoy.filters.http.ext_authz` filter removed.
