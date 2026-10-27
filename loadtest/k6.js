// Constant-arrival-rate load through the gateway with a realistic identity mix.
//   docker run --rm --network host -v $PWD/loadtest:/s grafana/k6 run -e BASE=http://localhost:8080 -e RATE=500 /s/k6.js
import http from "k6/http";
import { check } from "k6";

const BASE = __ENV.BASE || "http://localhost:8080";
const RATE = parseInt(__ENV.RATE || "500");
const DURATION = __ENV.DURATION || "30s";
const RAMP = __ENV.RAMP === "1";

export const options = {
  discardResponseBodies: true,
  summaryTrendStats: ["avg", "p(50)", "p(95)", "p(99)", "max"],
  scenarios: RAMP
    ? { ramp: { executor: "ramping-arrival-rate", startRate: 200, timeUnit: "1s", preAllocatedVUs: 200, maxVUs: 800,
               stages: [{ target: RATE, duration: DURATION }] } }
    : { steady: { executor: "constant-arrival-rate", rate: RATE, timeUnit: "1s", duration: DURATION, preAllocatedVUs: 200, maxVUs: 800 } },
  thresholds: { http_req_failed: ["rate<0.01"] },
};

// Each identity exercises a different policy path: full Conditional Access checks (HR),
// group-only (wiki), and web content filtering (internet).
const MIX = [
  ["alice", "/apps/hr/reviews"],
  ["bob", "/apps/wiki/runbooks"],
  ["dave", "/internet/github.com/"],
];

export function setup() {
  return MIX.map(([persona, path]) => {
    const t = http.post(`${BASE}/api/demo/token`, JSON.stringify({ persona }), { headers: { "content-type": "application/json" }, responseType: "text" }).json();
    const headers = { authorization: `Bearer ${t.accessToken}` };
    if (t.deviceToken) headers["x-device-token"] = t.deviceToken;
    return { path, headers };
  });
}

export default function (targets) {
  const t = targets[Math.floor(Math.random() * targets.length)];
  const r = http.get(`${BASE}${t.path}`, { headers: t.headers });
  check(r, { "200": (x) => x.status === 200 });
}
