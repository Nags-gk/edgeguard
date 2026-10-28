"""Black-box integration tests: drive the real container (Envoy + authz) over HTTP.

Run:  EDGEGUARD_URL=http://localhost:8080 EDGEGUARD_ADMIN_KEY=... pytest -q tests/integration
"""
import base64
import concurrent.futures as cf
import json
import os
import time

import pytest
import requests

BASE = os.environ.get("EDGEGUARD_URL", "http://localhost:8080").rstrip("/")
ADMIN_KEY = os.environ.get("EDGEGUARD_ADMIN_KEY", "")
S = requests.Session()


def token(persona, tamper=None, session=None):
    for _ in range(20):  # the token endpoint is deliberately rate limited
        r = S.post(f"{BASE}/api/demo/token", json={"persona": persona, "tamper": tamper, "session": session}, timeout=5)
        if r.status_code != 429:
            break
        time.sleep(0.1)
    r.raise_for_status()
    return r.json()


def headers_for(t, device=True):
    h = {"authorization": f"Bearer {t['accessToken']}"}
    if device and t.get("deviceToken"):
        h["x-device-token"] = t["deviceToken"]
    return h


def call(path, h=None, **kw):
    return S.get(f"{BASE}{path}", headers=h or {}, timeout=5, **kw)


def reason(r):
    if r.status_code == 200:
        return "allow"
    try:
        return r.json()["reason"]
    except Exception:
        return str(r.status_code)


# ---------------------------------------------------------------- policy matrix
TARGETS = ["/apps/hr", "/apps/finance", "/apps/wiki", "/apps/status",
           "/internet/news.example/", "/internet/casino.example/", "/internet/malware.test/"]
EXPECTED = {
    "alice": ["allow", "group_required", "allow", "allow", "allow", "web_category_blocked", "web_category_blocked"],
    "bob":   ["group_required", "group_required", "allow", "allow", "allow", "web_category_blocked", "web_category_blocked"],
    "carol": ["group_required", "device_noncompliant", "allow", "allow", "allow", "web_category_blocked", "web_category_blocked"],
    "dave":  ["group_required", "group_required", "allow", "allow", "allow", "web_category_blocked", "allow"],
    "eve":   ["group_required", "group_required", "group_required", "allow", "allow", "web_category_blocked", "web_category_blocked"],
}


@pytest.mark.parametrize("persona", list(EXPECTED))
def test_access_matrix(persona):
    h = headers_for(token(persona))
    got = [reason(call(p, h)) for p in TARGETS]
    assert got == EXPECTED[persona]


def test_denials_are_explained_and_traceable():
    r = call("/apps/hr", headers_for(token("bob")))
    assert r.status_code == 403
    body = r.json()
    assert body["decision"] == "deny" and body["policies"] and body["decisionId"]
    assert r.headers["x-eg-decision-id"] == body["decisionId"]


# ---------------------------------------------------------------- identity
def test_missing_token_gets_401_with_bearer_challenge():
    r = call("/apps/wiki")
    assert r.status_code == 401
    assert r.headers["www-authenticate"].startswith("Bearer")


@pytest.mark.parametrize("tamper,expected", [("expired", "token_expired"), ("wrong_audience", "wrong_audience")])
def test_bad_tokens_are_rejected(tamper, expected):
    r = call("/apps/wiki", headers_for(token("alice", tamper)))
    assert (r.status_code, reason(r)) == (401, expected)


def _b64(d):
    return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()


def test_unsigned_alg_none_token_is_rejected():
    forged = f"{_b64({'alg': 'none', 'typ': 'JWT'})}.{_b64({'iss': 'https://edgeguard.demo/issuer', 'aud': 'api://edgeguard', 'sub': 'demo-alice', 'roles': ['HR'], 'exp': 9999999999})}."
    r = call("/apps/hr", {"authorization": f"Bearer {forged}"})
    assert r.status_code == 401


def test_payload_tampering_breaks_the_signature():
    t = token("bob")
    head, payload, sig = t["accessToken"].split(".")
    claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    claims["roles"] = ["HR", "Employees"]
    r = call("/apps/hr", {"authorization": f"Bearer {head}.{_b64(claims)}.{sig}"})
    assert r.status_code == 401


def test_device_token_cannot_be_used_as_a_user_token():
    t = token("alice")
    r = call("/apps/wiki", {"authorization": f"Bearer {t['deviceToken']}"})
    assert (r.status_code, reason(r)) == (401, "wrong_audience")


def test_missing_device_token_fails_device_compliance():
    r = call("/apps/hr", headers_for(token("alice"), device=False))
    assert reason(r) == "device_noncompliant"


# ---------------------------------------------------------------- data path hygiene
def test_credentials_are_stripped_and_identity_headers_cannot_be_spoofed():
    h = headers_for(token("alice"))
    h.update({"x-eg-user": "admin", "x-eg-groups": "Finance", "x-eg-risk": "none"})
    seen = call("/apps/wiki", h).json()["seenByUpstream"]
    assert seen["user"].startswith("demo-alice-")
    assert seen["groups"] == "HR,Employees"
    assert seen["authorizationHeaderPresent"] is False
    assert seen["deviceTokenPresent"] is False


@pytest.mark.parametrize("path", ["/apps/status/../hr", "/apps/status/./../hr", "//apps//hr", "/apps/status/%2e%2e/hr"])
def test_path_tricks_cannot_reach_a_protected_app_anonymously(path):
    r = S.get(f"{BASE}{path}", timeout=5)
    assert r.status_code in (400, 401, 403, 404)


def test_escaped_slashes_are_rejected():
    assert S.get(f"{BASE}/apps/status%2F..%2Fhr", timeout=5).status_code == 400


def test_envoy_retries_hide_a_flaky_upstream():
    h = headers_for(token("alice"))
    assert [call("/apps/wiki/flaky", h).status_code for _ in range(6)] == [200] * 6


def test_only_envoy_stats_are_exposed_not_the_admin_api():
    assert "envoy_http_ext_authz_ok" in call("/envoy/stats").text
    assert call("/envoy/quitquitquit").status_code == 404
    assert S.post(f"{BASE}/envoy/stats", timeout=5).status_code != 200


def test_prometheus_metrics_are_exported():
    assert "edgeguard_decisions_total" in call("/metrics").text


def test_demo_token_endpoint_is_rate_limited():
    def mint(_):
        return S.post(f"{BASE}/api/demo/token", json={"persona": "dave"}, timeout=5).status_code
    with cf.ThreadPoolExecutor(16) as ex:
        codes = list(ex.map(mint, range(80)))
    assert 429 in codes and 200 in codes


# ---------------------------------------------------------------- risk and containment
def test_admin_risk_api_requires_the_admin_key():
    r = S.post(f"{BASE}/api/admin/risk", json={"subject": "demo-alice", "level": "High"}, timeout=5)
    assert r.status_code == 401


def test_each_session_gets_an_isolated_identity():
    a, b = token("alice"), token("alice")
    assert a["subject"] != b["subject"]
    assert token("alice", session=a["session"])["subject"] == a["subject"]


@pytest.mark.skipif(ADMIN_KEY == "", reason="needs EDGEGUARD_ADMIN_KEY")
def test_external_risk_signal_contains_then_releases_an_identity():
    t = token("alice")
    h = headers_for(t)
    assert call("/apps/hr", h).status_code == 200
    r = S.post(f"{BASE}/api/admin/risk", headers={"x-admin-key": ADMIN_KEY},
               json={"subject": t["subject"], "level": "High", "reason": "test: impossible travel", "ttlSeconds": 60}, timeout=5)
    assert r.status_code == 200
    assert reason(call("/apps/hr", h)) == "policy_block"
    assert S.delete(f"{BASE}/api/admin/risk/{t['subject']}", headers={"x-admin-key": ADMIN_KEY}, timeout=5).status_code == 204
    assert call("/apps/hr", h).status_code == 200


def test_burst_escalates_risk_to_step_up_then_block():
    t = token("carol")
    h = headers_for(t)
    with cf.ThreadPoolExecutor(8) as ex:
        reasons = list(ex.map(lambda _: reason(call("/apps/hr", h)), range(80)))
    assert "policy_block" in reasons
    decisions = S.get(f"{BASE}/api/decisions", params={"subject": t["subject"], "limit": 200}, timeout=5).json()
    assert {"medium", "high"} <= {d["risk"] for d in decisions}
