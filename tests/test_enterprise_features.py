import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.database import clear_all_logs, init_db

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_teardown():
    init_db()
    yield


def test_intercept_extended_telemetry():
    payload = {
        "agent": "ResearchAgent",
        "action": "read_file",
        "target": "analytics.csv",
        "arguments": {"lines": 100},
    }
    res = client.post("/api/intercept", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert "risk_breakdown" in data and data["risk_breakdown"] is not None
    assert "signals" in data and isinstance(data["signals"], list)
    assert "pipeline_timings" in data and data["pipeline_timings"] is not None
    assert data["pipeline_timings"]["total_latency_ms"] == 32
    assert "explainability" in data and data["explainability"] is not None
    assert "what_happened" in data["explainability"]
    assert "why" in data["explainability"]
    assert "which_policy" in data["explainability"]
    assert "what_agentguard_did" in data["explainability"]
    assert "next_steps" in data["explainability"]


def test_agent_isolation_workflow():
    agent_name = "TestIsolatedAgent"
    # 1. Action allowed before isolation
    res1 = client.post("/api/intercept", json={"agent": agent_name, "action": "read_file", "target": "doc.txt", "arguments": {}})
    assert res1.status_code == 200
    assert res1.json()["decision"] == "ALLOW"

    # 2. Isolate agent
    iso_res = client.post(f"/api/agents/{agent_name}/isolate", json={"reason": "Suspicious exfiltration activity"})
    assert iso_res.status_code == 200
    assert iso_res.json()["status"] == "ISOLATED"

    # 3. Subsequent action blocked due to isolation
    res2 = client.post("/api/intercept", json={"agent": agent_name, "action": "read_file", "target": "doc.txt", "arguments": {}})
    assert res2.status_code == 200
    assert res2.json()["decision"] == "BLOCKED"
    assert "quarantine" in res2.json()["reason"].lower() or "isolated" in res2.json()["reason"].lower()

    # 4. Restore agent
    rest_res = client.post(f"/api/agents/{agent_name}/restore")
    assert rest_res.status_code == 200
    assert rest_res.json()["status"] == "ACTIVE"

    # 5. Subsequent action allowed again
    res3 = client.post("/api/intercept", json={"agent": agent_name, "action": "read_file", "target": "doc.txt", "arguments": {}})
    assert res3.status_code == 200
    assert res3.json()["decision"] == "ALLOW"


def test_incidents_management():
    # 1. List incidents
    inc_res = client.get("/api/incidents")
    assert inc_res.status_code == 200
    incidents = inc_res.json()
    assert len(incidents) >= 1

    first_id = incidents[0]["incident_id"]

    # 2. Update status
    patch_res = client.patch(
        f"/api/incidents/{first_id}/status",
        json={"status": "CONTAINED", "assigned_to": "AI Safety Lead", "triage_notes": "Tokens rotated and host isolated."},
    )
    assert patch_res.status_code == 200
    updated = patch_res.json()
    assert updated["status"] == "CONTAINED"
    assert updated["assigned_to"] == "AI Safety Lead"
    assert "Tokens rotated" in updated["triage_notes"]


def test_autonomous_response_execution():
    # 1. Fetch rules
    resp_res = client.get("/api/responses")
    assert resp_res.status_code == 200
    data = resp_res.json()
    assert "rules" in data and len(data["rules"]) > 0

    # 2. Execute rule manually
    exec_res = client.post("/api/responses/execute", json={"rule_id": "RESP-01", "target_agent": "UntrustedAgent"})
    assert exec_res.status_code == 200
    exec_data = exec_res.json()
    assert exec_data["success"] is True
    assert "audit" in exec_data


def test_policy_recommendations_and_apply():
    # 1. Fetch recommendations
    rec_res = client.get("/api/policies/recommendations")
    assert rec_res.status_code == 200
    recs = rec_res.json()
    assert len(recs) > 0

    rec_id = recs[0]["rec_id"]

    # 2. Apply recommendation
    apply_res = client.post(f"/api/policies/recommendations/{rec_id}/apply")
    assert apply_res.status_code == 200
    assert apply_res.json()["success"] is True


def test_security_copilot_query():
    query_payload = {"query": "Why was DatabaseAgent blocked from drop_database_table?", "role": "SecOps Engineer"}
    copilot_res = client.post("/api/copilot/query", json=query_payload)
    assert copilot_res.status_code == 200
    c_data = copilot_res.json()
    assert "DatabaseAgent" in c_data["answer"] or "blocked" in c_data["answer"]
    assert len(c_data["sources"]) > 0
    assert len(c_data["suggested_actions"]) > 0


def test_reports_summary():
    report_res = client.get("/api/reports/summary")
    assert report_res.status_code == 200
    rep = report_res.json()
    assert "executive_summary" in rep
    assert "compliance_alignment" in rep
    assert "ISO_27001" in rep["compliance_alignment"]
    assert "OWASP_TOP_10_FOR_LLMS" in rep["compliance_alignment"]


def test_alerts_config_flow():
    get_res = client.get("/api/alerts/config")
    assert get_res.status_code == 200

    update_payload = {
        "slack_webhook": "https://hooks.slack.com/services/T99/B99/TEST",
        "email_recipients": ["ops@company.org"],
        "pagerduty_key": "pd_key_123",
        "min_severity": "CRITICAL",
        "enabled": True,
    }
    post_res = client.post("/api/alerts/config", json=update_payload)
    assert post_res.status_code == 200
    cfg = post_res.json()
    assert cfg["slack_webhook"] == update_payload["slack_webhook"]
    assert cfg["min_severity"] == "CRITICAL"
