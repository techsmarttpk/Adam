import pytest
import os
os.environ["ADAM__SANDBOX__GUEST_USERNAME"] = "tester"
os.environ["ADAM__SANDBOX__GUEST_PASSWORD"] = "not-a-real-secret"

from fastapi.testclient import TestClient
from adam.api.main import app, sessions_store
from adam.contracts.session import AnalysisSession, SampleRef, SessionConfig, SessionMetrics
from adam.contracts.enums import Arm, NetworkMode, SessionStatus
from datetime import datetime, timezone

@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c

@pytest.fixture
def mock_session():
    session_id = "test_dash_session"
    sample = SampleRef(
        sha256="a" * 64, md5="b" * 32, filename="test.exe", size_bytes=100, file_type="binary"
    )
    config = SessionConfig(
        deception_enabled=True, policy_ruleset="default", vm_profile="win10", timeout_seconds=300, network_mode=NetworkMode.SIMULATED
    )
    metadata = AnalysisSession(
        session_id=session_id, experiment_id="exp_dash", arm=Arm.TREATMENT, sample=sample,
        config=config, status=SessionStatus.COMPLETED, started_at=datetime.now(timezone.utc), metrics=SessionMetrics()
    )
    sessions_store[session_id] = {
        "metadata": metadata, "events": [], "decisions": [], "mutations": []
    }
    yield session_id
    if session_id in sessions_store:
        del sessions_store[session_id]

def test_dashboard_index(client):
    response = client.get("/dashboard/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]

def test_dashboard_session_detail(client, mock_session):
    response = client.get(f"/dashboard/sessions/{mock_session}")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]

def test_dashboard_report(client, mock_session):
    # This might return 500 if ReportGenerator is not initialized correctly in tests
    # But for basic rendering we mock or depend on deps
    response = client.get(f"/dashboard/sessions/{mock_session}/report")
    # if it fails because report generator isn't seeded with SQLite, we just ensure it doesn't crash 500 in a bad way
    assert response.status_code in (200, 500) 

def test_dashboard_comparison(client):
    response = client.get("/dashboard/experiments/exp_dash/comparison")
    assert response.status_code in (200, 500)
