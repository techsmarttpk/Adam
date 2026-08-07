"""
tests/integration/test_api.py
"""

import pytest
import os

os.environ["ADAM__SANDBOX__GUEST_USERNAME"] = "tester"
os.environ["ADAM__SANDBOX__GUEST_PASSWORD"] = "not-a-real-secret"

from fastapi.testclient import TestClient
from adam.api.main import app

@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c

def test_get_sessions(client):
    response = client.get("/api/v1/sessions")
    assert response.status_code == 200
    assert "sessions" in response.json()

def test_get_session_events(client):
    response = client.get("/api/v1/sessions/fake_session/events")
    assert response.status_code == 200
    assert response.json() == []

def test_get_session_decisions(client):
    response = client.get("/api/v1/sessions/fake_session/decisions")
    assert response.status_code == 200
    assert response.json() == []
