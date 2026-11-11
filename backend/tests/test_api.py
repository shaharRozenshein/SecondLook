"""Tests for the API layer: authentication and input validation."""

import pytest
from fastapi.testclient import TestClient

import main

client = TestClient(main.app)
VALID_EMAIL = {"sender": "Dana <dana@company.com>", "subject": "Hi"}


@pytest.fixture(autouse=True)
def configured_key(monkeypatch):
    """Every test runs with a known API key, without touching the real environment."""
    monkeypatch.setattr(main, "API_KEY", "test-key")


def test_health_needs_no_key():
    assert client.get("/health").status_code == 200


def test_missing_key_is_rejected():
    assert client.post("/analyze", json=VALID_EMAIL).status_code == 401


def test_wrong_key_is_rejected():
    response = client.post("/analyze", json=VALID_EMAIL, headers={"X-API-Key": "wrong"})
    assert response.status_code == 401


def test_correct_key_is_accepted():
    response = client.post("/analyze", json=VALID_EMAIL, headers={"X-API-Key": "test-key"})
    assert response.status_code == 200
    assert response.json()["verdict"] == "Low risk"


def test_fails_closed_when_no_key_is_configured(monkeypatch):
    monkeypatch.setattr(main, "API_KEY", None)
    response = client.post("/analyze", json=VALID_EMAIL, headers={"X-API-Key": ""})
    assert response.status_code == 401


def test_oversized_input_is_rejected():
    email = {"sender": "Dana <dana@company.com>", "subject": "x" * 1001}
    response = client.post("/analyze", json=email, headers={"X-API-Key": "test-key"})
    assert response.status_code == 422

def test_docs_are_disabled_by_default():
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404


def test_huge_request_is_rejected_before_parsing():
    response = client.post("/analyze", content="x" * 1_100_000,
                           headers={"X-API-Key": "test-key", "Content-Type": "application/json"})
    assert response.status_code == 413