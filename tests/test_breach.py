import hashlib

import pytest
import requests

from vaultkey import breach
from vaultkey.breach import BreachChecker


class FakeResponse:
    def __init__(self, text):
        self.text = text

    def raise_for_status(self):
        pass


@pytest.fixture
def checker(monkeypatch):
    c = BreachChecker()
    c.min_request_interval = 0
    return c


def suffix_of(password):
    return hashlib.sha1(password.encode()).hexdigest().upper()[5:]


def test_padded_response_is_parsed(checker, monkeypatch):
    calls = []

    def fake_get(url, headers, timeout):
        calls.append(headers)
        return FakeResponse(
            "0000000000000000000000000000000000A:0\r\n"     # padding entry
            f"{suffix_of('hunter2').lower()}:42\r\n"
        )

    monkeypatch.setattr(breach.requests, "get", fake_get)
    result = checker.check_password("hunter2")
    assert result["found"] and result["count"] == 42
    assert calls[0]["Add-Padding"] == "true"
    assert "Accept" not in calls[0]


def test_padding_entries_do_not_count_as_breaches(checker, monkeypatch):
    monkeypatch.setattr(breach.requests, "get",
                        lambda *a, **k: FakeResponse(f"{suffix_of('unique-pw')}:0\n"))
    result = checker.check_password("unique-pw")
    assert not result["found"] and result["severity"] == "safe"


def test_network_failure_is_reported_as_error(checker, monkeypatch):
    def fail(*args, **kwargs):
        raise requests.exceptions.ConnectionError("offline")

    monkeypatch.setattr(breach.requests, "get", fail)
    result = checker.check_password("anything")
    assert result["error"] is True
