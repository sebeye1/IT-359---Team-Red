import pytest

from webrecon.interactive import helpers


@pytest.fixture(autouse=True)
def lab_port_is_free(monkeypatch):
    monkeypatch.setattr(helpers, "port_free", lambda port: True)
