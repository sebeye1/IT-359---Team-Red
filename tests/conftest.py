import pytest

from fake_ai import FakeAi
from webrecon.ai import envfile


@pytest.fixture(autouse=True)
def run_in_temp_dir(tmp_path, monkeypatch):
    """Every test starts in an empty folder, so nothing it writes (reports/, JSON) can leak into the project.
    The AI cache folder is redirected too, and no real AI key is ever picked up from the environment."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("WEBRECON_CACHE_DIR", str(tmp_path / "cache"))
    # Never read a developer's real key file: the project .env and the per-user file are both redirected to the temp dir.
    monkeypatch.setattr(envfile, "PROJECT_ROOT", str(tmp_path / "project-root"))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("APPDATA", str(tmp_path / "appdata"))
    monkeypatch.delenv("WEBRECON_ENV_FILE", raising=False)
    for name in ("WEBRECON_AI_KEY", "WEBRECON_AI_URL", "WEBRECON_AI_MODEL", "WEBRECON_AI_PROVIDER",
                 "ANTHROPIC_API_KEY", "OPENAI_API_KEY"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def fake_ai():
    server = FakeAi().start()
    yield server
    server.stop()
