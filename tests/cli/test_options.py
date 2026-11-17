"""Tests for cli/options.py: the options, profiles, short help, and checking what the user typed."""

import pytest

from webrecon.cli import app
from webrecon.cli.options import (UserError, load_targets, parse_also, parse_args, parse_headers)


def test_header_parsing():
    assert parse_headers(["X-Api-Key: abc", "Authorization:Bearer t"]) == {
        "X-Api-Key": "abc", "Authorization": "Bearer t"}
    with pytest.raises(UserError):
        parse_headers(["no-colon-here"])


def test_targets_file_comments_and_duplicates(tmp_path):
    f = tmp_path / "t.txt"
    f.write_text("# my sites\nexample.com\n\nhttps://example.com/  # same\nhttp://127.0.0.1:8080\n")
    args = parse_args(["http://127.0.0.1:8080", "--targets-file", str(f)])
    assert load_targets(args) == ["http://127.0.0.1:8080", "example.com"]


def test_targets_file_errors_are_friendly(tmp_path):
    with pytest.raises(UserError):
        load_targets(parse_args(["--targets-file", str(tmp_path / "missing.txt")]))
    empty = tmp_path / "e.txt"
    empty.write_text("# nothing\n")
    with pytest.raises(UserError):
        load_targets(parse_args(["--targets-file", str(empty)]))


def test_also_accepts_comma_lists_and_rejects_unknown_formats():
    assert parse_also(["csv, MD", "json"]) == {"csv", "md"}  # json is always saved, so it is a no-op
    assert parse_also([]) == set()
    with pytest.raises(UserError):
        parse_also(["pdf"])


def test_profiles_fill_in_settings_but_explicit_options_win():
    standard = parse_args(["x"])
    assert (standard.max_pages, standard.delay, standard.timeout, standard.retries, standard.max_time) == (
        10, 0.2, 10.0, 2, 300.0)
    gentle = parse_args(["x", "--profile", "gentle"])
    assert (gentle.max_pages, gentle.delay) == (5, 1.0)
    mixed = parse_args(["x", "--profile", "thorough", "--max-pages", "7", "--delay", "0"])
    assert (mixed.max_pages, mixed.delay, mixed.max_time) == (7, 0, 900.0)  # explicit 0 is respected, not replaced


def test_short_help_is_short_and_help_all_is_complete(capsys):
    with pytest.raises(SystemExit):
        app.main(["--help"])
    short = capsys.readouterr().out
    assert "--help-all" in short and "--max-pages" not in short and len(short.splitlines()) < 30
    with pytest.raises(SystemExit):
        app.main(["--help-all"])
    full = capsys.readouterr().out
    assert "--max-pages" in full and "--baseline" in full and "--profile" in full


def test_max_time_defaults_to_five_minutes_and_zero_means_unlimited():
    assert parse_args(["x"]).max_time == 300
    args = parse_args(["x", "--max-time", "0"])
    assert (args.max_time or None) is None


def test_ai_options_and_their_defaults():
    args = parse_args(["x"])
    assert (args.ai, args.ai_provider, args.ai_url, args.ai_model, args.ai_timeout, args.attack_update) == (
        False, None, None, None, 60.0, False)
    args = parse_args(["x", "--ai", "--ai-provider", "openai", "--ai-url", "http://localhost:11434/v1",
                       "--ai-model", "llama3", "--ai-timeout", "5"])
    assert (args.ai, args.ai_provider, args.ai_model, args.ai_timeout) == (True, "openai", "llama3", 5.0)


def test_there_is_no_option_for_the_api_key(capsys):
    with pytest.raises(SystemExit):
        parse_args(["x", "--ai-key", "sk-secret"])        # keys would end up in shell history, so they are not accepted
    with pytest.raises(SystemExit):
        parse_args(["x", "--ai-provider", "gemini"])
    capsys.readouterr()


def test_the_ai_options_appear_in_the_help(capsys):
    with pytest.raises(SystemExit):
        app.main(["--help"])
    short = capsys.readouterr().out
    assert "--ai " in short and "--ai-url" not in short and len(short.splitlines()) < 30
    with pytest.raises(SystemExit):
        app.main(["--help-all"])
    full = capsys.readouterr().out
    for option in ("--ai-provider", "--ai-url", "--ai-model", "--ai-timeout", "--attack-update", "WEBRECON_AI_KEY"):
        assert option in full
