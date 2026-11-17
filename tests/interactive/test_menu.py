"""Tests for interactive/menu.py and helpers.py: the short menu and the argument-list helpers."""

from helpers import answers
from webrecon.interactive import choose_scan, helpers, run_all
from webrecon.interactive.helpers import has_flag, pick_lab_port, strip_flags


def test_has_flag_matches_exact_and_equals_forms():
    assert has_flag(["--cookie=a=b"], "--cookie")
    assert has_flag(["-o", "x.html"], "-o", "--output")
    assert not has_flag(["--cookies-file"], "--cookie")


def test_strip_flags_removes_switches_and_valued_flags():
    raw = ["--auto-lab", "-o", "x.html", "--delay", "0", "--json=y.json", "--hardened-lab"]
    assert strip_flags(raw, switches=("--auto-lab", "--hardened-lab"),
                              valued=("-o", "--json")) == ["--delay", "0"]


def test_pick_lab_port_moves_on_when_busy(monkeypatch):
    monkeypatch.setattr(helpers, "port_free", lambda port: port != 8080)
    answers(monkeypatch, "")  # accept the suggested next port
    assert pick_lab_port() == 8081
    monkeypatch.setattr(helpers, "port_free", lambda port: True)
    assert pick_lab_port() == 8080  # no question when the default is free


def test_run_all_shows_commands_and_returns_the_worst_exit_code(capsys):
    seen = []
    codes = iter([0, 2, 1])
    runs = [["a"], ["b", "--cookie", "x y"], ["c"]]
    assert run_all(lambda argv: seen.append(argv) or next(codes), runs) == 2
    assert seen == runs
    out = capsys.readouterr().out
    assert "step 2 of 3" in out and "--cookie 'x y'" in out


def test_menu_vulnerable_lab(monkeypatch):
    answers(monkeypatch, "1")
    (argv,) = choose_scan([])
    assert argv[0] == "http://127.0.0.1:8080" and "--auto-lab" in argv and "--open" in argv
    assert "--hardened-lab" not in argv


def test_menu_defaults_to_hardened_when_that_flag_was_given(monkeypatch):
    answers(monkeypatch, "")  # just press Enter
    (argv,) = choose_scan(["--hardened-lab", "--delay", "0"])
    assert argv.count("--hardened-lab") == 1 and argv.count("--auto-lab") == 1
    assert argv[-3:] == ["--delay", "0", "--open"]  # the user's options are kept as given


def test_menu_does_not_add_open_twice(monkeypatch):
    answers(monkeypatch, "1")
    (argv,) = choose_scan(["--open"])
    assert argv.count("--open") == 1


def test_menu_full_demo_scans_before_after_then_compares(monkeypatch):
    answers(monkeypatch, "3")
    before, after, compare_run = choose_scan(["-o", "mine.html", "--delay", "0"])
    assert "--hardened-lab" not in before and "--hardened-lab" in after
    assert "mine.html" not in before + after            # a shared -o would overwrite the first report
    assert before[-2:] == ["--delay", "0"]
    assert compare_run[:3] == ["--compare", "reports/before.json", "reports/after.json"]


def test_menu_own_targets_with_cookie(monkeypatch):
    answers(monkeypatch, "4", "https://a.example https://b.example", "s=1")
    (argv,) = choose_scan(["-y"])
    assert argv[:2] == ["https://a.example", "https://b.example"]
    assert argv[argv.index("--cookie") + 1] == "s=1" and "--open" in argv and "-y" in argv


def test_menu_own_target_skips_cookie_question_when_already_given(monkeypatch):
    answers(monkeypatch, "4", "https://a.example")  # a third answer would raise StopIteration
    (argv,) = choose_scan(["--cookie", "x=1"])
    assert argv.count("--cookie") == 1


def test_menu_own_targets_from_a_file(monkeypatch, tmp_path):
    listing = tmp_path / "sites.txt"
    listing.write_text("a.example\n")
    answers(monkeypatch, "4", str(listing), "")
    (argv,) = choose_scan([])
    assert argv[:2] == ["--targets-file", str(listing)]


def test_menu_cancel_and_quit_return_none(monkeypatch):
    answers(monkeypatch, "4", "")
    assert choose_scan([]) is None
    answers(monkeypatch, "5")
    assert choose_scan([]) is None


def test_menu_reasks_on_bad_input(monkeypatch):
    answers(monkeypatch, "9", "x", "1")
    assert choose_scan([]) is not None
