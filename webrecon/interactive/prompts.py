"""
prompts.py - Asking the user questions in the terminal.
"""

from __future__ import annotations


class Quit(Exception):
    """The user asked to stop (typed q at a pause, or chose Quit)."""


def ask(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    return input(f"{prompt}{suffix}: ").strip() or default


def ask_yes_no(prompt: str, default: bool = True) -> bool:
    while True:
        answer = input(f"{prompt} ({'Y/n' if default else 'y/N'}): ").strip().lower()
        if not answer:
            return default
        if answer in ("y", "yes", "n", "no"):
            return answer.startswith("y")
        print("    Please answer y or n.")


def ask_choice(prompt: str, options: list[str], default: int = 1) -> int:
    print(prompt)
    for i, text in enumerate(options, 1):
        print(f"  {i}) {text}")
    while True:
        answer = input(f"Choose 1-{len(options)} [{default}]: ").strip()
        if not answer:
            return default
        if answer.isdigit() and 1 <= int(answer) <= len(options):
            return int(answer)
        print(f"    Enter a number from 1 to {len(options)}.")


def ask_int(prompt: str, default: int) -> int:
    while True:
        answer = ask(prompt, str(default))
        if answer.isdigit() and int(answer) > 0:
            return int(answer)
        print("    Enter a positive whole number.")


def pause(message: str = "Press Enter to continue (or q to quit)") -> None:
    if input(f"\n    {message}: ").strip().lower() in ("q", "quit", "exit"):
        raise Quit()
