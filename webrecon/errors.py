"""
errors.py - Errors shared across WebRecon.
"""


class UserError(Exception):
    """A mistake in how WebRecon was invoked. The message is shown to the user as-is."""
