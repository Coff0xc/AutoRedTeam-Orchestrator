"""Help assertions that do not depend on terminal styling."""

from __future__ import annotations

from typer.main import get_command


def command_help_text(app, *names: str) -> str:
    """Return declared command text and option strings, without rendering."""
    command = get_command(app)
    for name in names:
        command = command.commands[name]
    parts = [command.help or ""]
    for param in command.params:
        parts.extend(param.opts)
        help_text = getattr(param, "help", None)
        if help_text:
            parts.append(str(help_text))
    return " ".join(parts)
